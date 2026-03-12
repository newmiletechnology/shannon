// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Temporal workflow for Shannon pentest pipeline.
 *
 * Orchestrates the penetration testing workflow:
 * 1. Pre-Reconnaissance (sequential)
 * 2. Reconnaissance (sequential)
 * 3-4. Vulnerability + Exploitation (5 pipelined pairs in parallel)
 *      Each pair: vuln agent → queue check → conditional exploit
 *      No synchronization barrier - exploits start when their vuln finishes
 * 5. Reporting (sequential)
 *
 * Features:
 * - Queryable state via getProgress
 * - Automatic retry with backoff for transient/billing errors
 * - Non-retryable classification for permanent errors
 * - Audit correlation via workflowId
 * - Graceful failure handling: pipelines continue if one fails
 */

import {
  log,
  proxyActivities,
  setHandler,
  workflowInfo,
} from '@temporalio/workflow';
import type * as activities from './activities.js';
import type { ActivityInput } from './activities.js';
import {
  getProgress,
  type PipelineInput,
  type RetestPipelineInput,
  type PipelineState,
  type PipelineProgress,
  type PipelineSummary,
  type VulnExploitPipelineResult,
  type AgentMetrics,
  type ResumeState,
} from './shared.js';
import type { AgentName, VulnType } from '../types/agents.js';
import { ALL_AGENTS } from '../types/agents.js';
import { toWorkflowSummary } from './summary-mapper.js';
import { formatWorkflowError } from './workflow-errors.js';

// Retry configuration for production (long intervals for billing recovery)
const PRODUCTION_RETRY = {
  initialInterval: '5 minutes',
  maximumInterval: '30 minutes',
  backoffCoefficient: 2,
  maximumAttempts: 50,
  nonRetryableErrorTypes: [
    'AuthenticationError',
    'PermissionError',
    'InvalidRequestError',
    'RequestTooLargeError',
    'ConfigurationError',
    'InvalidTargetError',
    'ExecutionLimitError',
  ],
};

// Retry configuration for pipeline testing (fast iteration)
const TESTING_RETRY = {
  initialInterval: '10 seconds',
  maximumInterval: '30 seconds',
  backoffCoefficient: 2,
  maximumAttempts: 5,
  nonRetryableErrorTypes: PRODUCTION_RETRY.nonRetryableErrorTypes,
};

// Activity proxy with production retry configuration (default)
const acts = proxyActivities<typeof activities>({
  startToCloseTimeout: '2 hours',
  heartbeatTimeout: '60 minutes', // Extended for sub-agent execution (SDK blocks event loop during Task tool calls)
  retry: PRODUCTION_RETRY,
});

// Activity proxy with testing retry configuration (fast)
const testActs = proxyActivities<typeof activities>({
  startToCloseTimeout: '30 minutes',
  heartbeatTimeout: '30 minutes', // Extended for sub-agent execution in testing
  retry: TESTING_RETRY,
});

// Retry configuration for subscription plans (5h+ rolling rate limit windows)
const SUBSCRIPTION_RETRY = {
  initialInterval: '5 minutes',
  maximumInterval: '6 hours',
  backoffCoefficient: 2,
  maximumAttempts: 100,
  nonRetryableErrorTypes: PRODUCTION_RETRY.nonRetryableErrorTypes,
};

// Activity proxy for subscription plan recovery (extended timeouts)
const subscriptionActs = proxyActivities<typeof activities>({
  startToCloseTimeout: '8 hours',
  heartbeatTimeout: '2 hours',
  retry: SUBSCRIPTION_RETRY,
});

// Retry configuration for preflight validation (short timeout, few retries)
const PREFLIGHT_RETRY = {
  initialInterval: '10 seconds',
  maximumInterval: '1 minute',
  backoffCoefficient: 2,
  maximumAttempts: 3,
  nonRetryableErrorTypes: PRODUCTION_RETRY.nonRetryableErrorTypes,
};

// Activity proxy for preflight validation (short timeout)
const preflightActs = proxyActivities<typeof activities>({
  startToCloseTimeout: '2 minutes',
  heartbeatTimeout: '2 minutes',
  retry: PREFLIGHT_RETRY,
});

/**
 * Run thunks with a concurrency limit, returning PromiseSettledResult for each.
 * When limit >= thunks.length, all launch concurrently — identical to Promise.allSettled.
 * NOTE: Results are in completion order, not input order. Callers must key on value fields, not index.
 */
async function runWithConcurrencyLimit(
  thunks: Array<() => Promise<VulnExploitPipelineResult>>,
  limit: number
): Promise<PromiseSettledResult<VulnExploitPipelineResult>[]> {
  const results: PromiseSettledResult<VulnExploitPipelineResult>[] = [];
  const inFlight = new Set<Promise<void>>();

  for (const thunk of thunks) {
    const slot = thunk().then(
      (value) => { results.push({ status: 'fulfilled', value }); },
      (reason: unknown) => { results.push({ status: 'rejected', reason }); }
    ).finally(() => { inFlight.delete(slot); });

    inFlight.add(slot);

    if (inFlight.size >= limit) {
      await Promise.race(inFlight);
    }
  }

  await Promise.allSettled(inFlight);
  return results;
}

/**
 * Compute aggregated metrics from the current pipeline state.
 * Called on both success and failure to provide partial metrics.
 */
function computeSummary(state: PipelineState): PipelineSummary {
  const metrics = Object.values(state.agentMetrics);
  return {
    totalCostUsd: metrics.reduce((sum, m) => sum + (m.costUsd ?? 0), 0),
    totalDurationMs: Date.now() - state.startTime,
    totalTurns: metrics.reduce((sum, m) => sum + (m.numTurns ?? 0), 0),
    agentCount: state.completedAgents.length,
  };
}

export async function pentestPipelineWorkflow(
  input: PipelineInput
): Promise<PipelineState> {
  const { workflowId } = workflowInfo();

  // Select activity proxy based on mode: testing (fast), subscription (extended), or default
  function selectActivityProxy(pipelineInput: PipelineInput) {
    if (pipelineInput.pipelineTestingMode) return testActs;
    if (pipelineInput.pipelineConfig?.retry_preset === 'subscription') return subscriptionActs;
    return acts;
  }

  const a = selectActivityProxy(input);

  const state: PipelineState = {
    status: 'running',
    currentPhase: null,
    currentAgent: null,
    completedAgents: [],
    failedAgent: null,
    error: null,
    startTime: Date.now(),
    agentMetrics: {},
    summary: null,
  };

  setHandler(getProgress, (): PipelineProgress => ({
    ...state,
    workflowId,
    elapsedMs: Date.now() - state.startTime,
  }));

  // Build ActivityInput with required workflowId for audit correlation
  // Activities require workflowId (non-optional), PipelineInput has it optional
  // Use spread to conditionally include optional properties (exactOptionalPropertyTypes)
  // sessionId is workspace name for resume, or workflowId for new runs
  const sessionId = input.sessionId || input.resumeFromWorkspace || workflowId;

  const activityInput: ActivityInput = {
    webUrl: input.webUrl,
    repoPath: input.repoPath,
    workflowId,
    sessionId,
    ...(input.configPath !== undefined && { configPath: input.configPath }),
    ...(input.outputPath !== undefined && { outputPath: input.outputPath }),
    ...(input.pipelineTestingMode !== undefined && {
      pipelineTestingMode: input.pipelineTestingMode,
    }),
  };

  let resumeState: ResumeState | null = null;

  if (input.resumeFromWorkspace) {
    // 1. Load resume state (validates workspace, cross-checks deliverables)
    resumeState = await a.loadResumeState(
      input.resumeFromWorkspace,
      input.webUrl,
      input.repoPath
    );

    // 2. Restore git workspace and clean up incomplete deliverables
    const incompleteAgents = ALL_AGENTS.filter(
      (agentName) => !resumeState!.completedAgents.includes(agentName)
    ) as AgentName[];

    await a.restoreGitCheckpoint(
      input.repoPath,
      resumeState.checkpointHash,
      incompleteAgents
    );

    // 3. Short-circuit if all agents already completed
    if (resumeState.completedAgents.length === ALL_AGENTS.length) {
      log.info(`All ${ALL_AGENTS.length} agents already completed. Nothing to resume.`);
      state.status = 'completed';
      state.completedAgents = [...resumeState.completedAgents];
      state.summary = computeSummary(state);
      return state;
    }

    // 4. Record this resume attempt in session.json and workflow.log
    await a.recordResumeAttempt(
      activityInput,
      input.terminatedWorkflows || [],
      resumeState.checkpointHash,
      resumeState.originalWorkflowId,
      resumeState.completedAgents
    );

    log.info('Resume state loaded and workspace restored');
  }

  const shouldSkip = (agentName: string): boolean => {
    return resumeState?.completedAgents.includes(agentName) ?? false;
  };

  // Run a sequential agent phase (pre-recon, recon)
  async function runSequentialPhase(
    phaseName: string,
    agentName: AgentName,
    runAgent: (input: ActivityInput) => Promise<AgentMetrics>
  ): Promise<void> {
    if (!shouldSkip(agentName)) {
      state.currentPhase = phaseName;
      state.currentAgent = agentName;
      await a.logPhaseTransition(activityInput, phaseName, 'start');
      state.agentMetrics[agentName] = await runAgent(activityInput);
      state.completedAgents.push(agentName);
      await a.logPhaseTransition(activityInput, phaseName, 'complete');
    } else {
      log.info(`Skipping ${agentName} (already complete)`);
      state.completedAgents.push(agentName);
    }
  }

  // Build pipeline configs for the 5 vuln→exploit pairs
  function buildPipelineConfigs(): Array<{
    vulnType: VulnType;
    vulnAgent: string;
    exploitAgent: string;
    runVuln: () => Promise<AgentMetrics>;
    runExploit: () => Promise<AgentMetrics>;
  }> {
    return [
      {
        vulnType: 'injection',
        vulnAgent: 'injection-vuln',
        exploitAgent: 'injection-exploit',
        runVuln: () => a.runInjectionVulnAgent(activityInput),
        runExploit: () => a.runInjectionExploitAgent(activityInput),
      },
      {
        vulnType: 'xss',
        vulnAgent: 'xss-vuln',
        exploitAgent: 'xss-exploit',
        runVuln: () => a.runXssVulnAgent(activityInput),
        runExploit: () => a.runXssExploitAgent(activityInput),
      },
      {
        vulnType: 'auth',
        vulnAgent: 'auth-vuln',
        exploitAgent: 'auth-exploit',
        runVuln: () => a.runAuthVulnAgent(activityInput),
        runExploit: () => a.runAuthExploitAgent(activityInput),
      },
      {
        vulnType: 'ssrf',
        vulnAgent: 'ssrf-vuln',
        exploitAgent: 'ssrf-exploit',
        runVuln: () => a.runSsrfVulnAgent(activityInput),
        runExploit: () => a.runSsrfExploitAgent(activityInput),
      },
      {
        vulnType: 'authz',
        vulnAgent: 'authz-vuln',
        exploitAgent: 'authz-exploit',
        runVuln: () => a.runAuthzVulnAgent(activityInput),
        runExploit: () => a.runAuthzExploitAgent(activityInput),
      },
    ];
  }

  // Aggregate results from settled pipeline promises into workflow state
  function aggregatePipelineResults(
    results: PromiseSettledResult<VulnExploitPipelineResult>[]
  ): void {
    const failedPipelines: string[] = [];

    for (const result of results) {
      if (result.status === 'fulfilled') {
        const { vulnType, vulnMetrics, exploitMetrics } = result.value;

        const vulnAgentName = `${vulnType}-vuln`;
        if (vulnMetrics) {
          state.agentMetrics[vulnAgentName] = vulnMetrics;
          state.completedAgents.push(vulnAgentName);
        } else if (shouldSkip(vulnAgentName)) {
          state.completedAgents.push(vulnAgentName);
        }

        const exploitAgentName = `${vulnType}-exploit`;
        if (exploitMetrics) {
          state.agentMetrics[exploitAgentName] = exploitMetrics;
          state.completedAgents.push(exploitAgentName);
        } else if (shouldSkip(exploitAgentName)) {
          state.completedAgents.push(exploitAgentName);
        }
      } else {
        const errorMsg =
          result.reason instanceof Error
            ? result.reason.message
            : String(result.reason);
        failedPipelines.push(errorMsg);
      }
    }

    if (failedPipelines.length > 0) {
      log.warn(`${failedPipelines.length} pipeline(s) failed`, {
        failures: failedPipelines,
      });
    }
  }

  try {
    // === Preflight Validation ===
    // Quick sanity checks before committing to expensive agent runs.
    // NOT using runSequentialPhase — preflight doesn't produce AgentMetrics.
    state.currentPhase = 'preflight';
    state.currentAgent = null;
    await preflightActs.runPreflightValidation(activityInput);
    log.info('Preflight validation passed');

    // === Phase 1: Pre-Reconnaissance ===
    await runSequentialPhase('pre-recon', 'pre-recon', a.runPreReconAgent);

    // === Phase 2: Reconnaissance ===
    await runSequentialPhase('recon', 'recon', a.runReconAgent);

    // === Phases 3-4: Vulnerability Analysis + Exploitation (Pipelined) ===
    // Each vuln type runs as an independent pipeline:
    // vuln agent → queue check → conditional exploit agent
    // Exploits start immediately when their vuln finishes, not waiting for all.
    state.currentPhase = 'vulnerability-exploitation';
    state.currentAgent = 'pipelines';
    await a.logPhaseTransition(activityInput, 'vulnerability-exploitation', 'start');

    // Closure over shouldSkip and activityInput by design (Temporal replay safety)
    async function runVulnExploitPipeline(
      vulnType: VulnType,
      runVulnAgent: () => Promise<AgentMetrics>,
      runExploitAgent: () => Promise<AgentMetrics>
    ): Promise<VulnExploitPipelineResult> {
      const vulnAgentName = `${vulnType}-vuln`;
      const exploitAgentName = `${vulnType}-exploit`;

      // 1. Run vulnerability analysis (or skip if resumed)
      let vulnMetrics: AgentMetrics | null = null;
      if (!shouldSkip(vulnAgentName)) {
        vulnMetrics = await runVulnAgent();
      } else {
        log.info(`Skipping ${vulnAgentName} (already complete)`);
      }

      // 2. Check exploitation queue for actionable findings
      const decision = await a.checkExploitationQueue(activityInput, vulnType);

      // 3. Conditionally run exploitation agent
      let exploitMetrics: AgentMetrics | null = null;
      if (decision.shouldExploit) {
        if (!shouldSkip(exploitAgentName)) {
          exploitMetrics = await runExploitAgent();
        } else {
          log.info(`Skipping ${exploitAgentName} (already complete)`);
        }
      }

      return {
        vulnType,
        vulnMetrics,
        exploitMetrics,
        exploitDecision: {
          shouldExploit: decision.shouldExploit,
          vulnerabilityCount: decision.vulnerabilityCount,
        },
        error: null,
      };
    }

    const maxConcurrent = input.pipelineConfig?.max_concurrent_pipelines ?? 5;

    const pipelineConfigs = buildPipelineConfigs();
    const pipelineThunks: Array<() => Promise<VulnExploitPipelineResult>> = [];

    for (const config of pipelineConfigs) {
      if (!shouldSkip(config.vulnAgent) || !shouldSkip(config.exploitAgent)) {
        pipelineThunks.push(
          () => runVulnExploitPipeline(config.vulnType, config.runVuln, config.runExploit)
        );
      } else {
        log.info(`Skipping entire ${config.vulnType} pipeline (both agents complete)`);
        state.completedAgents.push(config.vulnAgent, config.exploitAgent);
      }
    }

    const pipelineResults = await runWithConcurrencyLimit(pipelineThunks, maxConcurrent);
    aggregatePipelineResults(pipelineResults);

    state.currentPhase = 'exploitation';
    state.currentAgent = null;
    await a.logPhaseTransition(activityInput, 'vulnerability-exploitation', 'complete');

    // === Phase 5: Reporting ===
    if (!shouldSkip('report')) {
      state.currentPhase = 'reporting';
      state.currentAgent = 'report';
      await a.logPhaseTransition(activityInput, 'reporting', 'start');

      // First, assemble the concatenated report from exploitation evidence files
      await a.assembleReportActivity(activityInput);

      // Then run the report agent to add executive summary and clean up
      state.agentMetrics['report'] = await a.runReportAgent(activityInput);
      state.completedAgents.push('report');

      // Inject model metadata into the final report
      await a.injectReportMetadataActivity(activityInput);

      await a.logPhaseTransition(activityInput, 'reporting', 'complete');
    } else {
      log.info('Skipping report (already complete)');
      state.completedAgents.push('report');
    }

    state.status = 'completed';
    state.currentPhase = null;
    state.currentAgent = null;
    state.summary = computeSummary(state);

    // Log workflow completion summary
    await a.logWorkflowComplete(activityInput, toWorkflowSummary(state, 'completed'));

    return state;
  } catch (error) {
    state.status = 'failed';
    state.failedAgent = state.currentAgent;
    state.error = formatWorkflowError(error, state.currentPhase, state.currentAgent);
    state.summary = computeSummary(state);

    // Log workflow failure summary
    await a.logWorkflowComplete(activityInput, toWorkflowSummary(state, 'failed'));

    throw error;
  }
}

/**
 * Retest pipeline workflow.
 *
 * Runs after code fixes have been applied to re-assess selected vulnerability types.
 * Skips pre-recon and recon phases entirely. Generates a diff context from the
 * checkpoint hash, runs selected vuln agents with retest context, runs all exploit
 * agents (queue-check gates each), and produces an updated report.
 */
export async function retestPipelineWorkflow(
  input: RetestPipelineInput
): Promise<PipelineState> {
  const { workflowId } = workflowInfo();

  // Select activity proxy based on mode
  function selectActivityProxy(pipelineInput: RetestPipelineInput) {
    if (pipelineInput.pipelineTestingMode) return testActs;
    if (pipelineInput.pipelineConfig?.retry_preset === 'subscription') return subscriptionActs;
    return acts;
  }

  const a = selectActivityProxy(input);

  const state: PipelineState = {
    status: 'running',
    currentPhase: null,
    currentAgent: null,
    completedAgents: [],
    failedAgent: null,
    error: null,
    startTime: Date.now(),
    agentMetrics: {},
    summary: null,
  };

  setHandler(getProgress, (): PipelineProgress => ({
    ...state,
    workflowId,
    elapsedMs: Date.now() - state.startTime,
  }));

  const sessionId = input.sessionId || workflowId;

  const activityInput: ActivityInput = {
    webUrl: input.webUrl,
    repoPath: input.repoPath,
    workflowId,
    sessionId,
    ...(input.configPath !== undefined && { configPath: input.configPath }),
    ...(input.outputPath !== undefined && { outputPath: input.outputPath }),
    ...(input.pipelineTestingMode !== undefined && {
      pipelineTestingMode: input.pipelineTestingMode,
    }),
  };

  // Build pipeline configs (reused from pentestPipelineWorkflow)
  function buildPipelineConfigs(): Array<{
    vulnType: VulnType;
    vulnAgent: string;
    exploitAgent: string;
    runVuln: () => Promise<AgentMetrics>;
    runExploit: () => Promise<AgentMetrics>;
  }> {
    // Use retestInput for vuln agents so they get the retest context
    const retestInput = activityInput;
    return [
      {
        vulnType: 'injection',
        vulnAgent: 'injection-vuln',
        exploitAgent: 'injection-exploit',
        runVuln: () => a.runInjectionVulnAgent(retestInput),
        runExploit: () => a.runInjectionExploitAgent(retestInput),
      },
      {
        vulnType: 'xss',
        vulnAgent: 'xss-vuln',
        exploitAgent: 'xss-exploit',
        runVuln: () => a.runXssVulnAgent(retestInput),
        runExploit: () => a.runXssExploitAgent(retestInput),
      },
      {
        vulnType: 'auth',
        vulnAgent: 'auth-vuln',
        exploitAgent: 'auth-exploit',
        runVuln: () => a.runAuthVulnAgent(retestInput),
        runExploit: () => a.runAuthExploitAgent(retestInput),
      },
      {
        vulnType: 'ssrf',
        vulnAgent: 'ssrf-vuln',
        exploitAgent: 'ssrf-exploit',
        runVuln: () => a.runSsrfVulnAgent(retestInput),
        runExploit: () => a.runSsrfExploitAgent(retestInput),
      },
      {
        vulnType: 'authz',
        vulnAgent: 'authz-vuln',
        exploitAgent: 'authz-exploit',
        runVuln: () => a.runAuthzVulnAgent(retestInput),
        runExploit: () => a.runAuthzExploitAgent(retestInput),
      },
    ];
  }

  // Aggregate results (same pattern as pentestPipelineWorkflow)
  function aggregatePipelineResults(
    results: PromiseSettledResult<VulnExploitPipelineResult>[]
  ): void {
    const failedPipelines: string[] = [];

    for (const result of results) {
      if (result.status === 'fulfilled') {
        const { vulnType, vulnMetrics, exploitMetrics } = result.value;

        if (vulnMetrics) {
          state.agentMetrics[`${vulnType}-vuln`] = vulnMetrics;
          state.completedAgents.push(`${vulnType}-vuln`);
        }

        if (exploitMetrics) {
          state.agentMetrics[`${vulnType}-exploit`] = exploitMetrics;
          state.completedAgents.push(`${vulnType}-exploit`);
        }
      } else {
        const errorMsg =
          result.reason instanceof Error
            ? result.reason.message
            : String(result.reason);
        failedPipelines.push(errorMsg);
      }
    }

    if (failedPipelines.length > 0) {
      log.warn(`${failedPipelines.length} pipeline(s) failed`, {
        failures: failedPipelines,
      });
    }
  }

  try {
    // === Preflight Validation ===
    state.currentPhase = 'preflight';
    state.currentAgent = null;
    await preflightActs.runPreflightValidation(activityInput);
    log.info('Preflight validation passed');

    // === Generate Retest Context ===
    state.currentPhase = 'retest-context';
    state.currentAgent = null;
    await a.logPhaseTransition(activityInput, 'retest-context', 'start');

    const retestContext = await a.generateRetestContext(
      activityInput,
      input.checkpointHashes,
      input.retestVulnTypes
    );

    // Inject retest context into activity input for all subsequent agent runs
    activityInput.retestContext = retestContext;

    await a.logPhaseTransition(activityInput, 'retest-context', 'complete');
    log.info('Retest context generated', { vulnTypes: input.retestVulnTypes });

    // === Snapshot Deliverables ===
    // Freeze current deliverables before retest agents overwrite them
    const snapshotDir = await a.snapshotDeliverablesActivity(activityInput);
    if (snapshotDir) {
      log.info('Deliverables snapshot saved', { snapshotDir });
    }

    // === Pre-Recon Update ===
    // Update the code analysis deliverable to reflect code changes before vuln agents run
    state.currentPhase = 'pre-recon-update';
    state.currentAgent = 'pre-recon-update';
    await a.logPhaseTransition(activityInput, 'pre-recon-update', 'start');
    state.agentMetrics['pre-recon-update'] = await a.runPreReconUpdateAgent(activityInput);
    state.completedAgents.push('pre-recon-update');
    await a.logPhaseTransition(activityInput, 'pre-recon-update', 'complete');

    // === Vuln + Exploit Phase (Pipelined) ===
    state.currentPhase = 'vulnerability-exploitation';
    state.currentAgent = 'pipelines';
    await a.logPhaseTransition(activityInput, 'vulnerability-exploitation', 'start');

    async function runVulnExploitPipeline(
      vulnType: VulnType,
      runVulnAgent: () => Promise<AgentMetrics>,
      runExploitAgent: () => Promise<AgentMetrics>
    ): Promise<VulnExploitPipelineResult> {
      // 1. Run vuln analysis (only for selected types)
      let vulnMetrics: AgentMetrics | null = null;
      if (input.retestVulnTypes.includes(vulnType)) {
        vulnMetrics = await runVulnAgent();
      }

      // 2. Check exploitation queue
      const decision = await a.checkExploitationQueue(activityInput, vulnType);

      // 3. Conditionally run exploit
      let exploitMetrics: AgentMetrics | null = null;
      if (decision.shouldExploit) {
        exploitMetrics = await runExploitAgent();
      }

      return {
        vulnType,
        vulnMetrics,
        exploitMetrics,
        exploitDecision: {
          shouldExploit: decision.shouldExploit,
          vulnerabilityCount: decision.vulnerabilityCount,
        },
        error: null,
      };
    }

    const maxConcurrent = input.pipelineConfig?.max_concurrent_pipelines ?? 5;
    const pipelineConfigs = buildPipelineConfigs();

    const pipelineThunks: Array<() => Promise<VulnExploitPipelineResult>> =
      pipelineConfigs.map((config) =>
        () => runVulnExploitPipeline(config.vulnType, config.runVuln, config.runExploit)
      );

    const pipelineResults = await runWithConcurrencyLimit(pipelineThunks, maxConcurrent);
    aggregatePipelineResults(pipelineResults);

    state.currentPhase = 'exploitation';
    state.currentAgent = null;
    await a.logPhaseTransition(activityInput, 'vulnerability-exploitation', 'complete');

    // === Reporting ===
    state.currentPhase = 'reporting';
    state.currentAgent = 'report';
    await a.logPhaseTransition(activityInput, 'reporting', 'start');

    await a.assembleReportActivity(activityInput);
    state.agentMetrics['report'] = await a.runReportAgent(activityInput);
    state.completedAgents.push('report');
    await a.injectReportMetadataActivity(activityInput);

    await a.logPhaseTransition(activityInput, 'reporting', 'complete');

    state.status = 'completed';
    state.currentPhase = null;
    state.currentAgent = null;
    state.summary = computeSummary(state);

    await a.logWorkflowComplete(activityInput, toWorkflowSummary(state, 'completed'));

    return state;
  } catch (error) {
    state.status = 'failed';
    state.failedAgent = state.currentAgent;
    state.error = formatWorkflowError(error, state.currentPhase, state.currentAgent);
    state.summary = computeSummary(state);

    await a.logWorkflowComplete(activityInput, toWorkflowSummary(state, 'failed'));

    throw error;
  }
}
