// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Generates diff context for retest mode.
 *
 * Computes what changed between the checkpoint hash (from the previous run)
 * and HEAD, writes the diff to deliverables/retest_context.md, and returns
 * the retest preamble text for agent prompts.
 */

import { fs, path } from 'zx';
import type { Result } from '../types/result.js';
import { ok, err } from '../types/result.js';
import { PentestError } from './error-handling.js';
import { ErrorCode } from '../types/errors.js';
import { executeGitCommandWithRetry } from './git-manager.js';
import type { ActivityLogger } from '../types/activity-logger.js';
import type { VulnType } from '../types/agents.js';
import { AGENTS } from '../session-manager.js';
import type { AgentName } from '../types/agents.js';
import { fileExists } from '../utils/file-io.js';

const MAX_DIFF_BYTES = 100 * 1024; // 100KB

// Directories and patterns created by Shannon agents, excluded from retest diffs
const SHANNON_ARTIFACT_DIRS = ['deliverables', 'workspace', '.security'];

/**
 * Build pathspec exclusions for git diff by comparing the tree at the checkpoint
 * against the tree at the commit before Shannon first touched the repo.
 * Any top-level entries that exist at the checkpoint but not at the pre-Shannon
 * base are Shannon artifacts and should be excluded from the diff.
 */
async function buildDiffExclusions(
  repoPath: string,
  checkpointHash: string
): Promise<string[]> {
  // 1. Find the pre-Shannon base commit: walk back from checkpoint until we find
  //    a commit that wasn't created by Shannon (no checkpoint/success prefix)
  const logResult = await executeGitCommandWithRetry(
    ['git', 'log', '--format=%H %s', '--max-count=100', checkpointHash],
    repoPath,
    'find pre-Shannon base commit'
  );

  const commits = logResult.stdout.trim().split('\n');
  let baseHash: string | null = null;
  for (const line of commits) {
    const message = line.substring(41); // Skip hash + space
    if (!message.startsWith('📍 Checkpoint:') && !message.startsWith('✅ ')) {
      baseHash = line.substring(0, 40);
      break;
    }
  }

  if (!baseHash) {
    // Fallback: just exclude known Shannon directories
    return ['--', ...SHANNON_ARTIFACT_DIRS.map((d) => `:(exclude)${d}`)];
  }

  // 2. Get top-level entries at both commits
  const [checkpointTree, baseTree] = await Promise.all([
    executeGitCommandWithRetry(
      ['git', 'ls-tree', '--name-only', checkpointHash],
      repoPath,
      'list entries at checkpoint'
    ),
    executeGitCommandWithRetry(
      ['git', 'ls-tree', '--name-only', baseHash],
      repoPath,
      'list entries at pre-Shannon base'
    ),
  ]);

  const checkpointEntries = new Set(checkpointTree.stdout.trim().split('\n').filter(Boolean));
  const baseEntries = new Set(baseTree.stdout.trim().split('\n').filter(Boolean));

  // 3. Entries in checkpoint but not in base are Shannon artifacts
  const shannonArtifacts: string[] = [];
  for (const entry of checkpointEntries) {
    if (!baseEntries.has(entry)) {
      shannonArtifacts.push(entry);
    }
  }

  if (shannonArtifacts.length === 0) {
    return [];
  }

  return ['--', ...shannonArtifacts.map((p) => `:(exclude)${p}`)];
}

/** Map vuln type to its vuln and exploit agent names. */
const VULN_TYPE_AGENTS: Record<VulnType, { vuln: AgentName; exploit: AgentName }> = {
  injection: { vuln: 'injection-vuln', exploit: 'injection-exploit' },
  xss: { vuln: 'xss-vuln', exploit: 'xss-exploit' },
  auth: { vuln: 'auth-vuln', exploit: 'auth-exploit' },
  ssrf: { vuln: 'ssrf-vuln', exploit: 'ssrf-exploit' },
  authz: { vuln: 'authz-vuln', exploit: 'authz-exploit' },
};

/**
 * Generate retest context file from git diff and return the retest prompt preamble.
 */
export async function generateRetestContextFile(
  repoPath: string,
  checkpointHash: string,
  selectedVulnTypes: VulnType[],
  logger: ActivityLogger
): Promise<Result<string, PentestError>> {
  try {
    // Build list of source-code-only paths by examining what existed at the checkpoint
    const excludeArgs = await buildDiffExclusions(repoPath, checkpointHash);

    // 1. Get diff stats
    const diffStat = await executeGitCommandWithRetry(
      ['git', 'diff', `${checkpointHash}..HEAD`, '--stat', ...excludeArgs],
      repoPath,
      'diff stat for retest'
    );

    // 2. Get full diff
    const diffFull = await executeGitCommandWithRetry(
      ['git', 'diff', `${checkpointHash}..HEAD`, ...excludeArgs],
      repoPath,
      'full diff for retest'
    );

    // 3. Get list of changed files
    const diffNames = await executeGitCommandWithRetry(
      ['git', 'diff', `${checkpointHash}..HEAD`, '--name-only', ...excludeArgs],
      repoPath,
      'changed file list for retest'
    );

    // 4. Truncate diff if too large
    let fullDiff = diffFull.stdout;
    let truncated = false;
    if (Buffer.byteLength(fullDiff, 'utf8') > MAX_DIFF_BYTES) {
      fullDiff = fullDiff.slice(0, MAX_DIFF_BYTES);
      truncated = true;
    }

    // 5. Scan for existing deliverables from the previous run
    const previousDeliverables = await findPreviousDeliverables(repoPath);

    // 6. Check for foundational deliverables (code analysis + recon)
    const foundational = {
      codeAnalysis: await fileExists(path.join(repoPath, 'deliverables', 'code_analysis_deliverable.md')),
      recon: await fileExists(path.join(repoPath, 'deliverables', 'recon_deliverable.md')),
    };

    // 7. Build markdown content (pure function, no I/O)
    const changedFiles = diffNames.stdout.trim().split('\n').filter(Boolean);
    const content = buildRetestMarkdown(
      checkpointHash,
      diffStat.stdout,
      fullDiff,
      truncated,
      changedFiles,
      selectedVulnTypes,
      previousDeliverables,
      foundational
    );

    // 8. Write to deliverables
    const deliverablesDir = path.join(repoPath, 'deliverables');
    await fs.ensureDir(deliverablesDir);
    const contextPath = path.join(deliverablesDir, 'retest_context.md');
    await fs.writeFile(contextPath, content, 'utf8');

    logger.info(`Retest context written to ${contextPath}`, {
      changedFiles: changedFiles.length,
      diffBytes: Buffer.byteLength(fullDiff, 'utf8'),
      truncated,
      previousDeliverables: previousDeliverables.length,
    });

    // 9. Load and return the retest preamble text
    const preamblePath = path.join(
      import.meta.dirname, '..', '..', 'prompts', 'shared', '_retest-context.txt'
    );
    const preamble = await fs.readFile(preamblePath, 'utf8');
    return ok(preamble);
  } catch (error) {
    if (error instanceof PentestError) {
      return err(error);
    }
    const message = error instanceof Error ? error.message : String(error);
    return err(
      new PentestError(
        `Failed to generate retest context: ${message}`,
        'filesystem',
        false,
        { repoPath, checkpointHash },
        ErrorCode.GIT_CHECKPOINT_FAILED
      )
    );
  }
}

interface PreviousDeliverable {
  vulnType: VulnType;
  agentName: string;
  filename: string;
  role: 'analysis' | 'exploitation';
}

/**
 * Scan deliverables/ for existing files from the previous run.
 * Returns metadata for each found deliverable so retest_context.md can reference them.
 */
async function findPreviousDeliverables(
  repoPath: string
): Promise<PreviousDeliverable[]> {
  const found: PreviousDeliverable[] = [];

  // Check all 5 vuln types (not just selected) so exploit agents for
  // non-retested types can still reference their previous vuln findings
  const allTypes: VulnType[] = ['injection', 'xss', 'auth', 'ssrf', 'authz'];

  for (const vulnType of allTypes) {
    const agents = VULN_TYPE_AGENTS[vulnType];

    const vulnFilename = AGENTS[agents.vuln].deliverableFilename;
    const vulnPath = path.join(repoPath, 'deliverables', vulnFilename);
    if (await fileExists(vulnPath)) {
      found.push({
        vulnType,
        agentName: agents.vuln,
        filename: vulnFilename,
        role: 'analysis',
      });
    }

    const exploitFilename = AGENTS[agents.exploit].deliverableFilename;
    const exploitPath = path.join(repoPath, 'deliverables', exploitFilename);
    if (await fileExists(exploitPath)) {
      found.push({
        vulnType,
        agentName: agents.exploit,
        filename: exploitFilename,
        role: 'exploitation',
      });
    }
  }

  return found;
}

interface FoundationalDeliverables {
  codeAnalysis: boolean;
  recon: boolean;
}

function buildRetestMarkdown(
  checkpointHash: string,
  diffStat: string,
  fullDiff: string,
  truncated: boolean,
  changedFiles: string[],
  selectedVulnTypes: VulnType[],
  previousDeliverables: PreviousDeliverable[],
  foundational: FoundationalDeliverables
): string {
  const lines: string[] = [
    '# Retest Context',
    '',
    `**Checkpoint:** \`${checkpointHash}\``,
    `**Retesting:** ${selectedVulnTypes.join(', ')}`,
    `**Changed files:** ${changedFiles.length}`,
    '',
    '## Previous Findings',
    '',
    'The following deliverables from the previous run are available in `deliverables/`.',
    'Read these to understand what was found before and compare against the current code.',
    '',
  ];

  if (foundational.codeAnalysis || foundational.recon) {
    lines.push('### Foundational Analysis', '');
    if (foundational.codeAnalysis) {
      lines.push('- **Code analysis**: `deliverables/code_analysis_deliverable.md`');
    }
    if (foundational.recon) {
      lines.push('- **Reconnaissance**: `deliverables/recon_deliverable.md`');
    }
    lines.push('');
  }

  if (previousDeliverables.length === 0) {
    lines.push('*No previous vuln/exploit deliverables found.*', '');
  } else {
    for (const vulnType of selectedVulnTypes) {
      const typeDeliverables = previousDeliverables.filter((d) => d.vulnType === vulnType);
      if (typeDeliverables.length > 0) {
        lines.push(`### ${vulnType}`, '');
        for (const d of typeDeliverables) {
          lines.push(`- **${d.role}**: \`deliverables/${d.filename}\``);
        }
        lines.push('');
      }
    }

    // Also list non-retested types that have deliverables (for exploit agent context)
    const nonRetested = previousDeliverables.filter(
      (d) => !selectedVulnTypes.includes(d.vulnType)
    );
    if (nonRetested.length > 0) {
      lines.push('### Other (not being retested, for reference)', '');
      for (const d of nonRetested) {
        lines.push(`- **${d.vulnType} ${d.role}**: \`deliverables/${d.filename}\``);
      }
      lines.push('');
    }
  }

  lines.push(
    '## Diff Summary',
    '',
    '```',
    diffStat.trim(),
    '```',
    '',
    '## Changed Files',
    '',
    ...changedFiles.map((f) => `- \`${f}\``),
    '',
    '## Full Diff',
    '',
    '```diff',
    fullDiff.trim(),
    '```',
  );

  if (truncated) {
    lines.push('', '*Diff truncated at 100KB. Review the full diff with `git diff` for complete changes.*');
  }

  lines.push('');
  return lines.join('\n');
}
