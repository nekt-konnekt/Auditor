import { AuditIssue, AuditReport, Category, CategoryScore } from '../types/audit.ts';
import { calculateAuditScores } from './audit-rules.ts';

export interface GitHubRepoDetails {
  owner: string;
  repo: string;
  fullName: string;
  description: string;
  stars: number;
  forks: number;
  openIssues: number;
  license?: string;
  defaultBranch: string;
  hasSecurityPolicy: boolean;
  hasWorkflows: boolean;
  gitignoreContent?: string;
  packageJsonContent?: string;
  readmeContent?: string;
}

export function parseGitHubUrl(url: string): { owner: string; repo: string } | null {
  const match = url.trim().match(/^https?:\/\/(?:www\.)?github\.com\/([a-zA-Z0-9_.-]+)\/([a-zA-Z0-9_.-]+)/i);
  if (!match) return null;
  const owner = match[1];
  let repo = match[2];
  if (repo.endsWith('.git')) repo = repo.slice(0, -4);
  return { owner, repo };
}

export async function auditGitHubRepo(url: string): Promise<AuditReport> {
  const parsed = parseGitHubUrl(url);
  if (!parsed) {
    throw new Error('Invalid GitHub repository URL format. Expected: https://github.com/owner/repo');
  }

  const { owner, repo } = parsed;
  const fullName = `${owner}/${repo}`;
  const reportId = 'gh-' + Math.random().toString(36).substring(2, 9) + Date.now().toString(36);
  const createdAt = new Date().toISOString();
  const startTime = Date.now();

  const issues: AuditIssue[] = [];
  const metrics: Record<string, string | number | boolean> = {
    'Repository': fullName,
    'Audit Mode': 'GitHub Repository Security & Architecture',
  };

  let defaultBranch = 'main';
  let license = 'None detected';
  let stars = 0;
  let openIssuesCount = 0;

  // 1. Verify that the target is an accessible public repository before auditing it.
  // Never produce a heuristic report for a missing, private, rate-limited, or
  // otherwise unverifiable repository: that would present guesses as findings.
  let apiRes: Response;
  try {
    apiRes = await fetch(`https://api.github.com/repos/${owner}/${repo}`, {
      headers: {
        'User-Agent': 'Auditor-Engine/2.4 (Security Audit Bot)',
        'Accept': 'application/vnd.github.v3+json',
      },
    });
  } catch {
    throw new Error('Could not reach the GitHub API to verify this repository. No audit report was generated.');
  }

  if (apiRes.status === 404) {
    throw new Error('GitHub repository was not found or is not publicly accessible. Auditor only supports public repositories; no report was generated.');
  }
  if (apiRes.status === 403 || apiRes.status === 429) {
    throw new Error('GitHub API access was rate-limited or denied. Retry later; no repository audit report was generated.');
  }
  if (!apiRes.ok) {
    throw new Error(`Could not verify the public GitHub repository (HTTP ${apiRes.status}). No audit report was generated.`);
  }

  const data = await apiRes.json();
  defaultBranch = data.default_branch;
  license = data.license?.spdx_id || data.license?.name || 'Unlicensed';
  stars = data.stargazers_count ?? 0;
  openIssuesCount = data.open_issues_count ?? 0;

  metrics['Default Branch'] = defaultBranch;
  metrics['License'] = license;
  metrics['GitHub Stars'] = stars;
  metrics['Open Issues'] = openIssuesCount;

  // 2. Fetch standard files from the verified default branch only. A missing
  // file is a valid observation; a fetch failure aborts rather than inventing
  // a "missing" finding from unavailable data.
  let securityMd: string | null = null;
  let gitignore: string | null = null;
  let packageJson: string | null = null;
  let readme: string | null = null;

  const fetchRaw = async (filePath: string): Promise<string | null> => {
    let res: Response;
    try {
      res = await fetch(`https://raw.githubusercontent.com/${owner}/${repo}/${defaultBranch}/${filePath}`, {
        headers: { 'User-Agent': 'Auditor-Engine/2.4' },
      });
    } catch {
      throw new Error(`Could not fetch ${filePath} from the verified default branch. No complete repository report was generated.`);
    }
    if (res.status === 404) return null;
    if (!res.ok) {
      throw new Error(`Could not inspect ${filePath} on the verified default branch (HTTP ${res.status}). No complete repository report was generated.`);
    }
    return await res.text();
  };

  const [secRes, gitignoreRes, pkgRes, readmeRes] = await Promise.all([
    fetchRaw('SECURITY.md'),
    fetchRaw('.gitignore'),
    fetchRaw('package.json'),
    fetchRaw('README.md'),
  ]);

  securityMd = secRes;
  gitignore = gitignoreRes;
  packageJson = pkgRes;
  readme = readmeRes;

  // GitHub may not classify custom license files. Probe common root filenames
  // before claiming that no license file exists.
  let licenseFilePath: string | null = null;
  let licenseFileContent: string | null = null;
  if (license === 'Unlicensed' || license === 'None detected') {
    const licenseCandidates = ['LICENSE', 'LICENSE.md', 'LICENSE.txt', 'COPYING', 'COPYING.md'];
    const candidateResults = await Promise.all(
      licenseCandidates.map(async (filePath) => ({ filePath, content: await fetchRaw(filePath) })),
    );
    const detected = candidateResults.find((candidate) => candidate.content !== null);
    if (detected) {
      licenseFilePath = detected.filePath;
      licenseFileContent = detected.content;
    }
  }

  // 3. Deterministic Security & Repository Hygiene Checks

  // Check: SECURITY.md
  metrics['Security Policy'] = securityMd ? 'Present' : 'Missing';
  if (!securityMd) {
    issues.push({
      id: 'gh-sec-policy',
      category: 'security',
      severity: 'medium',
      title: 'Missing SECURITY.md Vulnerability Disclosure Policy',
      description: 'The repository does not contain a SECURITY.md file instructing security researchers how to responsibly disclose discovered vulnerabilities.',
      impact: 'Security flaws may be published openly in public GitHub Issues rather than handled privately via confidential advisory channels.',
      remediation: 'Create a `SECURITY.md` in the repository root defining supported versions and a private contact email / PGP key for security disclosures.',
      references: [
        { title: 'GitHub: Adding a security policy', url: 'https://docs.github.com/en/code-security/getting-started/adding-a-security-policy-to-your-repository' },
      ],
      codeSnippet: {
        proposed: `# Security Policy\n\n## Supported Versions\n| Version | Supported |\n| ------- | --------- |\n| 1.0.x   | Yes       |\n\n## Reporting a Vulnerability\nPlease send security inquiries privately to security@${owner.toLowerCase()}.com.`,
      },
    });
  } else {
    issues.push({
      id: 'gh-sec-policy-pass',
      category: 'security',
      severity: 'passed',
      title: 'Security Policy (SECURITY.md) Declared',
      description: 'A formal vulnerability disclosure policy is present in the repository root.',
      evidence: securityMd.substring(0, 100),
      remediation: 'Periodically review supported versions and contact addresses.',
    });
  }

  // Check: .gitignore secret coverage
  if (gitignore) {
    const hasEnvIgnored = /^\s*\.env/m.test(gitignore);
    metrics['Secrets in .gitignore'] = hasEnvIgnored ? 'Excludes .env files' : 'No .env exclusion detected';

    if (!hasEnvIgnored) {
      issues.push({
        id: 'gh-gitignore-env',
        category: 'security',
        severity: 'medium',
        title: 'Missing .env Exclusion in .gitignore',
        description: 'The inspected `.gitignore` does not appear to exclude `.env` files. This is a preventive-hardening gap; it does not establish that secrets are present in the repository or have been exposed.',
        impact: 'If environment files containing secrets are created and committed, credentials could be exposed. This check does not scan repository history or confirm that such files exist.',
        remediation: 'Append `.env`, `.env.*`, and `.env.local` to `.gitignore`.',
        codeSnippet: {
          original: '# Current .gitignore missing .env',
          proposed: '# Environment variables\n.env\n.env.*\n.env.local\n*.pem\n*.key',
        },
      });
    } else {
      issues.push({
        id: 'gh-gitignore-pass',
        category: 'security',
        severity: 'passed',
        title: '.gitignore Excludes Environment Variable Files',
        description: '.env files are explicitly ignored, reducing risk of accidental secret leaks.',
        remediation: 'Keep secret exclusions up to date across all developer platforms.',
      });
    }
  } else {
    issues.push({
      id: 'gh-gitignore-missing',
      category: 'quality',
      severity: 'medium',
      title: 'Missing .gitignore File',
      description: 'No .gitignore file was detected in the root of the repository.',
      impact: 'Operating system artifacts, build binaries, node_modules, and temporary files will pollute the repository history.',
      remediation: 'Add a standard `.gitignore` suited to your project tech stack.',
    });
  }

  // Check: Dependency Manifest & Outdated Packages
  if (packageJson) {
    try {
      const parsedPkg = JSON.parse(packageJson);
      const depCount = Object.keys(parsedPkg.dependencies || {}).length;
      const devDepCount = Object.keys(parsedPkg.devDependencies || {}).length;
      metrics['Dependencies'] = `${depCount} prod, ${devDepCount} dev`;

      // Check for known risky dependencies or wildcard versions
      const allDeps = { ...(parsedPkg.dependencies || {}), ...(parsedPkg.devDependencies || {}) };
      const wildcardDeps = Object.entries(allDeps).filter(([_, ver]) => String(ver).includes('*') || String(ver) === 'latest');

      if (wildcardDeps.length > 0) {
        issues.push({
          id: 'gh-pkg-wildcard',
          category: 'security',
          severity: 'medium',
          title: `Wildcard Dependency Version Ranges (${wildcardDeps.length})`,
          description: `Dependencies using a wildcard or the latest tag were found: ${wildcardDeps.map(([d]) => d).join(', ')}.`,
          impact: 'These ranges can make dependency resolution less reproducible. This observation does not by itself establish that a package is vulnerable or that a supply-chain compromise occurred.',
          remediation: 'Prefer bounded version ranges and commit/maintain the appropriate lockfile. Use exact versions where your reproducibility policy requires them; verify actual package vulnerabilities with a dependency advisory scanner.',
        });
      } else {
        issues.push({
          id: 'gh-pkg-pass',
          category: 'quality',
          severity: 'passed',
          title: 'Dependencies Properly Version-Pinned',
          description: `All ${depCount + devDepCount} declared packages use bounded semantic version constraints.`,
          remediation: 'Run automated audit tooling like npm audit or Snyk.',
        });
      }
    } catch {
      // Malformed package.json
    }
  }

  // Check: Open Source Licensing
  metrics['Open Source License'] = licenseFilePath
    ? `License file present but not classified by GitHub (${licenseFilePath})`
    : license;
  if (!license || license === 'Unlicensed' || license === 'None detected') {
    if (licenseFilePath) {
      issues.push({
        id: 'gh-license-unclassified',
        category: 'quality',
        severity: 'low',
        title: 'License File Present but Not Classified',
        description: `A root-level ${licenseFilePath} file was found, but GitHub did not identify a recognized license. Auditor has not determined whether the file grants reuse rights.`,
        impact: 'The license terms may require human review; file presence alone does not establish that the project is permissively licensed.',
        evidence: (licenseFileContent || '').substring(0, 180),
        remediation: 'Review the license text and confirm it clearly defines the rights and restrictions intended for this repository.',
      });
    } else {
      issues.push({
        id: 'gh-license-missing',
        category: 'quality',
        severity: 'medium',
        title: 'No Common Root-Level License File Detected',
        description: 'GitHub did not report a recognized license, and Auditor did not find a license file at the common root-level paths it checked. Other locations or custom arrangements were not inspected.',
        impact: 'Without applicable license terms, others may not have permission to reuse or redistribute the code. This check is limited to repository metadata and common root-level filenames.',
        remediation: 'Confirm the intended licensing policy and add an appropriate license file if the repository is meant to be reused or distributed.',
        references: [{ title: 'Choose an Open Source License', url: 'https://choosealicense.com/' }],
      });
    }
  } else {
    issues.push({
      id: 'gh-license-pass',
      category: 'quality',
      severity: 'passed',
      title: `GitHub Reports a Recognized License (${license})`,
      description: `GitHub's repository metadata identifies the license as ${license}; this is a metadata observation, not a full legal review.`,
      remediation: 'Confirm that the declared license matches your intended distribution and dependency obligations.',
    });
  }

  // Check: Documentation & README
  metrics['README Documentation'] = readme ? `${Math.round(readme.length / 1024)} KB` : 'Missing';
  if (!readme || readme.length < 150) {
    issues.push({
      id: 'gh-readme-sparse',
      category: 'quality',
      severity: 'low',
      title: 'Sparse or Missing README Documentation',
      description: 'The repository README provides little to no setup instructions, architecture overview, or quickstart guide.',
      impact: 'Impairs developer onboarding and reduces discoverability in search and GitHub explore.',
      remediation: 'Add a structured README with installation steps, prerequisites, configuration, and testing commands.',
    });
  } else {
    issues.push({
      id: 'gh-readme-pass',
      category: 'quality',
      severity: 'passed',
      title: 'Comprehensive README Documentation',
      description: `README is well-documented (${Math.round(readme.length / 1024)} KB).`,
      remediation: 'Maintain updated architecture diagrams and deployment instructions.',
    });
  }

  // This mode inspects repository metadata and selected root-level files only.
  // Do not send this metadata summary to a source-code auditor or describe it as
  // a source-level security review.
  const allIssues = issues;
  const { overallScore, categories } = calculateAuditScores(allIssues);

  const responseTimeMs = Date.now() - startTime;

  return {
    id: reportId,
    createdAt,
    target: {
      type: 'url',
      target: `https://github.com/${fullName}`,
      filename: fullName,
      statusCode: 200,
      responseTimeMs,
      contentType: 'application/vnd.github.v3+json',
      resourceSizeKb: Math.round(((readme?.length || 0) + (packageJson?.length || 0)) / 1024),
    },
    overallScore,
    categories,
    summary: `Repository hygiene review of ${fullName}. Auditor inspected public repository metadata and selected root-level files on the default branch (including SECURITY.md, .gitignore, package.json, README.md, and common license filenames). It did not scan all source files, repository history, secrets across the full tree, dependency advisories, deployed runtime behavior, or private content. Treat findings as limited observations, not a complete security audit.`,
    issues: allIssues,
    metrics,
  };
}
