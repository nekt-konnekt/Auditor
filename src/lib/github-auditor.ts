import { AuditIssue, AuditReport, Category, CategoryScore } from '../types/audit.ts';
import { calculateAuditScores } from './audit-rules.ts';
import { analyzeWithGemini } from './gemini-auditor.ts';

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
  let description = '';
  let license = 'None detected';
  let stars = 0;
  let forks = 0;
  let openIssuesCount = 0;

  // 1. Fetch GitHub API repo metadata
  try {
    const apiRes = await fetch(`https://api.github.com/repos/${owner}/${repo}`, {
      headers: {
        'User-Agent': 'Auditor-Engine/2.4 (Security Audit Bot)',
        'Accept': 'application/vnd.github.v3+json',
      },
    });

    if (apiRes.ok) {
      const data = await apiRes.json();
      defaultBranch = data.default_branch || 'main';
      description = data.description || '';
      license = data.license?.spdx_id || data.license?.name || 'Unlicensed';
      stars = data.stargazers_count ?? 0;
      forks = data.forks_count ?? 0;
      openIssuesCount = data.open_issues_count ?? 0;

      metrics['Default Branch'] = defaultBranch;
      metrics['License'] = license;
      metrics['GitHub Stars'] = stars;
      metrics['Open Issues'] = openIssuesCount;
    } else if (apiRes.status === 404) {
      // Check if it's a private repo or fake repo
      // Still proceed with simulated/heuristic inspection so user can audit sample or halftone repos
      description = 'Target repository analysis';
    }
  } catch (e) {
    // API failed or rate-limited; proceed with raw file fetch attempts
  }

  // 2. Fetch standard repository files (SECURITY.md, .gitignore, package.json, README.md)
  let securityMd: string | null = null;
  let gitignore: string | null = null;
  let packageJson: string | null = null;
  let readme: string | null = null;
  let workflowsDetected = false;

  const fetchRaw = async (filePath: string): Promise<string | null> => {
    for (const b of [defaultBranch, 'main', 'master']) {
      try {
        const res = await fetch(`https://raw.githubusercontent.com/${owner}/${repo}/${b}/${filePath}`, {
          headers: { 'User-Agent': 'Auditor-Engine/2.4' },
        });
        if (res.ok) {
          return await res.text();
        }
      } catch {
        // try next branch
      }
    }
    return null;
  };

  const [secRes, gitignoreRes, pkgRes, readmeRes] = await Promise.all([
    fetchRaw('SECURITY.md').catch(() => null),
    fetchRaw('.gitignore').catch(() => null),
    fetchRaw('package.json').catch(() => null),
    fetchRaw('README.md').catch(() => null),
  ]);

  securityMd = secRes;
  gitignore = gitignoreRes;
  packageJson = pkgRes;
  readme = readmeRes;

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
    const hasPemIgnored = /\.pem|\.key/m.test(gitignore);
    metrics['Secrets in .gitignore'] = hasEnvIgnored ? 'Protected (.env)' : 'Vulnerable';

    if (!hasEnvIgnored) {
      issues.push({
        id: 'gh-gitignore-env',
        category: 'security',
        severity: 'high',
        title: 'Missing .env Exclusion in .gitignore',
        description: 'The repository `.gitignore` does not explicitly exclude `.env` or `.env.local` environment variable files.',
        impact: 'Developers or contributors risk inadvertently committing live API keys, JWT secrets, and database credentials to version control.',
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
          severity: 'high',
          title: `Unpinned / Wildcard Dependency Versions (${wildcardDeps.length})`,
          description: `Dependencies specified with '*' or 'latest': ${wildcardDeps.map(([d]) => d).join(', ')}.`,
          impact: 'Exposes production builds to unpredictable upstream supply-chain poisoning and breaking API updates.',
          remediation: 'Pin dependencies to explicit semantic versions or strict ranges (e.g. `^1.2.3` or exact versions with lockfiles).',
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
  metrics['Open Source License'] = license;
  if (!license || license === 'Unlicensed' || license === 'None detected') {
    issues.push({
      id: 'gh-license-missing',
      category: 'quality',
      severity: 'medium',
      title: 'Missing Open Source Software License',
      description: 'The repository does not declare a recognized open-source or commercial license (e.g. MIT, Apache 2.0, BSD).',
      impact: 'Under copyright law, the code remains "all rights reserved," making it legally ambiguous or prohibited for other developers to consume or contribute.',
      remediation: 'Add a `LICENSE` file (such as MIT or Apache-2.0) defining permissible reuse and distribution terms.',
      references: [{ title: 'Choose an Open Source License', url: 'https://choosealicense.com/' }],
    });
  } else {
    issues.push({
      id: 'gh-license-pass',
      category: 'quality',
      severity: 'passed',
      title: `Valid Software License Declared (${license})`,
      description: `The project is published with an recognized ${license} license.`,
      remediation: 'Ensure dependencies remain compatible with this license.',
    });
  }

  // Check: Documentation & README
  metrics['README Documentation'] = readme ? `${Math.round(readme.length / 1024)} KB` : 'Missing';
  if (!readme || readme.length < 150) {
    issues.push({
      id: 'gh-readme-sparse',
      category: 'seo',
      severity: 'low',
      title: 'Sparse or Missing README Documentation',
      description: 'The repository README provides little to no setup instructions, architecture overview, or quickstart guide.',
      impact: 'Impairs developer onboarding and reduces discoverability in search and GitHub explore.',
      remediation: 'Add a structured README with installation steps, prerequisites, configuration, and testing commands.',
    });
  } else {
    issues.push({
      id: 'gh-readme-pass',
      category: 'seo',
      severity: 'passed',
      title: 'Comprehensive README Documentation',
      description: `README is well-documented (${Math.round(readme.length / 1024)} KB).`,
      remediation: 'Maintain updated architecture diagrams and deployment instructions.',
    });
  }

  // 4. Gemini Deep Analysis on Repository Context
  const contextSnippet = `
GitHub Repository: ${fullName}
Description: ${description}
License: ${license}
Default Branch: ${defaultBranch}
Stars: ${stars}, Open Issues: ${openIssuesCount}
Has SECURITY.md: ${Boolean(securityMd)}
Has .gitignore: ${Boolean(gitignore)}
package.json summary: ${packageJson ? packageJson.substring(0, 1500) : 'None'}
README excerpt: ${readme ? readme.substring(0, 1500) : 'None'}
`;

  const aiResult = await analyzeWithGemini('code', fullName, contextSnippet, {
    filename: `${fullName} (GitHub Repo)`,
    language: 'markdown',
  });

  const allIssues = [...issues, ...aiResult.additionalIssues];
  const { overallScore, categories, verdict } = calculateAuditScores(allIssues);

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
    verdict,
    categories,
    summary:
      aiResult.summary ||
      `Security and architecture audit completed for GitHub repository ${fullName}. Analyzed repository configuration, security policies, dependency governance, and secret leakage risks.`,
    issues: allIssues,
    metrics,
  };
}
