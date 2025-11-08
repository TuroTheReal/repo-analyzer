"""
Report generation for analysis.
"""

import os
from datetime import datetime
from pathlib import Path
from html_reporter import HTMLReportGenerator
from score_calculator import SecurityScoreCalculator

class ReportGenerator:
	"""Generates analysis reports in different formats."""

	def __init__(self, output_dir="output"):
		"""
		Args:
			output_dir: Directory to save reports
		"""
		self.output_dir = output_dir

		# Create directory if it doesn't exist
		Path(output_dir).mkdir(exist_ok=True)

		# Initialize HTML generator
		self.html_generator = HTMLReportGenerator(output_dir)

		# Initialize score calculator
		self.score_calculator = SecurityScoreCalculator()

	def generate_markdown(self, owner, repo, repo_info, languages,
						contributors, structure, dependencies, security_results, docker_results):
		"""
		Generate complete Markdown report.
		Returns:
			str: Path to generated file
		"""

		timestamp = datetime.now().strftime("%Y-%m-%d")
		filename = f"{repo}-{timestamp}.md"
		filepath = os.path.join(self.output_dir, filename)

		# Build markdown content
		md_content = self._build_markdown_content(
			owner, repo, repo_info, languages, contributors,
			structure, dependencies, security_results, docker_results
		)

		# Write file
		with open(filepath, 'w', encoding='utf-8') as f:
			f.write(md_content)

		return filepath

	def generate_html(self, owner, repo, repo_info, languages,
					contributors, structure, dependencies, security_results, docker_results):
		"""
		Generate interactive HTML report.
		Returns:
			str: Path to generated file
		"""
		return self.html_generator.generate_html(
			owner, repo, repo_info, languages, contributors,
			structure, dependencies, security_results, docker_results
		)

	def _build_markdown_content(self, owner, repo, repo_info, languages,
								contributors, structure, dependencies, security_results, docker_results):
		"""Build markdown content."""

		# Calculate unified score with GitHub data flag
		has_github_data = bool(languages) or bool(contributors)

		score_data = self.score_calculator.calculate_unified_score(
			security_results, docker_results, structure, has_github_data
		)

		# Header
		md = f"# Analysis of {owner}/{repo}\n\n"
		md += f"**Generated on:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
		md += f"**URL:** https://github.com/{owner}/{repo}\n\n"

		# Unified Score
		md += f"## 🎯 Security Score: {score_data['grade']} ({score_data['total_score']}/100)\n\n"
		md += f"**{score_data['description']}**\n\n"

		# Add local analysis note if applicable
		if score_data.get('is_local_analysis'):
			md += "> **Note:** This is a local analysis. GitHub metadata (stars, forks, contributors) is not available.\n\n"

		md += "| Component | Score | Weight |\n"
		md += "|-----------|-------|--------|\n"
		md += f"| Security | {score_data['security_score']}/100 | 50% |\n"
		md += f"| Docker | {score_data['docker_score']}/100 | 30% |\n"
		md += f"| Best Practices | {score_data['best_practices_score']}/100 | 20% |\n\n"
		md += "---\n\n"

		# Table of contents
		md += "## 📑 Table of Contents\n\n"
		md += "- [Metadata](#metadata)\n"
		if languages:
			md += "- [Languages](#languages)\n"
		if contributors:
			md += "- [Contributors](#contributors)\n"
		md += "- [Structure](#structure)\n"
		md += "- [Best Practices](#best-practices)\n"
		if docker_results['total'] > 0 or docker_results['dockerfiles'] or docker_results['compose_files']:
			md += "- [Docker Configuration](#docker-configuration)\n"
		md += "- [Dependencies](#dependencies)\n"
		md += "- [Security](#security)\n"
		md += "- [Recommendations](#recommendations)\n\n"
		md += "---\n\n"

		# Metadata
		md += "## 📊 Metadata\n\n"
		md += f"**Full name:** {repo_info['full_name']}\n\n"
		md += f"**Description:** {repo_info['description']}\n\n"

		md += "| Metric | Value |\n"
		md += "|--------|-------|\n"

		# Safe display for GitHub-only metrics
		stars = repo_info.get('stars')
		forks = repo_info.get('forks')
		watchers = repo_info.get('watchers')
		open_issues = repo_info.get('open_issues')

		md += f"| ⭐ Stars | {stars:,} |\n" if isinstance(stars, int) else "| ⭐ Stars | N/A |\n"
		md += f"| 🍴 Forks | {forks:,} |\n" if isinstance(forks, int) else "| 🍴 Forks | N/A |\n"
		md += f"| 👀 Watchers | {watchers:,} |\n" if isinstance(watchers, int) else "| 👀 Watchers | N/A |\n"
		md += f"| 🛠 Open issues | {open_issues} |\n" if isinstance(open_issues, int) else "| 🛠 Open issues | N/A |\n"

		md += f"| ⚖️ License | {repo_info['license']} |\n"
		md += f"| 📅 Created | {repo_info['created_at'][:10] if repo_info['created_at'] != 'N/A' else 'N/A'} |\n"
		md += f"| 🔄 Last update | {repo_info['updated_at'][:10] if repo_info['updated_at'] != 'N/A' else 'N/A'} |\n"
		md += f"| 🌿 Default branch | {repo_info['default_branch']} |\n"
		md += f"| 💾 Size | {repo_info['size'] / 1024:.1f} MB |\n\n"

		# Languages (only if available)
		if languages:
			md += "## 💻 Languages\n\n"
			md += "```\n"
			for lang, percent in languages.items():
				bar_length = int(percent / 2)  # 1 char = 2%
				bar = "█" * bar_length
				md += f"{lang:<15} {bar} {percent}%\n"
			md += "```\n\n"

		# Contributors (only if available)
		if contributors:
			md += "## 👥 Contributors\n\n"
			md += "Top 5 contributors:\n\n"
			md += "| Rank | Contributor | Commits |\n"
			md += "|------|-------------|----------|\n"
			for i, contrib in enumerate(contributors[:5], 1):
				md += f"| {i} | [{contrib['login']}](https://github.com/{contrib['login']}) | {contrib['contributions']:,} |\n"
			md += "\n"

		# Structure
		md += "## 📂 Structure\n\n"
		md += "### General statistics\n\n"
		md += f"- **Total files:** {structure.get('total_files', 0):,}\n"
		md += f"- **Directories:** {structure.get('total_dirs', 0):,}\n"
		md += f"- **Max depth:** {structure.get('max_depth', 0)} levels\n\n"

		md += "### Detected features\n\n"
		md += f"- **Tests:** {'✅ Present' if structure.get('has_tests') else '❌ Missing'}\n"
		md += f"- **CI/CD:** {'✅ Configured' if structure.get('has_ci') else '❌ Not configured'}\n"
		md += f"- **Docker:** {'✅ Present' if structure.get('has_docker') else '❌ Missing'}\n\n"

		# Important files
		if structure.get('important_files'):
			md += "### Important files detected\n\n"
			for f in sorted(structure['important_files']):
				md += f"- ✅ `{f}`\n"
			md += "\n"

		# File types
		if structure.get('file_types'):
			md += "### File type distribution\n\n"
			md += "| Extension | Count |\n"
			md += "|-----------|-------|\n"
			for ext, count in list(structure['file_types'].items())[:15]:
				md += f"| `{ext}` | {count} |\n"
			md += "\n"

		# Best Practices Section
		md += self._generate_best_practices_section(structure, security_results, score_data)

		# Docker Configuration
		if docker_results['total'] > 0 or docker_results['dockerfiles'] or docker_results['compose_files']:
			md += "## 🐳 Docker Configuration\n\n"

			if docker_results['dockerfiles']:
				md += f"**Dockerfiles found:** {len(docker_results['dockerfiles'])}\n"
				for df in docker_results['dockerfiles']:
					md += f"- `{df}`\n"
				md += "\n"

			if docker_results['compose_files']:
				md += f"**Docker Compose files found:** {len(docker_results['compose_files'])}\n"
				for cf in docker_results['compose_files']:
					md += f"- `{cf}`\n"
				md += "\n"

			if docker_results['total'] > 0:
				md += f"### Docker Issues ({docker_results['total']})\n\n"

				# Summary by severity
				md += "| Severity | Count |\n"
				md += "|----------|-------|\n"
				md += f"| 🔴 Critical | {len(docker_results['critical'])} |\n"
				md += f"| 🟠 High | {len(docker_results['high'])} |\n"
				md += f"| 🟡 Medium | {len(docker_results['medium'])} |\n"
				md += f"| 🔵 Low | {len(docker_results['low'])} |\n"
				md += f"| ℹ️ Info | {len(docker_results.get('info', []))} |\n\n"

				# Details by severity
				severity_names = {
					"critical": "🔴 Critical",
					"high": "🟠 High",
					"medium": "🟡 Medium",
					"low": "🔵 Low",
					"info": "ℹ️ Info"
				}

				for severity in ["critical", "high", "medium", "low", "info"]:
					alerts = docker_results.get(severity, [])
					if not alerts:
						continue

					md += f"#### {severity_names[severity]} ({len(alerts)})\n\n"

					for alert in alerts:
						file_info = f"`{alert['file']}`" + (f":{alert['line']}" if alert.get('line', 0) > 0 else "")
						md += f"**{alert['message']}**\n\n"
						md += f"- **File:** {file_info}\n"
						if 'recommendation' in alert:
							md += f"- **Recommendation:** {alert['recommendation']}\n"
						md += "\n"
			else:
				md += "✅ **No Docker issues detected!**\n\n"

		# Dependencies
		if dependencies:
			md += "## 📦 Dependencies\n\n"
			for dep_type, deps in dependencies.items():
				md += f"### {dep_type.capitalize()}\n\n"
				if deps:
					for dep in deps:
						md += f"- `{dep}`\n"
					md += "\n"
				else:
					md += "*No dependencies detected*\n\n"

		# Security
		md += "## 🔒 Security\n\n"

		total_issues = security_results['total']

		if total_issues == 0:
			md += "✅ **No security issues detected!**\n\n"
			md += "The scan found no exposed secrets, sensitive files, or outdated dependencies.\n\n"
		else:
			md += f"⚠️ **{total_issues} issue(s) detected**\n\n"

			# Summary by severity
			md += "### Summary\n\n"
			md += "| Severity | Count |\n"
			md += "|----------|-------|\n"
			md += f"| 🔴 Critical | {len(security_results['critical'])} |\n"
			md += f"| 🟠 High | {len(security_results['high'])} |\n"
			md += f"| 🟡 Medium | {len(security_results['medium'])} |\n"
			md += f"| 🔵 Low | {len(security_results['low'])} |\n\n"

			# Details by severity
			severity_names = {
				"critical": "🔴 Critical",
				"high": "🟠 High",
				"medium": "🟡 Medium",
				"low": "🔵 Low"
			}

			for severity in ["critical", "high", "medium", "low"]:
				alerts = security_results.get(severity, [])
				if not alerts:
					continue

				md += f"### {severity_names[severity]} ({len(alerts)})\n\n"

				for alert in alerts:
					if alert["type"] == "secret_exposed":
						md += f"**Secret detected: {alert['secret_type'].replace('_', ' ').title()}**\n\n"
						md += f"- **File:** `{alert['file']}:{alert['line']}`\n"
						md += f"- **Preview:** `{alert['preview'][:80]}...`\n\n"

					elif alert["type"] == "sensitive_file":
						md += f"**Sensitive file: `{alert['file']}`**\n\n"
						md += f"- {alert['message']}\n\n"

					elif alert["type"] == "outdated_dependency":
						md += f"**Outdated dependency: {alert['package']}**\n\n"
						md += f"- **Current version:** {alert['current_version']}\n"
						md += f"- **Recommended version:** >={alert['min_safe_version']}\n"
						md += f"- **Reason:** {alert['message']}\n\n"

					else:
						md += f"**{alert.get('message', 'Alert')}**\n\n"
						if 'file' in alert:
							md += f"- **File:** `{alert['file']}`\n\n"

		# Recommendations
		md += "## 💡 Recommendations\n\n"
		recommendations = self._generate_recommendations(structure, security_results, dependencies, docker_results)

		if recommendations:
			for i, rec in enumerate(recommendations, 1):
				md += f"{i}. {rec}\n"
			md += "\n"
		else:
			md += "✅ No specific recommendations. The project looks well configured!\n\n"

		# Footer
		md += "---\n\n"
		md += "*Report automatically generated by [GitHub Repository Analyzer](https://github.com/TuroTheReal/repo-analyzer)*\n"

		return md

	def _generate_best_practices_section(self, structure, security_results, score_data):
		"""Generate detailed best practices section."""
		md = "## ✨ Best Practices\n\n"

		best_practices_score = score_data['best_practices_score']

		md += f"**Overall Best Practices Score: {best_practices_score}/100**\n\n"

		# Tests (+30 points)
		has_tests = structure.get('has_tests')
		md += "### 🧪 Testing (30 points)\n\n"
		if has_tests:
			md += "- ✅ **Test directory detected** (+30 points)\n"
			md += "  - Tests are essential for code quality and reliability\n"
			md += "  - Helps catch bugs early in development\n\n"
		else:
			md += "- ❌ **No test directory found** (0 points)\n"
			md += "  - **Action needed:** Add a `tests/` or `test/` directory\n"
			md += "  - Recommended frameworks:\n"
			md += "    - Python: `pytest`, `unittest`\n"
			md += "    - JavaScript/TypeScript: `Jest`, `Mocha`, `Vitest`\n"
			md += "    - Java: `JUnit`, `TestNG`\n"
			md += "    - Go: built-in `testing` package\n\n"

		# CI/CD (+25 points)
		has_ci = structure.get('has_ci')
		md += "### 🔄 CI/CD Configuration (25 points)\n\n"
		if has_ci:
			md += "- ✅ **CI/CD configuration detected** (+25 points)\n"
			md += "  - Automated workflows improve code quality\n"
			md += "  - Detected configuration files:\n"
			for file in structure.get('important_files', []):
				if any(ci in file for ci in ['.github/workflows', '.gitlab-ci.yml', 'Jenkinsfile', '.circleci']):
					md += f"    - `{file}`\n"
			md += "\n"
		else:
			md += "- ❌ **No CI/CD configuration found** (0 points)\n"
			md += "  - **Action needed:** Set up continuous integration\n"
			md += "  - Popular CI/CD platforms:\n"
			md += "    - GitHub Actions (`.github/workflows/*.yml`)\n"
			md += "    - GitLab CI (`.gitlab-ci.yml`)\n"
			md += "    - Jenkins (`Jenkinsfile`)\n"
			md += "    - CircleCI (`.circleci/config.yml`)\n"
			md += "  - Benefits: Automated testing, linting, deployments\n\n"

		# .gitignore (+20 points)
		has_proper_gitignore = not any(
			a['type'] in ['incomplete_gitignore', 'missing_gitignore']
			for a in security_results['low']
		)
		md += "### 📝 .gitignore Configuration (20 points)\n\n"
		if has_proper_gitignore:
			md += "- ✅ **Proper .gitignore configuration** (+20 points)\n"
			md += "  - Prevents committing sensitive or unnecessary files\n"
			md += "  - Keeps repository clean and secure\n\n"
		else:
			md += "- ⚠️ **Issues with .gitignore** (0 points)\n"
			incomplete = any(a['type'] == 'incomplete_gitignore' for a in security_results['low'])
			missing = any(a['type'] == 'missing_gitignore' for a in security_results['low'])

			if missing:
				md += "  - **Missing .gitignore file**\n"
				md += "  - Create one with essential patterns\n"
			elif incomplete:
				md += "  - **Incomplete .gitignore**\n"
				for alert in security_results['low']:
					if alert['type'] == 'incomplete_gitignore':
						md += f"  - {alert['message']}\n"

			md += "  - Essential patterns to include:\n"
			md += "    - `.env` (environment variables)\n"
			md += "    - `*.log` (log files)\n"
			md += "    - `node_modules/` (Node.js)\n"
			md += "    - `__pycache__/` and `*.pyc` (Python)\n"
			md += "    - `.vscode/`, `.idea/` (IDE configs)\n\n"

		# No exposed secrets (+25 points)
		no_secrets = not any(
			a['type'] == 'secret_exposed'
			for a in security_results['critical'] + security_results['high']
		)
		md += "### 🔐 Secret Management (25 points)\n\n"
		if no_secrets:
			md += "- ✅ **No exposed secrets detected** (+25 points)\n"
			md += "  - Excellent! No hardcoded credentials found\n"
			md += "  - Continue using environment variables for sensitive data\n\n"
		else:
			md += "- 🚨 **CRITICAL: Exposed secrets detected** (0 points)\n"
			secret_count = len([a for a in security_results['critical'] + security_results['high'] if a['type'] == 'secret_exposed'])
			md += f"  - **{secret_count} secret(s) found in the codebase**\n"
			md += "  - **IMMEDIATE ACTION REQUIRED:**\n"
			md += "    1. Revoke/rotate all exposed credentials\n"
			md += "    2. Remove secrets from git history (`git filter-branch` or BFG Repo-Cleaner)\n"
			md += "    3. Use environment variables or secret management tools\n"
			md += "  - Best practices:\n"
			md += "    - Use `.env` files (and add to `.gitignore`)\n"
			md += "    - Use secret management: AWS Secrets Manager, HashiCorp Vault, Azure Key Vault\n"
			md += "    - Never commit API keys, passwords, or tokens\n\n"

		# Summary
		md += "### 📊 Best Practices Summary\n\n"
		md += "| Practice | Status | Points Earned |\n"
		md += "|----------|--------|---------------|\n"
		md += f"| Testing | {'✅ Present' if has_tests else '❌ Missing'} | {30 if has_tests else 0}/30 |\n"
		md += f"| CI/CD | {'✅ Configured' if has_ci else '❌ Not configured'} | {25 if has_ci else 0}/25 |\n"
		md += f"| .gitignore | {'✅ Proper' if has_proper_gitignore else '⚠️ Issues'} | {20 if has_proper_gitignore else 0}/20 |\n"
		md += f"| Secret Management | {'✅ Secure' if no_secrets else '🚨 Exposed'} | {25 if no_secrets else 0}/25 |\n"
		md += f"| **TOTAL** | | **{best_practices_score}/100** |\n\n"

		return md

	def _generate_recommendations(self, structure, security_results, dependencies, docker_results):
		"""Generate recommendations based on analysis."""
		recommendations = []

		# Tests
		if not structure.get('has_tests'):
			recommendations.append("**Add tests**: No test directory detected. Consider pytest (Python) or Jest (JS).")

		# CI/CD
		if not structure.get('has_ci'):
			recommendations.append("**Configure CI/CD**: Automate your tests with GitHub Actions or GitLab CI.")

		# Docker
		if not structure.get('has_docker'):
			recommendations.append("**Containerize the application**: Add a Dockerfile for easier deployment.")

		# Docker issues
		if docker_results.get('critical') or docker_results.get('high'):
			recommendations.append("**🚨 URGENT: Fix critical/high Docker security issues** before continuing.")

		# Security
		if security_results['total'] > 0:
			if security_results['critical'] or security_results['high']:
				recommendations.append("**🚨 URGENT: Fix critical/high security issues** before continuing.")

			if any(a['type'] == 'secret_exposed' for a in security_results['critical'] + security_results['high']):
				recommendations.append("**Revoke exposed secrets**: Immediately change detected tokens/passwords.")

		# Dependencies
		if dependencies:
			recommendations.append("**Update dependencies regularly**: Use `pip-audit` (Python) or `npm audit` (Node).")

		# Documentation
		if 'CONTRIBUTING.md' not in structure.get('important_files', []):
			recommendations.append("**Add CONTRIBUTING.md**: Guide potential contributors.")

		return recommendations