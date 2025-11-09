"""
Interactive modern HTML report generation.

FIXES:
- Fixed chart container overflow (proper CSS constraints)
- Enhanced .env file security alert display
- Improved responsive design for charts
"""

import os
from datetime import datetime
from pathlib import Path
from score_calculator import SecurityScoreCalculator

class HTMLReportGenerator:
	"""Generates HTML reports with modern design and interactivity."""

	def __init__(self, output_dir="output"):
		self.output_dir = output_dir
		Path(output_dir).mkdir(exist_ok=True)
		self.score_calculator = SecurityScoreCalculator()

	def generate_html(self, owner, repo, repo_info, languages,
					contributors, structure, dependencies, security_results, docker_results):
		timestamp = datetime.now().strftime("%Y-%m-%d")
		filename = f"{repo}-{timestamp}.html"
		filepath = os.path.join(self.output_dir, filename)

		html_content = self._build_html(
			owner, repo, repo_info, languages, contributors,
			structure, dependencies, security_results, docker_results
		)

		with open(filepath, 'w', encoding='utf-8') as f:
			f.write(html_content)

		return filepath

	def _generate_dependencies_section(self, dependencies):
		"""Generate Dependencies section for HTML."""
		if not dependencies or all(not deps for deps in dependencies.values()):
			return ""

		html = """
		<div class="section">
			<div class="section-title">📦 Dependencies</div>
		"""

		for dep_type, deps in dependencies.items():
			if not deps:
				continue

			type_title = dep_type.capitalize()

			html += f"""
			<div style="margin-bottom: 2rem;">
				<h3 style="color: var(--accent-blue); font-size: 1.2rem; margin-bottom: 1rem;">
					{type_title}
				</h3>
				<div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 0.75rem;">
			"""

			for dep in deps:
				html += f"""
					<div style="background: var(--bg-tertiary); padding: 0.75rem 1rem; border-radius: 8px; border: 1px solid var(--border); font-family: 'SF Mono', Monaco, monospace; font-size: 0.9rem; color: var(--text-primary);">
						<code style="color: var(--accent-purple);">{dep}</code>
					</div>
				"""

			html += """
				</div>
			</div>
			"""

		html += """
		</div>
		"""

		return html

	def _generate_best_practices_section(self, structure, security_results, score_data):
		"""Generate best practices section with detailed breakdown."""

		best_practices_score = score_data['best_practices_score']

		has_tests = structure.get('has_tests')
		has_ci = structure.get('has_ci')
		has_proper_gitignore = not any(
			a['type'] in ['incomplete_gitignore', 'missing_gitignore']
			for a in security_results['low']
		)
		no_secrets = not any(
			a['type'] == 'secret_exposed'
			for a in security_results['critical'] + security_results['high']
		)

		test_score = 30 if has_tests else 0
		ci_score = 25 if has_ci else 0
		gitignore_score = 20 if has_proper_gitignore else 0
		secrets_score = 25 if no_secrets else 0

		html = f"""
		<div class="section">
			<div class="section-title">✨ Best Practices</div>

			<div class="security-score" style="padding: 2rem 0;">
				<div style="text-align: center; margin-bottom: 2rem;">
					<div style="font-size: 3rem; font-weight: 700; color: {'var(--accent-green)' if best_practices_score >= 75 else 'var(--accent-yellow)' if best_practices_score >= 50 else 'var(--accent-red)'};">
						{best_practices_score}/100
					</div>
					<div style="color: var(--text-secondary); margin-top: 0.5rem;">
						Best Practices Score
					</div>
				</div>

				<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1.5rem; margin-top: 2rem;">

					<div class="info-item" style="border-left: 4px solid {'var(--accent-green)' if has_tests else 'var(--accent-red)'};">
						<div style="display: flex; align-items: center; gap: 0.75rem; margin-bottom: 1rem;">
							<div style="font-size: 2rem;">🧪</div>
							<div>
								<div style="font-weight: 600; font-size: 1.1rem;">Testing</div>
								<div style="color: var(--text-secondary); font-size: 0.9rem;">{test_score}/30 points</div>
							</div>
						</div>
						<div style="color: var(--text-secondary); font-size: 0.95rem; line-height: 1.5;">
							{'✅ Test directory detected. Great job maintaining code quality!' if has_tests else '❌ No test directory found. Consider adding tests with pytest (Python) or Jest (JavaScript).'}
						</div>
					</div>

					<div class="info-item" style="border-left: 4px solid {'var(--accent-green)' if has_ci else 'var(--accent-red)'};">
						<div style="display: flex; align-items: center; gap: 0.75rem; margin-bottom: 1rem;">
							<div style="font-size: 2rem;">🔄</div>
							<div>
								<div style="font-weight: 600; font-size: 1.1rem;">CI/CD</div>
								<div style="color: var(--text-secondary); font-size: 0.9rem;">{ci_score}/25 points</div>
							</div>
						</div>
						<div style="color: var(--text-secondary); font-size: 0.95rem; line-height: 1.5;">
							{'✅ CI/CD configuration detected. Automated workflows are active!' if has_ci else '❌ No CI/CD found. Set up GitHub Actions or GitLab CI for automated testing.'}
						</div>
					</div>

					<div class="info-item" style="border-left: 4px solid {'var(--accent-green)' if has_proper_gitignore else 'var(--accent-yellow)'};">
						<div style="display: flex; align-items: center; gap: 0.75rem; margin-bottom: 1rem;">
							<div style="font-size: 2rem;">📝</div>
							<div>
								<div style="font-weight: 600; font-size: 1.1rem;">.gitignore</div>
								<div style="color: var(--text-secondary); font-size: 0.9rem;">{gitignore_score}/20 points</div>
							</div>
						</div>
						<div style="color: var(--text-secondary); font-size: 0.95rem; line-height: 1.5;">
							{'✅ Proper .gitignore configuration. Repository is clean!' if has_proper_gitignore else '⚠️ Issues with .gitignore. Add patterns for .env, *.log, node_modules/, etc.'}
						</div>
					</div>

					<div class="info-item" style="border-left: 4px solid {'var(--accent-green)' if no_secrets else 'var(--accent-red)'};">
						<div style="display: flex; align-items: center; gap: 0.75rem; margin-bottom: 1rem;">
							<div style="font-size: 2rem;">🔐</div>
							<div>
								<div style="font-weight: 600; font-size: 1.1rem;">Secret Management</div>
								<div style="color: var(--text-secondary); font-size: 0.9rem;">{secrets_score}/25 points</div>
							</div>
						</div>
						<div style="color: var(--text-secondary); font-size: 0.95rem; line-height: 1.5;">
							{'✅ No exposed secrets detected. Excellent security!' if no_secrets else '🚨 CRITICAL: Secrets exposed! Immediately revoke credentials and use environment variables.'}
						</div>
					</div>

				</div>

				<div style="margin-top: 2.5rem; background: var(--bg-tertiary); padding: 2rem; border-radius: 12px;">
					<div style="font-weight: 600; font-size: 1.2rem; margin-bottom: 1rem; display: flex; align-items: center; gap: 0.5rem;">
						<span>💡</span> Recommendations
					</div>
					<div style="display: grid; gap: 1rem;">
		"""

		if not has_tests:
			html += """
						<div style="padding: 1rem; background: var(--bg-secondary); border-radius: 8px; border-left: 3px solid var(--accent-yellow);">
							<div style="font-weight: 600; margin-bottom: 0.5rem;">Add automated testing</div>
							<div style="color: var(--text-secondary); font-size: 0.9rem; line-height: 1.5;">
								Create a <code class="code">tests/</code> directory and write unit tests. This improves code quality and catches bugs early.
								<br><strong>Quick start:</strong> Python → pytest, JavaScript → Jest, Go → built-in testing
							</div>
						</div>
			"""

		if not has_ci:
			html += """
						<div style="padding: 1rem; background: var(--bg-secondary); border-radius: 8px; border-left: 3px solid var(--accent-yellow);">
							<div style="font-weight: 600; margin-bottom: 0.5rem;">Set up CI/CD pipeline</div>
							<div style="color: var(--text-secondary); font-size: 0.9rem; line-height: 1.5;">
								Automate testing, linting, and deployments with GitHub Actions (<code class="code">.github/workflows/</code>) or GitLab CI (<code class="code">.gitlab-ci.yml</code>).
								<br><strong>Benefits:</strong> Automatic code quality checks, faster deployments
							</div>
						</div>
			"""

		if not has_proper_gitignore:
			html += """
						<div style="padding: 1rem; background: var(--bg-secondary); border-radius: 8px; border-left: 3px solid var(--accent-yellow);">
							<div style="font-weight: 600; margin-bottom: 0.5rem;">Fix .gitignore configuration</div>
							<div style="color: var(--text-secondary); font-size: 0.9rem; line-height: 1.5;">
								Add essential patterns: <code class="code">.env</code>, <code class="code">*.log</code>, <code class="code">node_modules/</code>, <code class="code">__pycache__/</code>, <code class="code">*.pyc</code>
								<br><strong>Why:</strong> Prevents committing sensitive files and reduces repository size
							</div>
						</div>
			"""

		if not no_secrets:
			secret_count = len([a for a in security_results['critical'] + security_results['high'] if a['type'] == 'secret_exposed'])
			html += f"""
						<div style="padding: 1rem; background: rgba(245, 153, 141, 0.1); border-radius: 8px; border-left: 3px solid var(--accent-red);">
							<div style="font-weight: 600; margin-bottom: 0.5rem; color: var(--accent-red);">🚨 URGENT: Remove exposed secrets</div>
							<div style="color: var(--text-secondary); font-size: 0.9rem; line-height: 1.5;">
								<strong>{secret_count} secret(s) detected</strong> in your codebase. Take immediate action:
								<br>1. Revoke/rotate all exposed credentials
								<br>2. Remove from git history (use BFG Repo-Cleaner)
								<br>3. Use environment variables or secret managers (AWS Secrets Manager, HashiCorp Vault)
							</div>
						</div>
			"""

		if has_tests and has_ci and has_proper_gitignore and no_secrets:
			html += """
						<div style="padding: 1.5rem; background: rgba(125, 211, 176, 0.1); border-radius: 8px; text-align: center; border: 2px solid var(--accent-green);">
							<div style="font-size: 2.5rem; margin-bottom: 0.5rem;">🎉</div>
							<div style="font-weight: 600; color: var(--accent-green); font-size: 1.1rem;">
								Perfect! All best practices followed
							</div>
							<div style="color: var(--text-secondary); margin-top: 0.5rem; font-size: 0.9rem;">
								Your project demonstrates excellent software engineering practices
							</div>
						</div>
			"""

		html += """
					</div>
				</div>
			</div>
		</div>
		"""

		return html

	def _generate_docker_section(self, docker_results):
		"""Generate Docker configuration section."""
		if not docker_results['dockerfiles'] and not docker_results['compose_files']:
			return ""

		files_html = f"""
		<div style="margin-bottom: 1.5rem;">
			<p style="color: var(--text-secondary); margin-bottom: 0.5rem;">
				📄 {len(docker_results['dockerfiles'])} Dockerfile(s),
				{len(docker_results['compose_files'])} docker-compose file(s)
			</p>
		</div>
		"""

		if docker_results['total'] == 0:
			return f"""
			<div class="section">
				<div class="section-title">🐳 Docker Configuration</div>
				{files_html}
				<div style="text-align: center; padding: 2rem;">
					<div style="font-size: 4rem; margin-bottom: 1rem;">✅</div>
					<p style="font-size: 1.1rem; color: var(--accent-green);">
						Docker configuration looks good!
					</p>
				</div>
			</div>
			"""

		filters_html = f"""
		<div class="filter-buttons">
			<button class="filter-btn active" onclick="filterDockerAlerts('all')">
				All ({docker_results['total']})
			</button>
			<button class="filter-btn" onclick="filterDockerAlerts('critical')">
				🔴 Critical ({len(docker_results['critical'])})
			</button>
			<button class="filter-btn" onclick="filterDockerAlerts('high')">
				🟠 High ({len(docker_results['high'])})
			</button>
			<button class="filter-btn" onclick="filterDockerAlerts('medium')">
				🟡 Medium ({len(docker_results['medium'])})
			</button>
			<button class="filter-btn" onclick="filterDockerAlerts('low')">
				🔵 Low ({len(docker_results['low'])})
			</button>
			<button class="filter-btn" onclick="filterDockerAlerts('info')">
				ℹ️ Info ({len(docker_results.get('info', []))})
			</button>
		</div>
		"""

		alerts_html = ""
		severity_icons = {
			"critical": "🔴",
			"high": "🟠",
			"medium": "🟡",
			"low": "🔵",
			"info": "ℹ️"
		}

		for severity in ["critical", "high", "medium", "low", "info"]:
			for alert in docker_results.get(severity, []):
				icon = severity_icons[severity]

				file_info = alert['file']
				if alert.get('line', 0) > 0:
					file_info += f":{alert['line']}"

				recommendation_html = ""
				if 'recommendation' in alert:
					recommendation_html = f"<div style='margin-top: 0.5rem; color: var(--text-secondary);'>💡 {alert['recommendation']}</div>"

				alerts_html += f"""
				<div class="alert alert-{severity} docker-alert" data-severity="{severity}">
					<div class="alert-icon">{icon}</div>
					<div class="alert-content">
						<div class="alert-title">{alert['message']}</div>
						<div class="alert-details">
							<span class='code'>{file_info}</span>
							{recommendation_html}
						</div>
					</div>
				</div>
				"""

		return f"""
		<div class="section">
			<div class="section-title">🐳 Docker Configuration ({docker_results['total']} issues)</div>
			{files_html}
			{filters_html}
			<div class="alerts-container">
				{alerts_html}
			</div>
		</div>
		"""

	def _generate_security_section(self, security_results):
		"""Generate security section with alerts. ENHANCED: Better .env file display."""
		total = security_results['total']

		if total == 0:
			return """
			<div class="section">
				<div class="section-title">🔒 Security Alerts</div>
				<div style="text-align: center; padding: 3rem;">
					<div style="font-size: 5rem; margin-bottom: 1rem;">✅</div>
					<p style="font-size: 1.2rem; color: var(--accent-green);">
						No security issues detected!
					</p>
				</div>
			</div>
			"""

		filters_html = f"""
		<div class="filter-buttons">
			<button class="filter-btn active" onclick="filterSecurityAlerts('all')">
				All ({total})
			</button>
			<button class="filter-btn" onclick="filterSecurityAlerts('critical')">
				🔴 Critical ({len(security_results['critical'])})
			</button>
			<button class="filter-btn" onclick="filterSecurityAlerts('high')">
				🟠 High ({len(security_results['high'])})
			</button>
			<button class="filter-btn" onclick="filterSecurityAlerts('medium')">
				🟡 Medium ({len(security_results['medium'])})
			</button>
			<button class="filter-btn" onclick="filterSecurityAlerts('low')">
				🔵 Low ({len(security_results['low'])})
			</button>
		</div>
		"""

		alerts_html = ""
		severity_icons = {
			"critical": "🔴",
			"high": "🟠",
			"medium": "🟡",
			"low": "🔵"
		}

		for severity in ["critical", "high", "medium", "low"]:
			for alert in security_results.get(severity, []):
				icon = severity_icons[severity]

				if alert["type"] == "secret_exposed":
					title = f"{alert['secret_type'].replace('_', ' ').title()} detected"
					details = f"<span class='code'>{alert['file']}:{alert['line']}</span><br>{alert['preview'][:100]}..."
				elif alert["type"] == "sensitive_file":
					title = f"Sensitive file: {alert['file']}"
					details = alert['message']
					# ENHANCED: Add recommendation if present
					if 'recommendation' in alert:
						details += f"<br><div style='margin-top: 0.5rem; padding: 0.75rem; background: var(--bg-secondary); border-radius: 6px; border-left: 3px solid var(--accent-yellow);'><strong>💡 Best Practice:</strong> {alert['recommendation']}</div>"
				elif alert["type"] == "outdated_dependency":
					title = f"Outdated dependency: {alert['package']}"
					details = f"Current version: {alert['current_version']} → Recommended: {alert['min_safe_version']}"
				else:
					title = alert.get('message', 'Alert')
					details = alert.get('file', '')

				alerts_html += f"""
				<div class="alert alert-{severity} security-alert" data-severity="{severity}">
					<div class="alert-icon">{icon}</div>
					<div class="alert-content">
						<div class="alert-title">{title}</div>
						<div class="alert-details">{details}</div>
					</div>
				</div>
				"""

		return f"""
		<div class="section">
			<div class="section-title">⚠️ Security Alerts ({total})</div>
			{filters_html}
			<div class="alerts-container">
				{alerts_html}
			</div>
		</div>
		"""

	def _generate_languages_chart(self, languages_data):
		"""Generate Chart.js script for languages."""
		if not languages_data:
			return ""

		labels = str(languages_data['labels'])
		data = str(languages_data['data'])

		colors = [
			'#7c9ff5', '#b794f6', '#7dd3b0', '#f5d679',
			'#f5998d', '#f5b57c'
		]

		return f"""
		const languagesCtx = document.getElementById('languagesChart');
		if (languagesCtx) {{
			new Chart(languagesCtx, {{
				type: 'doughnut',
				data: {{
					labels: {labels},
					datasets: [{{
						data: {data},
						backgroundColor: {colors},
						borderWidth: 1,
						borderColor: '#363b52',
						hoverOffset: 8
					}}]
				}},
				options: {{
					responsive: true,
					maintainAspectRatio: true,
					aspectRatio: 2,
					plugins: {{
						legend: {{
							position: 'right',
							labels: {{
								padding: 15,
								font: {{ size: 13 }},
								usePointStyle: true,
								pointStyle: 'circle',
								boxWidth: 8
							}}
						}},
						tooltip: {{
							backgroundColor: '#2a2f45',
							titleColor: '#e8eaf0',
							bodyColor: '#a3a8c3',
							borderColor: '#363b52',
							borderWidth: 1,
							padding: 12,
							cornerRadius: 8
						}}
					}}
				}}
			}});
		}}
		"""

	def _generate_file_types_chart(self, file_types_data):
		"""Generate Chart.js script for file types."""
		if not file_types_data:
			return ""

		labels = str(file_types_data['labels'])
		data = str(file_types_data['data'])

		return f"""
		const fileTypesCtx = document.getElementById('fileTypesChart');
		if (fileTypesCtx) {{
			new Chart(fileTypesCtx, {{
				type: 'bar',
				data: {{
					labels: {labels},
					datasets: [{{
						label: 'File count',
						data: {data},
						backgroundColor: '#7c9ff5',
						borderRadius: 8,
						maxBarThickness: 60
					}}]
				}},
				options: {{
					responsive: true,
					maintainAspectRatio: true,
					aspectRatio: 2,
					plugins: {{
						legend: {{ display: false }},
						tooltip: {{
							backgroundColor: '#2a2f45',
							padding: 12,
							cornerRadius: 8
						}}
					}},
					scales: {{
						x: {{ grid: {{ display: false }} }},
						y: {{
							beginAtZero: true,
							grid: {{ color: '#363b52' }},
							ticks: {{ precision: 0 }}
						}}
					}}
				}}
			}});
		}}
		"""

	def _calculate_security_score(self, security_results, docker_results, structure, languages=None, contributors=None):
		has_github_data = bool(languages) or bool(contributors)
		score_data = self.score_calculator.calculate_unified_score(
			security_results, docker_results, structure, has_github_data
		)
		return score_data

	def _get_score_class(self, score):
		if score >= 90:
			return "score-excellent"
		elif score >= 75:
			return "score-good"
		elif score >= 60:
			return "score-warning"
		else:
			return "score-danger"

	def _prepare_languages_data(self, languages):
		if not languages:
			return None

		return {
			'labels': list(languages.keys())[:6],
			'data': list(languages.values())[:6]
		}

	def _prepare_file_types_data(self, structure):
		file_types = structure.get('file_types', {})
		if not file_types:
			return None

		top_types = dict(list(file_types.items())[:8])

		return {
			'labels': list(top_types.keys()),
			'data': list(top_types.values())
		}

	def _build_html(self, owner, repo, repo_info, languages,
					contributors, structure, dependencies, security_results, docker_results):
		"""Build complete HTML content."""

		score_data = self._calculate_security_score(
			security_results, docker_results, structure, languages, contributors)
		total_score = score_data['total_score']
		grade = score_data['grade']

		languages_data = self._prepare_languages_data(languages)
		file_types_data = self._prepare_file_types_data(structure)

		docker_section = self._generate_docker_section(docker_results)
		security_section = self._generate_security_section(security_results)
		best_practices_section = self._generate_best_practices_section(structure, security_results, score_data)

		# Generate dependencies section
		dependencies_section = self._generate_dependencies_section(dependencies)

		# Contributors section
		contributors_html = ""
		if contributors:
			medals = ["🥇", "🥈", "🥉", "4️⃣", "5️⃣"]
			for i, contrib in enumerate(contributors[:5]):
				medal = medals[i] if i < len(medals) else f"{i+1}️⃣"
				contributors_html += f"""
				<div class="contributor">
					<div class="contributor-rank">{medal}</div>
					<div class="contributor-name">
						<a href="https://github.com/{contrib['login']}" target="_blank">
							{contrib['login']}
						</a>
					</div>
					<div class="contributor-commits">{contrib['contributions']:,} commits</div>
				</div>
				"""

		contributors_section = f"""
		<div class="section">
			<div class="section-title">👥 Top Contributors</div>
			<div class="contributors-grid">
				{contributors_html}
			</div>
		</div>
		""" if contributors and len(contributors) > 0 else ""

		def safe_int_display(value, default="N/A"):
			return f"{value:,}" if isinstance(value, int) else default

		html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Report {owner}/{repo}</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.js"></script>
<style>
	* {{
		margin: 0;
		padding: 0;
		box-sizing: border-box;
	}}

	:root {{
		--bg-primary: #1a1d29;
		--bg-secondary: #22263a;
		--bg-tertiary: #2a2f45;
		--bg-card: #252938;

		--text-primary: #e8eaf0;
		--text-secondary: #a3a8c3;
		--text-muted: #6b7280;

		--accent-blue: #7c9ff5;
		--accent-purple: #b794f6;
		--accent-green: #7dd3b0;
		--accent-yellow: #f5d679;
		--accent-red: #f5998d;
		--accent-orange: #f5b57c;

		--border: #363b52;
		--shadow: rgba(0, 0, 0, 0.2);
	}}

	body {{
		font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Noto Sans', Helvetica, Arial, sans-serif;
		background: linear-gradient(135deg, var(--bg-primary) 0%, #1e2235 100%);
		color: var(--text-primary);
		line-height: 1.6;
		min-height: 100vh;
	}}

	.container {{
		max-width: 1400px;
		margin: 0 auto;
		padding: 2.5rem;
	}}

	header {{
		text-align: center;
		padding: 3rem 0 4rem;
		margin-bottom: 3rem;
	}}

	h1 {{
		font-size: 2.8rem;
		margin-bottom: 0.75rem;
		font-weight: 700;
		background: linear-gradient(120deg, var(--accent-blue), var(--accent-purple));
		-webkit-background-clip: text;
		-webkit-text-fill-color: transparent;
		background-clip: text;
		letter-spacing: -0.02em;
	}}

	.repo-url {{
		color: var(--text-secondary);
		text-decoration: none;
		font-size: 1.05rem;
		transition: color 0.2s ease;
		display: inline-block;
		margin-top: 0.5rem;
	}}

	.repo-url:hover {{
		color: var(--accent-blue);
	}}

	.timestamp {{
		color: var(--text-muted);
		font-size: 0.9rem;
		margin-top: 1rem;
	}}

	.stats-grid {{
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
		gap: 1.5rem;
		margin-bottom: 3rem;
	}}

	.stat-card {{
		background: var(--bg-card);
		padding: 2rem;
		border-radius: 16px;
		border: 1px solid var(--border);
		transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
		position: relative;
		overflow: hidden;
	}}

	.stat-card::before {{
		content: '';
		position: absolute;
		top: 0;
		left: 0;
		right: 0;
		height: 3px;
		background: linear-gradient(90deg, var(--accent-blue), var(--accent-purple));
		opacity: 0;
		transition: opacity 0.3s ease;
	}}

	.stat-card:hover {{
		transform: translateY(-4px);
		box-shadow: 0 12px 24px var(--shadow);
		border-color: var(--accent-blue);
	}}

	.stat-card:hover::before {{
		opacity: 1;
	}}

	.stat-icon {{
		font-size: 2.5rem;
		margin-bottom: 1rem;
		opacity: 0.9;
	}}

	.stat-value {{
		font-size: 2.5rem;
		font-weight: 700;
		color: var(--accent-blue);
		margin-bottom: 0.5rem;
		letter-spacing: -0.02em;
	}}

	.stat-label {{
		color: var(--text-secondary);
		font-size: 0.95rem;
		font-weight: 500;
	}}

	.section {{
		background: var(--bg-card);
		padding: 2.5rem;
		border-radius: 16px;
		border: 1px solid var(--border);
		margin-bottom: 2rem;
		box-shadow: 0 4px 6px var(--shadow);
	}}

	.section-title {{
		font-size: 1.75rem;
		margin-bottom: 2rem;
		display: flex;
		align-items: center;
		gap: 0.75rem;
		font-weight: 600;
		color: var(--text-primary);
	}}

	/* FIXED: Chart container with proper overflow constraints */
	.chart-container {{
		position: relative;
		width: 100%;
		max-width: 100%;
		height: auto;
		margin: 2rem auto;
		padding: 1rem;
		overflow: hidden; /* Prevent overflow */
	}}

	.chart-wrapper {{
		position: relative;
		width: 100%;
		max-width: 600px;
		margin: 0 auto;
		overflow: hidden; /* Prevent overflow */
	}}

	.chart-wrapper canvas {{
		width: 100% !important;
		height: auto !important;
		max-width: 100%; /* Constrain width */
	}}

	.security-score {{
		text-align: center;
		padding: 3rem 2rem;
	}}

	.score-circle {{
		width: 220px;
		height: 220px;
		margin: 0 auto 1.5rem;
		border-radius: 50%;
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		font-size: 3rem;
		font-weight: 700;
		position: relative;
		border: 8px solid var(--bg-secondary);
	}}

	.score-grade {{
		font-size: 4rem;
		font-weight: 800;
		margin-bottom: 0.25rem;
	}}

	.score-number {{
		font-size: 1.5rem;
		opacity: 0.9;
	}}

	.score-excellent {{
		background: linear-gradient(135deg, var(--accent-green), #6bc9a0);
		box-shadow: 0 8px 32px rgba(125, 211, 176, 0.3);
	}}

	.score-good {{
		background: linear-gradient(135deg, var(--accent-blue), #6b8ee5);
		box-shadow: 0 8px 32px rgba(124, 159, 245, 0.3);
	}}

	.score-warning {{
		background: linear-gradient(135deg, var(--accent-yellow), #e5c369);
		box-shadow: 0 8px 32px rgba(245, 214, 121, 0.3);
	}}

	.score-danger {{
		background: linear-gradient(135deg, var(--accent-red), #e5897d);
		box-shadow: 0 8px 32px rgba(245, 153, 141, 0.3);
	}}

	.score-description {{
		color: var(--text-secondary);
		font-size: 1.1rem;
		margin-top: 1rem;
	}}

	.score-breakdown {{
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
		gap: 1rem;
		margin-top: 2rem;
	}}

	.breakdown-item {{
		background: var(--bg-tertiary);
		padding: 1.5rem;
		border-radius: 12px;
		text-align: center;
	}}

	.breakdown-label {{
		color: var(--text-secondary);
		font-size: 0.9rem;
		margin-bottom: 0.5rem;
	}}

	.breakdown-value {{
		font-size: 2rem;
		font-weight: 700;
		color: var(--accent-blue);
	}}

	.alerts-container {{
		display: grid;
		gap: 1.25rem;
	}}

	.alert {{
		background: var(--bg-tertiary);
		padding: 1.5rem;
		border-radius: 12px;
		border-left: 4px solid;
		display: flex;
		align-items: start;
		gap: 1.25rem;
		transition: all 0.2s ease;
	}}

	.alert:hover {{
		transform: translateX(4px);
	}}

	.alert-critical {{
		border-color: var(--accent-red);
		background: linear-gradient(90deg, rgba(245, 153, 141, 0.08), var(--bg-tertiary));
	}}

	.alert-high {{
		border-color: var(--accent-orange);
		background: linear-gradient(90deg, rgba(245, 181, 124, 0.08), var(--bg-tertiary));
	}}

	.alert-medium {{
		border-color: var(--accent-yellow);
		background: linear-gradient(90deg, rgba(245, 214, 121, 0.08), var(--bg-tertiary));
	}}

	.alert-low {{
		border-color: var(--accent-blue);
		background: linear-gradient(90deg, rgba(124, 159, 245, 0.08), var(--bg-tertiary));
	}}

	.alert-info {{
		border-color: var(--accent-blue);
		background: linear-gradient(90deg, rgba(124, 159, 245, 0.05), var(--bg-tertiary));
	}}

	.alert-icon {{
		font-size: 1.75rem;
		flex-shrink: 0;
		line-height: 1;
	}}

	.alert-content {{
		flex: 1;
		min-width: 0;
		overflow-wrap: break-word;
	}}

	.alert-title {{
		font-weight: 600;
		margin-bottom: 0.5rem;
		font-size: 1.05rem;
		color: var(--text-primary);
		word-break: break-word;
	}}

	.alert-details {{
		color: var(--text-secondary);
		font-size: 0.95rem;
		line-height: 1.5;
		word-break: break-word;
		overflow-wrap: break-word;
	}}

	.code {{
		background: var(--bg-secondary);
		padding: 0.25rem 0.6rem;
		border-radius: 6px;
		font-family: 'SF Mono', 'Monaco', 'Courier New', monospace;
		font-size: 0.9rem;
		color: var(--accent-purple);
		border: 1px solid var(--border);
		word-break: break-all;
		display: inline-block;
		max-width: 100%;
	}}

	.badge {{
		display: inline-flex;
		align-items: center;
		gap: 0.4rem;
		padding: 0.5rem 1rem;
		border-radius: 8px;
		font-size: 0.9rem;
		font-weight: 600;
		margin: 0.25rem;
		transition: all 0.2s ease;
	}}

	.badge-success {{
		background: rgba(125, 211, 176, 0.15);
		color: var(--accent-green);
		border: 1px solid rgba(125, 211, 176, 0.3);
	}}

	.badge-danger {{
		background: rgba(245, 153, 141, 0.15);
		color: var(--accent-red);
		border: 1px solid rgba(245, 153, 141, 0.3);
	}}

	.contributors-grid {{
		display: grid;
		gap: 1rem;
	}}

	.contributor {{
		display: flex;
		align-items: center;
		gap: 1.25rem;
		background: var(--bg-tertiary);
		padding: 1.25rem;
		border-radius: 12px;
		transition: all 0.2s ease;
		border: 1px solid var(--border);
	}}

	.contributor:hover {{
		background: var(--bg-secondary);
		transform: translateX(4px);
	}}

	.contributor-rank {{
		font-size: 1.75rem;
		font-weight: 700;
		color: var(--accent-blue);
		min-width: 50px;
		text-align: center;
	}}

	.contributor-name {{
		flex: 1;
		font-weight: 600;
		font-size: 1.05rem;
	}}

	.contributor-name a {{
		color: var(--text-primary);
		text-decoration: none;
		transition: color 0.2s ease;
	}}

	.contributor-name a:hover {{
		color: var(--accent-blue);
	}}

	.contributor-commits {{
		color: var(--text-secondary);
		font-size: 0.95rem;
	}}

	.info-grid {{
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
		gap: 1.5rem;
		margin-top: 1.5rem;
	}}

	.info-item {{
		background: var(--bg-tertiary);
		padding: 1.5rem;
		border-radius: 12px;
		border: 1px solid var(--border);
	}}

	.info-label {{
		color: var(--text-secondary);
		font-size: 0.9rem;
		margin-bottom: 0.5rem;
	}}

	.info-value {{
		font-size: 1.75rem;
		font-weight: 700;
		color: var(--accent-blue);
	}}

	footer {{
		text-align: center;
		padding: 4rem 0 2rem;
		color: var(--text-muted);
		margin-top: 4rem;
		border-top: 1px solid var(--border);
	}}

	footer a {{
		color: var(--accent-blue);
		text-decoration: none;
		transition: color 0.2s ease;
	}}

	footer a:hover {{
		color: var(--accent-purple);
	}}

	.filter-buttons {{
		display: flex;
		gap: 0.75rem;
		margin-bottom: 1.5rem;
		flex-wrap: wrap;
	}}

	.filter-btn {{
		padding: 0.75rem 1.25rem;
		background: var(--bg-tertiary);
		border: 1px solid var(--border);
		border-radius: 10px;
		color: var(--text-primary);
		cursor: pointer;
		transition: all 0.2s ease;
		font-weight: 500;
		font-size: 0.95rem;
	}}

	.filter-btn:hover {{
		background: var(--accent-blue);
		border-color: var(--accent-blue);
		transform: translateY(-2px);
	}}

	.filter-btn.active {{
		background: var(--accent-blue);
		border-color: var(--accent-blue);
		box-shadow: 0 4px 12px rgba(124, 159, 245, 0.3);
	}}

	.hidden {{
		display: none !important;
	}}

	/* Mobile responsive - keep 2x2 grid */
	@media (max-width: 768px) {{
		.container {{
			padding: 1.5rem;
		}}

		h1 {{
			font-size: 2rem;
		}}

		/* Keep 2x2 grid on mobile */
		.stats-grid {{
			grid-template-columns: repeat(2, 1fr);
			gap: 1rem;
		}}

		.stat-card {{
			padding: 1.5rem 1rem;
		}}

		.stat-icon {{
			font-size: 2rem;
		}}

		.stat-value {{
			font-size: 2rem;
		}}

		.stat-label {{
			font-size: 0.85rem;
		}}

		.score-circle {{
			width: 180px;
			height: 180px;
		}}

		.score-grade {{
			font-size: 3rem;
		}}

		.score-number {{
			font-size: 1.2rem;
		}}

		.section {{
			padding: 1.5rem;
		}}

		.section-title {{
			font-size: 1.5rem;
			flex-wrap: wrap;
		}}

		.chart-container {{
			padding: 0.5rem;
		}}

		/* FIXED: Better chart responsiveness on mobile */
		.chart-wrapper {{
			max-width: 100%;
		}}

		.alert {{
			flex-direction: row;
			gap: 1rem;
			padding: 1rem;
		}}

		.alert-icon {{
			font-size: 1.5rem;
		}}

		.filter-buttons {{
			gap: 0.5rem;
		}}

		.filter-btn {{
			padding: 0.6rem 1rem;
			font-size: 0.85rem;
		}}

		.contributor {{
			flex-wrap: wrap;
			gap: 1rem;
			padding: 1rem;
		}}

		.contributor-rank {{
			min-width: auto;
		}}
	}}

	/* Tablet responsive - same 2x2 */
	@media (min-width: 769px) and (max-width: 1024px) {{
		.stats-grid {{
			grid-template-columns: repeat(2, 1fr);
		}}
	}}
</style>
</head>
<body>
<div class="container">
	<header>
		<h1>📊 Analysis: {owner}/{repo}</h1>
		{f'<div style="color: var(--text-secondary); font-size: 1.05rem; margin-top: 0.75rem;">Local path: <code style="background: var(--bg-tertiary); padding: 0.25rem 0.5rem; border-radius: 4px;">{repo_info["clone_url"]}</code></div>' if owner == 'local' else f'<a href="https://github.com/{owner}/{repo}" class="repo-url" target="_blank">github.com/{owner}/{repo} →</a>'}
		<p class="timestamp">
			Generated on {datetime.now().strftime('%m/%d/%Y at %H:%M')}
		</p>
	</header>

	<!-- Main stats -->
	<div class="stats-grid">
		<div class="stat-card">
			<div class="stat-icon">⭐</div>
			<div class="stat-value">{safe_int_display(repo_info.get('stars'))}</div>
			<div class="stat-label">Stars</div>
		</div>
		<div class="stat-card">
			<div class="stat-icon">🔱</div>
			<div class="stat-value">{safe_int_display(repo_info.get('forks'))}</div>
			<div class="stat-label">Forks</div>
		</div>
		<div class="stat-card">
			<div class="stat-icon">📂</div>
			<div class="stat-value">{structure.get('total_files', 0):,}</div>
			<div class="stat-label">Files</div>
		</div>
		<div class="stat-card">
			<div class="stat-icon">🛠</div>
			<div class="stat-value">{safe_int_display(repo_info.get('open_issues'))}</div>
			<div class="stat-label">Open issues</div>
		</div>
	</div>

	<!-- Security Score -->
	<div class="section">
		<div class="section-title">🔒 Security Score</div>
		<div class="security-score">
			<div class="score-circle {self._get_score_class(total_score)}">
				<div class="score-grade">{grade}</div>
				<div class="score-number">{total_score}/100</div>
			</div>
			<p class="score-description">
				{score_data['description']}
			</p>
			{f'''
			<div style="margin-top: 1.5rem; padding: 1rem; background: rgba(124, 159, 245, 0.1); border-radius: 8px; border-left: 3px solid var(--accent-blue);">
				<div style="font-size: 0.95rem; color: var(--text-secondary);">
					<strong>ℹ️ Local Analysis Mode</strong><br>
					This project was analyzed locally. GitHub metadata (stars, forks, contributors, languages) are not available.
				</div>
			</div>
			''' if score_data.get('is_local_analysis') else ''}
			<div class="score-breakdown">
				<div class="breakdown-item">
					<div class="breakdown-label">Security (50%)</div>
					<div class="breakdown-value">{score_data['security_score']}</div>
				</div>
				<div class="breakdown-item">
					<div class="breakdown-label">Docker (30%)</div>
					<div class="breakdown-value">{score_data['docker_score']}</div>
				</div>
				<div class="breakdown-item">
					<div class="breakdown-label">Best Practices (20%)</div>
					<div class="breakdown-value">{score_data['best_practices_score']}</div>
				</div>
			</div>
		</div>
	</div>

	<!-- Languages (GitHub only) -->
	{f'''
	<div class="section">
		<div class="section-title">💻 Languages</div>
		<div class="chart-container"><div class="chart-wrapper"><canvas id="languagesChart"></canvas></div></div>
	</div>
	''' if languages and len(languages) > 0 else ''}

	<!-- Contributors (GitHub only) -->
	{contributors_section}

	<!-- Structure -->
	<div class="section">
		<div class="section-title">📁 Project Structure</div>
		<div style="display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 1.5rem;">
			<span class="badge {'badge-success' if structure.get('has_tests') else 'badge-danger'}">
				{'✅' if structure.get('has_tests') else '❌'} Tests
			</span>
			<span class="badge {'badge-success' if structure.get('has_ci') else 'badge-danger'}">
				{'✅' if structure.get('has_ci') else '❌'} CI/CD
			</span>
			<span class="badge {'badge-success' if structure.get('has_docker') else 'badge-danger'}">
				{'✅' if structure.get('has_docker') else '❌'} Docker
			</span>
		</div>
		<div class="info-grid">
			<div class="info-item">
				<p class="info-label">Directories</p>
				<p class="info-value">{structure.get('total_dirs', 0):,}</p>
			</div>
			<div class="info-item">
				<p class="info-label">Max depth</p>
				<p class="info-value">{structure.get('max_depth', 0)}</p>
			</div>
		</div>
		{('<div class="chart-container"><div class="chart-wrapper"><canvas id="fileTypesChart"></canvas></div></div>' if file_types_data else '')}
	</div>

	<!-- Best Practices -->
	{best_practices_section}

	<!-- Docker Configuration -->
	{docker_section}

	<!-- Dependencies Section -->
	{dependencies_section}

	<!-- Security Alerts -->
	{security_section}

	<footer>
		<p style="font-size: 1.1rem; margin-bottom: 0.5rem;">
			<strong>GitHub Repository Analyzer</strong>
		</p>
		<p style="font-size: 0.9rem;">
			<a href="https://github.com/TuroTheReal/repo-analyzer">
				github.com/TuroTheReal/repo-analyzer
			</a>
		</p>
	</footer>
</div>

<script>
	Chart.defaults.color = '#a3a8c3';
	Chart.defaults.borderColor = '#363b52';

	{self._generate_languages_chart(languages_data) if languages_data else ''}
	{self._generate_file_types_chart(file_types_data) if file_types_data else ''}

	function filterSecurityAlerts(severity) {{
		const buttons = document.querySelectorAll('.filter-buttons .filter-btn');
		const alerts = document.querySelectorAll('.security-alert');

		buttons.forEach(btn => btn.classList.remove('active'));
		event.target.classList.add('active');

		if (severity === 'all') {{
			alerts.forEach(alert => alert.classList.remove('hidden'));
		}} else {{
			alerts.forEach(alert => {{
				if (alert.dataset.severity === severity) {{
					alert.classList.remove('hidden');
				}} else {{
					alert.classList.add('hidden');
				}}
			}});
		}}
	}}

	function filterDockerAlerts(severity) {{
		const buttons = document.querySelectorAll('.filter-buttons .filter-btn');
		const alerts = document.querySelectorAll('.docker-alert');

		buttons.forEach(btn => btn.classList.remove('active'));
		event.target.classList.add('active');

		if (severity === 'all') {{
			alerts.forEach(alert => alert.classList.remove('hidden'));
		}} else {{
			alerts.forEach(alert => {{
				if (alert.dataset.severity === severity) {{
					alert.classList.remove('hidden');
				}} else {{
					alert.classList.add('hidden');
				}}
			}});
		}}
	}}
</script>
</body>
</html>"""

		return html