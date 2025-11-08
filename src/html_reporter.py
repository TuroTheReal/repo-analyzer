"""
Interactive modern HTML report generation.
"""

import os
from datetime import datetime
from pathlib import Path

class HTMLReportGenerator:
	"""Generates HTML reports with modern design and interactivity."""

	def __init__(self, output_dir="output"):
		"""
		Args:
			output_dir: Directory to save reports
		"""
		self.output_dir = output_dir
		Path(output_dir).mkdir(exist_ok=True)

	def generate_html(self, owner, repo, repo_info, languages,
					contributors, structure, dependencies, security_results, docker_results):
		"""
		Generate complete interactive HTML report.

		Returns:
			str: Path to generated file
		"""
		timestamp = datetime.now().strftime("%Y-%m-%d")
		filename = f"{repo}-{timestamp}.html"
		filepath = os.path.join(self.output_dir, filename)

		# Build HTML
		html_content = self._build_html(
			owner, repo, repo_info, languages, contributors,
			structure, dependencies, security_results, docker_results
		)

		# Write file
		with open(filepath, 'w', encoding='utf-8') as f:
			f.write(html_content)

		return filepath

	def _calculate_security_score(self, security_results):
		"""Calculate security score out of 100."""
		total = security_results['total']

		if total == 0:
			return 100

		# Penalties by severity
		score = 100
		score -= len(security_results['critical']) * 20
		score -= len(security_results['high']) * 10
		score -= len(security_results['medium']) * 5
		score -= len(security_results['low']) * 2

		return max(0, score)

	def _get_score_class(self, score):
		"""Return CSS class based on score."""
		if score >= 90:
			return "score-excellent"
		elif score >= 70:
			return "score-good"
		elif score >= 50:
			return "score-warning"
		else:
			return "score-danger"

	def _get_score_description(self, score):
		"""Return score description."""
		if score >= 90:
			return "Excellent! Very few issues detected."
		elif score >= 70:
			return "Good. Some improvements possible."
		elif score >= 50:
			return "Average. Several issues to fix."
		else:
			return "Warning! Important security issues."

	def _prepare_languages_data(self, languages):
		"""Prepare data for languages chart."""
		if not languages:
			return None

		return {
			'labels': list(languages.keys())[:6],
			'data': list(languages.values())[:6]
		}

	def _prepare_file_types_data(self, structure):
		"""Prepare data for file types chart."""
		file_types = structure.get('file_types', {})
		if not file_types:
			return None

		# Top 8 file types
		top_types = dict(list(file_types.items())[:8])

		return {
			'labels': list(top_types.keys()),
			'data': list(top_types.values())
		}

	def _generate_docker_section(self, docker_results):
		"""Generate Docker configuration section."""
		if not docker_results['dockerfiles'] and not docker_results['compose_files']:
			return ""

		# Files summary
		files_html = f"""
		<div style="margin-bottom: 1.5rem;">
			<p style="color: var(--text-secondary); margin-bottom: 0.5rem;">
				📄 {len(docker_results['dockerfiles'])} Dockerfile(s),
				{len(docker_results['compose_files'])} docker-compose file(s)
			</p>
		</div>
		"""

		# If no issues
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

		# With issues - filter buttons
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

		# Generate alerts
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
		"""Generate security section with alerts."""
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

		# Filter buttons
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

		# Generate alerts
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


	def _build_html(self, owner, repo, repo_info, languages,
				contributors, structure, dependencies, security_results, docker_results):
		"""Build complete HTML content."""

		# Calculate security score
		security_score = self._calculate_security_score(security_results)

		# Prepare data for charts
		languages_data = self._prepare_languages_data(languages)
		file_types_data = self._prepare_file_types_data(structure)

		# Generate sections
		docker_section = self._generate_docker_section(docker_results)
		security_section = self._generate_security_section(security_results)

		# Build contributors section
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
		""" if contributors else ""

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

		.chart-container {{
			position: relative;
			width: 100%;
			max-width: 100%;
			height: auto;
			margin: 2rem auto;
			padding: 1rem;
		}}

		.chart-wrapper {{
			position: relative;
			width: 100%;
			max-width: 600px;
			margin: 0 auto;
		}}

		.chart-wrapper canvas {{
			width: 100% !important;
			height: auto !important;
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
			align-items: center;
			justify-content: center;
			font-size: 3.5rem;
			font-weight: 700;
			position: relative;
			border: 8px solid var(--bg-secondary);
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
		}}

		.alert-title {{
			font-weight: 600;
			margin-bottom: 0.5rem;
			font-size: 1.05rem;
			color: var(--text-primary);
		}}

		.alert-details {{
			color: var(--text-secondary);
			font-size: 0.95rem;
			line-height: 1.5;
		}}

		.code {{
			background: var(--bg-secondary);
			padding: 0.25rem 0.6rem;
			border-radius: 6px;
			font-family: 'SF Mono', 'Monaco', 'Courier New', monospace;
			font-size: 0.9rem;
			color: var(--accent-purple);
			border: 1px solid var(--border);
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

		@media (max-width: 768px) {{
			.container {{
				padding: 1.5rem;
			}}

			h1 {{
				font-size: 2rem;
			}}

			.stats-grid {{
				grid-template-columns: 1fr;
			}}

			.score-circle {{
				width: 180px;
				height: 180px;
				font-size: 3rem;
			}}

			.section {{
				padding: 1.5rem;
			}}

			.chart-container {{
				height: 280px;
			}}
		}}
	</style>
	</head>
	<body>
	<div class="container">
		<header>
			<h1>📊 Analysis: {owner}/{repo}</h1>
			<a href="https://github.com/{owner}/{repo}" class="repo-url" target="_blank">
				github.com/{owner}/{repo} →
			</a>
			<p class="timestamp">
				Generated on {datetime.now().strftime('%m/%d/%Y at %H:%M')}
			</p>
		</header>

		<!-- Main stats -->
		<div class="stats-grid">
			<div class="stat-card">
				<div class="stat-icon">⭐</div>
				<div class="stat-value">{repo_info['stars']:,}</div>
				<div class="stat-label">Stars</div>
			</div>
			<div class="stat-card">
				<div class="stat-icon">🍴</div>
				<div class="stat-value">{repo_info['forks']:,}</div>
				<div class="stat-label">Forks</div>
			</div>
			<div class="stat-card">
				<div class="stat-icon">📂</div>
				<div class="stat-value">{structure.get('total_files', 0):,}</div>
				<div class="stat-label">Files</div>
			</div>
			<div class="stat-card">
				<div class="stat-icon">🐛</div>
				<div class="stat-value">{repo_info['open_issues']}</div>
				<div class="stat-label">Open issues</div>
			</div>
		</div>

		<!-- Security Score -->
		<div class="section">
			<div class="section-title">🔒 Security Score</div>
			<div class="security-score">
				<div class="score-circle {self._get_score_class(security_score)}">
					{security_score}/100
				</div>
				<p class="score-description">
					{self._get_score_description(security_score)}
				</p>
			</div>
		</div>

		<!-- Languages -->
		{'<div class="section"><div class="section-title">💻 Languages</div><div class="chart-container"><div class="chart-wrapper"><canvas id="languagesChart"></canvas></div></div></div>' if languages else ''}

		<!-- Contributors -->
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

		<!-- Docker Configuration -->
		{docker_section}

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
		// Chart.js config for dark theme
		Chart.defaults.color = '#a3a8c3';
		Chart.defaults.borderColor = '#363b52';

		// Languages chart
		{self._generate_languages_chart(languages_data) if languages_data else ''}

		// File types chart
		{self._generate_file_types_chart(file_types_data) if file_types_data else ''}

		// Filter functions for security alerts
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

		// Filter functions for Docker alerts
		function filterDockerAlerts(severity) {{
			const alerts = document.querySelectorAll('.docker-alert');

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
