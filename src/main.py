#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
GitHub Repository Analyzer - Main Entry Point

IMPROVEMENTS:
- Better error handling
- Enhanced statistics display
- Improved user feedback
- Integration with Trivy and dependency auditors
- Merged vulnerability results
"""

import sys
import os
import re
from rich.console import Console
from rich.table import Table
from github_api import GitHubAPI
from analyzer import RepoAnalyzer
from security import SecurityScanner
from docker_scanner import DockerScanner
from trivy_api import TrivyScanner
from dependency_scanner import DependencyScanner
from reporter import ReportGenerator

console = Console()

def parse_github_url(url):
	"""Extract owner and repo from GitHub URL."""
	url = url.strip().replace("https://", "").replace("http://", "")
	url = url.replace("git@github.com:", "github.com/")
	parts = url.split("/")

	if len(parts) < 3 or parts[0] != "github.com":
		raise ValueError("❌ Invalid URL. Format: github.com/owner/repo")

	owner = parts[1]
	repo = parts[2].replace(".git", "")

	if not owner or not repo:
		raise ValueError("❌ Incomplete URL. Need both owner AND repo")

	return owner, repo

def is_github_url(input_str):
	"""Detect if input is a GitHub URL."""
	patterns = [
		r'github\.com/',
		r'^https?://',
		r'git@github\.com:'
	]
	return any(re.search(pattern, input_str) for pattern in patterns)

def is_local_path(input_str):
	"""Detect if input is a local path."""
	path = os.path.expanduser(input_str)
	return os.path.exists(path) and os.path.isdir(path)

def get_directory_size(path):
	"""Calculate total size of directory in bytes."""
	total_size = 0
	try:
		for dirpath, dirnames, filenames in os.walk(path):
			if '.git' in dirpath:
				continue
			for filename in filenames:
				filepath = os.path.join(dirpath, filename)
				try:
					total_size += os.path.getsize(filepath)
				except:
					pass
	except:
		pass
	return total_size

def merge_vulnerability_results(security_results, trivy_results, audit_results):
	"""
	Merge vulnerability results from all sources.

	CHANGEMENT: Trivy et auditors remplacent la détection de vulnérabilités.
	Security scanner se concentre sur les secrets exposés et fichiers sensibles.
	"""
	# Start with security scanner results (secrets + sensitive files)
	merged = {
		'critical': list(security_results['critical']),
		'high': list(security_results['high']),
		'medium': list(security_results['medium']),
		'low': list(security_results['low']),
		'total': security_results['total'],
		'stats': security_results.get('stats', {}),
		'sources': {
			'security_scanner': security_results['total'],
			'trivy': 0,
			'dependency_audit': 0
		}
	}

	# Add Trivy vulnerabilities
	if trivy_results and trivy_results.get('total', 0) > 0:
		for severity in ['critical', 'high', 'medium', 'low']:
			for vuln in trivy_results.get(severity, []):
				merged[severity].append(vuln)
				merged['total'] += 1
		merged['sources']['trivy'] = trivy_results['total']

	# Add dependency audit vulnerabilities
	if audit_results:
		for lang, audit_data in audit_results.items():
			if audit_data and audit_data.get('total', 0) > 0:
				for vuln in audit_data.get('vulnerabilities', []):
					severity = vuln.get('severity', 'medium')
					merged[severity].append(vuln)
					merged['total'] += 1
				merged['sources']['dependency_audit'] += audit_data['total']

	return merged

def display_security_results(security_results):
	"""Display security scan results with enhanced formatting."""
	total = security_results['total']

	if total == 0:
		console.print("\n[bold green]🔒 No security issues detected![/bold green]")
		return

	console.print(f"\n[bold red]⚠️  {total} security issue(s) detected[/bold red]\n")

	# Create summary table
	table = Table(show_header=True, header_style="bold cyan")
	table.add_column("Severity", style="bold")
	table.add_column("Count", justify="right")
	table.add_column("Sample Issues")

	severity_data = [
		("🔴 Critical", security_results['critical'], "red"),
		("🟠 High", security_results['high'], "orange1"),
		("🟡 Medium", security_results['medium'], "yellow"),
		("🔵 Low", security_results['low'], "blue")
	]

	for severity_label, alerts, color in severity_data:
		if alerts:
			count = len(alerts)
			# Show first issue as sample
			sample = ""
			if alerts:
				alert = alerts[0]
				if alert["type"] == "secret_exposed":
					sample = f"{alert['file']}:{alert['line']}"
				elif alert["type"] == "sensitive_file":
					sample = alert['file']
				elif alert["type"] == "vulnerability":
					sample = f"{alert.get('package', 'N/A')} ({alert.get('cve_id', 'N/A')})"
				elif alert["type"] == "dependency_vulnerability":
					sample = f"{alert.get('package', 'N/A')} ({alert.get('cve_id', 'N/A')})"
				else:
					sample = alert.get('file', 'N/A')

			table.add_row(severity_label, str(count), sample)

	console.print(table)

	# Show stats if available
	if 'stats' in security_results:
		stats = security_results['stats']
		console.print(f"\n[dim]📊 Scanned {stats.get('files_scanned', 0)} files, filtered {stats.get('false_positives_filtered', 0)} false positives[/dim]")

	# Show sources breakdown
	if 'sources' in security_results:
		sources = security_results['sources']
		console.print(f"[dim]📦 Sources: Security={sources.get('security_scanner', 0)}, Trivy={sources.get('trivy', 0)}, Audits={sources.get('dependency_audit', 0)}[/dim]")

def display_docker_results(docker_results):
	"""Display Docker analysis results with enhanced formatting."""
	total = docker_results['total']

	if total == 0:
		if docker_results['dockerfiles'] or docker_results['compose_files']:
			console.print("\n[bold green]🐳 Docker configuration looks good![/bold green]")
		return

	console.print(f"\n[bold cyan]🐳 Docker Analysis: {total} issue(s) found[/bold cyan]\n")

	# Create summary table
	table = Table(show_header=True, header_style="bold cyan")
	table.add_column("Severity", style="bold")
	table.add_column("Count", justify="right")

	severity_data = [
		("🔴 Critical", docker_results['critical']),
		("🟠 High", docker_results['high']),
		("🟡 Medium", docker_results['medium']),
		("🔵 Low", docker_results['low']),
		("ℹ️ Info", docker_results.get('info', []))
	]

	for severity_label, alerts in severity_data:
		if alerts:
			table.add_row(severity_label, str(len(alerts)))

	console.print(table)

def display_test_info(structure):
	"""Display test information."""
	if structure.get('has_tests'):
		test_details = structure.get('test_details', {})
		test_type = test_details.get('type', 'unknown')
		test_quality = structure.get('test_quality', 'unknown')

		quality_emoji = {
			'extensive': '🌟',
			'good': '✅',
			'basic': '👍',
			'minimal': '⚠️',
			'empty': '❌',
			'unknown': '❓'
		}

		emoji = quality_emoji.get(test_quality, '❓')
		console.print(f"\n🧪 Tests: {emoji} {test_type} (Quality: {test_quality})")

def analyze_github_repo(url):
	"""Analyze a GitHub repository."""
	analyzer = None

	try:
		owner, repo = parse_github_url(url)
		console.print(f"\n[bold cyan]🔍 Analyzing GitHub: {owner}/{repo}[/bold cyan]\n")

		# GitHub API
		api = GitHubAPI()
		repo_info = api.get_repo_info(owner, repo)
		if not repo_info:
			sys.exit(1)

		languages = api.get_languages(owner, repo)
		contributors = api.get_contributors(owner, repo)

		# Clone and analyze
		analyzer = RepoAnalyzer(repo_info['clone_url'], repo_info['name'])
		if not analyzer.clone_repo():
			sys.exit(1)

		structure = analyzer.analyze_structure()
		dependencies = analyzer.find_dependencies()

		# Security scan (secrets + sensitive files)
		scanner = SecurityScanner(analyzer.repo_path)
		security_results = scanner.scan()

		# Trivy scan (CVE vulnerabilities)
		trivy_scanner = TrivyScanner(analyzer.repo_path)
		trivy_results = trivy_scanner.scan_filesystem()

		# Dependency audits (language-specific)
		auditor = DependencyScanner(analyzer.repo_path)
		audit_results = auditor.audit_all()

		# Merge all vulnerability results
		merged_security = merge_vulnerability_results(security_results, trivy_results, audit_results)

		# Docker analysis
		docker_scanner = DockerScanner(analyzer.repo_path)
		docker_results = docker_scanner.scan()

		# Generate reports
		console.print("[yellow]⏳ Generating reports...[/yellow]")
		reporter = ReportGenerator()

		md_path = reporter.generate_markdown(
			owner, repo, repo_info, languages, contributors,
			structure, dependencies, merged_security, docker_results
		)

		html_path = reporter.generate_html(
			owner, repo, repo_info, languages, contributors,
			structure, dependencies, merged_security, docker_results
		)

		# Display summary
		console.print("\n[bold green]✅ Analysis complete![/bold green]\n")

		# Repository info
		console.print(f"📊 [bold]{repo_info['full_name']}[/bold]")
		console.print(f"⭐ {repo_info['stars']:,} stars | 🔱 {repo_info['forks']:,} forks")
		console.print(f"📂 {structure.get('total_files', 0):,} files")

		if docker_results['dockerfiles'] or docker_results['compose_files']:
			console.print(f"🐳 {len(docker_results['dockerfiles'])} Dockerfile(s), {len(docker_results['compose_files'])} compose file(s)")

		# Test info
		display_test_info(structure)

		# Results
		display_security_results(merged_security)
		display_docker_results(docker_results)

		# Reports
		console.print(f"\n[bold green]📄 Reports generated:[/bold green]")
		console.print(f"  📝 Markdown: {md_path}")
		console.print(f"  🌐 HTML: [bold cyan]{html_path}[/bold cyan]")
		console.print(f"\n[dim]💡 Open the HTML file in your browser for an interactive view![/dim]\n")

	except ValueError as e:
		console.print(f"[red]{e}[/red]")
		sys.exit(1)
	except KeyboardInterrupt:
		console.print("\n[yellow]⚠️  Cancelled[/yellow]")
	finally:
		if analyzer:
			analyzer.cleanup()

def analyze_local_repo(path):
	"""Analyze a local repository."""
	try:
		path = os.path.abspath(os.path.expanduser(path))
		repo_name = os.path.basename(path)

		console.print(f"\n[bold cyan]🔍 Analyzing local: {path}[/bold cyan]\n")

		# Create repo info for local projects
		dir_size = get_directory_size(path)
		repo_info = {
			"name": repo_name,
			"full_name": f"local/{repo_name}",
			"description": f"Local analysis of {path}",
			"stars": 0,
			"forks": 0,
			"watchers": 0,
			"open_issues": 0,
			"language": "Unknown",
			"created_at": "N/A",
			"updated_at": "N/A",
			"license": "Unknown",
			"default_branch": "main",
			"size": dir_size / 1024,
			"clone_url": path
		}

		# No GitHub data
		languages = {}
		contributors = []

		# Analyze
		analyzer = RepoAnalyzer(None, repo_name, local_path=path)

		if not analyzer.prepare():
			sys.exit(1)

		structure = analyzer.analyze_structure()
		dependencies = analyzer.find_dependencies()

		# Security scan (secrets + sensitive files)
		scanner = SecurityScanner(analyzer.repo_path)
		security_results = scanner.scan()

		# Trivy scan (CVE vulnerabilities)
		trivy_scanner = TrivyScanner(analyzer.repo_path)
		trivy_results = trivy_scanner.scan_filesystem()

		# Dependency audits (language-specific)
		auditor = DependencyScanner(analyzer.repo_path)
		audit_results = auditor.audit_all()

		# Merge all vulnerability results
		merged_security = merge_vulnerability_results(security_results, trivy_results, audit_results)

		# Docker analysis
		docker_scanner = DockerScanner(analyzer.repo_path)
		docker_results = docker_scanner.scan()

		# Generate reports
		console.print("[yellow]⏳ Generating reports...[/yellow]")
		reporter = ReportGenerator()

		md_path = reporter.generate_markdown(
			"local", repo_name, repo_info, languages, contributors,
			structure, dependencies, merged_security, docker_results
		)

		html_path = reporter.generate_html(
			"local", repo_name, repo_info, languages, contributors,
			structure, dependencies, merged_security, docker_results
		)

		# Display summary
		console.print("\n[bold green]✅ Analysis complete![/bold green]\n")
		console.print(f"📊 [bold]{repo_info['full_name']}[/bold]")
		console.print(f"📂 {structure.get('total_files', 0):,} files")
		console.print(f"💾 Size: {repo_info['size'] / 1024:.1f} MB")

		if docker_results['dockerfiles'] or docker_results['compose_files']:
			console.print(f"🐳 {len(docker_results['dockerfiles'])} Dockerfile(s), {len(docker_results['compose_files'])} compose file(s)")

		# Test info
		display_test_info(structure)

		# Results
		display_security_results(merged_security)
		display_docker_results(docker_results)

		# Reports
		console.print(f"\n[bold green]📄 Reports generated:[/bold green]")
		console.print(f"  📝 Markdown: {md_path}")
		console.print(f"  🌐 HTML: [bold cyan]{html_path}[/bold cyan]")
		console.print(f"\n[dim]💡 Open the HTML file in your browser for an interactive view![/dim]\n")

	except Exception as e:
		console.print(f"[red]❌ Error analyzing local repository: {e}[/red]")
		import traceback
		console.print(f"[dim]{traceback.format_exc()}[/dim]")
		sys.exit(1)
	except KeyboardInterrupt:
		console.print("\n[yellow]⚠️  Cancelled[/yellow]")

def main():
	"""Entry point of the program."""
	if len(sys.argv) != 2:
		console.print("[red]Usage:[/red] python3 src/main.py <github_url_or_local_path>")
		console.print("\n[bold]Examples:[/bold]")
		console.print("  [cyan]GitHub:[/cyan]  python3 src/main.py github.com/owner/repo")
		console.print("  [cyan]Local:[/cyan]   python3 src/main.py /home/user/myproject")
		console.print("  [cyan]Local:[/cyan]   python3 src/main.py ./my-repo")
		console.print("  [cyan]Local:[/cyan]   python3 src/main.py ~/projects/webapp")
		sys.exit(1)

	input_arg = sys.argv[1]

	# Detect input type and analyze
	if is_github_url(input_arg):
		analyze_github_repo(input_arg)
	elif is_local_path(input_arg):
		analyze_local_repo(input_arg)
	else:
		console.print(f"[red]❌ Invalid input:[/red] {input_arg}")
		console.print("\n[bold]Must be either:[/bold]")
		console.print("  • A GitHub URL (github.com/owner/repo)")
		console.print("  • A valid local directory path")
		console.print("\n[bold]Examples:[/bold]")
		console.print("  python3 src/main.py github.com/torvalds/linux")
		console.print("  python3 src/main.py /home/user/myproject")
		console.print("  python3 src/main.py ./my-local-repo")
		sys.exit(1)

if __name__ == "__main__":
	main()