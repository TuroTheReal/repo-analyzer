#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
from rich.console import Console
from github_api import GitHubAPI
from analyzer import RepoAnalyzer
from security import SecurityScanner
from docker_scanner import DockerScanner
from reporter import ReportGenerator

console = Console()

def parse_github_url(url):
	"""Extract owner and repo from GitHub URL."""
	url = url.strip().replace("https://", "").replace("http://", "")
	parts = url.split("/")

	if len(parts) < 3 or parts[0] != "github.com":
		raise ValueError("❌ Invalid URL. Format: github.com/owner/repo")

	owner = parts[1]
	repo = parts[2].replace(".git", "")

	if not owner or not repo:
		raise ValueError("❌ Incomplete URL. Need both owner AND repo")

	return owner, repo

def display_security_results(security_results):
	"""Display security scan results."""
	total = security_results['total']

	if total == 0:
		console.print("\n[bold green]🔒 No security issues detected![/bold green]")
		return

	console.print(f"\n[bold red]⚠️  {total} security issue(s) detected[/bold red]\n")

	severity_colors = {
		"critical": "red",
		"high": "orange1",
		"medium": "yellow",
		"low": "blue"
	}

	severity_icons = {
		"critical": "🔴",
		"high": "🟠",
		"medium": "🟡",
		"low": "🔵"
	}

	for severity in ["critical", "high", "medium", "low"]:
		alerts = security_results.get(severity, [])

		if not alerts:
			continue

		color = severity_colors[severity]
		icon = severity_icons[severity]

		console.print(f"[bold {color}]{icon} {severity.upper()} ({len(alerts)})[/bold {color}]")

		for alert in alerts[:5]:  # Limit to 5 for console display
			if alert["type"] == "secret_exposed":
				console.print(f"  • {alert['file']}:{alert['line']} - {alert['message']}")
			elif alert["type"] == "outdated_dependency":
				console.print(f"  • {alert['package']} {alert['current_version']} → {alert['min_safe_version']}")
			else:
				console.print(f"  • {alert.get('file', 'N/A')} - {alert['message']}")

		if len(alerts) > 5:
			console.print(f"  [dim]... and {len(alerts) - 5} more (see report)[/dim]")

def display_docker_results(docker_results):
	"""Display Docker analysis results."""
	total = docker_results['total']

	if total == 0:
		if docker_results['dockerfiles'] or docker_results['compose_files']:
			console.print("\n[bold green]🐳 Docker configuration looks good![/bold green]")
		return

	console.print(f"\n[bold cyan]🐳 Docker Analysis: {total} issue(s) found[/bold cyan]\n")

	severity_colors = {
		"critical": "red",
		"high": "orange1",
		"medium": "yellow",
		"low": "blue",
		"info": "cyan"
	}

	severity_icons = {
		"critical": "🔴",
		"high": "🟠",
		"medium": "🟡",
		"low": "🔵",
		"info": "ℹ️"
	}

	for severity in ["critical", "high", "medium", "low", "info"]:
		alerts = docker_results.get(severity, [])

		if not alerts:
			continue

		color = severity_colors[severity]
		icon = severity_icons[severity]

		console.print(f"[bold {color}]{icon} {severity.upper()} ({len(alerts)})[/bold {color}]")

		for alert in alerts[:3]:  # Limit to 3 for console display
			file_info = f"{alert['file']}" + (f":{alert['line']}" if alert.get('line', 0) > 0 else "")
			console.print(f"  • {file_info} - {alert['message']}")

		if len(alerts) > 3:
			console.print(f"  [dim]... and {len(alerts) - 3} more (see report)[/dim]")

def main():
	"""Entry point of the program."""
	if len(sys.argv) != 2:
		console.print("[red]Usage:[/red] python3 src/main.py <github_url>")
		sys.exit(1)

	analyzer = None

	try:
		owner, repo = parse_github_url(sys.argv[1])
		console.print(f"\n[bold cyan]🔍 Analyzing: {owner}/{repo}[/bold cyan]\n")

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

		# Security scan
		scanner = SecurityScanner(analyzer.repo_path)
		security_results = scanner.scan()

		if dependencies:
			scanner.check_dependencies_versions(dependencies)
			security_results = {
				"critical": [a for a in scanner.alerts if a["severity"] == "critical"],
				"high": [a for a in scanner.alerts if a["severity"] == "high"],
				"medium": [a for a in scanner.alerts if a["severity"] == "medium"],
				"low": [a for a in scanner.alerts if a["severity"] == "low"],
				"total": len(scanner.alerts)
			}

		# Docker analysis
		docker_scanner = DockerScanner(analyzer.repo_path)
		docker_results = docker_scanner.scan()

		# Generate reports
		console.print("[yellow]⏳ Generating reports...[/yellow]")
		reporter = ReportGenerator()

		# Markdown report
		md_path = reporter.generate_markdown(
			owner, repo, repo_info, languages, contributors,
			structure, dependencies, security_results, docker_results
		)

		# HTML report 🎨
		html_path = reporter.generate_html(
			owner, repo, repo_info, languages, contributors,
			structure, dependencies, security_results, docker_results
		)

		# Display summary
		console.print("\n[bold green]✅ Analysis complete![/bold green]\n")
		console.print(f"📊 **{repo_info['full_name']}**")
		console.print(f"⭐ {repo_info['stars']:,} stars | 🍴 {repo_info['forks']:,} forks")
		console.print(f"📂 {structure.get('total_files', 0):,} files")

		if docker_results['dockerfiles'] or docker_results['compose_files']:
			console.print(f"🐳 {len(docker_results['dockerfiles'])} Dockerfile(s), {len(docker_results['compose_files'])} compose file(s)")

		display_security_results(security_results)
		display_docker_results(docker_results)

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

if __name__ == "__main__":
	main()
