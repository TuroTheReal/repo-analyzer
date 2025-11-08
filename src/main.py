#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import re
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
	# Support relative and absolute paths
	path = os.path.expanduser(input_str)  # Expand ~ to home directory
	return os.path.exists(path) and os.path.isdir(path)

def get_directory_size(path):
	"""Calculate total size of directory in bytes."""
	total_size = 0
	try:
		for dirpath, dirnames, filenames in os.walk(path):
			# Skip .git directory
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

def analyze_local_repo(path):
	"""Analyze a local repository."""
	try:
		# Expand and normalize path
		path = os.path.abspath(os.path.expanduser(path))
		repo_name = os.path.basename(path)

		console.print(f"\n[bold cyan]📁 Analyzing local: {path}[/bold cyan]\n")

		# Create fake repo_info for local projects
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
			"size": dir_size / 1024,  # Convert to KB
			"clone_url": path
		}

		# No GitHub data for local repos
		languages = {}
		contributors = []

		# Use local path directly (no cloning)
		analyzer = RepoAnalyzer(None, repo_name, local_path=path)

		# No need to clone - already local
		if not analyzer.prepare():
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

		# Use "local" as owner for reports
		md_path = reporter.generate_markdown(
			"local", repo_name, repo_info, languages, contributors,
			structure, dependencies, security_results, docker_results
		)

		html_path = reporter.generate_html(
			"local", repo_name, repo_info, languages, contributors,
			structure, dependencies, security_results, docker_results
		)

		# Display summary
		console.print("\n[bold green]✅ Analysis complete![/bold green]\n")
		console.print(f"📊 **{repo_info['full_name']}**")
		console.print(f"📂 {structure.get('total_files', 0):,} files")
		console.print(f"💾 Size: {repo_info['size'] / 1024:.1f} MB")

		if docker_results['dockerfiles'] or docker_results['compose_files']:
			console.print(f"🐳 {len(docker_results['dockerfiles'])} Dockerfile(s), {len(docker_results['compose_files'])} compose file(s)")

		display_security_results(security_results)
		display_docker_results(docker_results)

		console.print(f"\n[bold green]📄 Reports generated:[/bold green]")
		console.print(f"  📝 Markdown: {md_path}")
		console.print(f"  🌐 HTML: [bold cyan]{html_path}[/bold cyan]")
		console.print(f"\n[dim]💡 Open the HTML file in your browser for an interactive view![/dim]\n")

	except Exception as e:
		console.print(f"[red]❌ Error analyzing local repository: {e}[/red]")
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

	# Detect input type and analyze accordingly
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
