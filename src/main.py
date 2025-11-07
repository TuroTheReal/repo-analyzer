#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
from rich.console import Console
from github_api import GitHubAPI
from analyzer import RepoAnalyzer
from security import SecurityScanner
from reporter import ReportGenerator

console = Console()

def parse_github_url(url):
	"""Extrait owner et repo depuis une URL GitHub."""
	url = url.strip().replace("https://", "").replace("http://", "")
	parts = url.split("/")

	if len(parts) < 3 or parts[0] != "github.com":
		raise ValueError("❌ URL invalide. Format: github.com/owner/repo")

	owner = parts[1]
	repo = parts[2].replace(".git", "")

	if not owner or not repo:
		raise ValueError("❌ URL incomplète. Il faut owner ET repo")

	return owner, repo

def display_security_results(security_results):
	"""Affiche les résultats de sécurité."""
	total = security_results['total']

	if total == 0:
		console.print("\n[bold green]🔒 Aucun problème de sécurité détecté ![/bold green]")
		return

	console.print(f"\n[bold red]⚠️  {total} problème(s) de sécurité détecté(s)[/bold red]\n")

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

		for alert in alerts[:5]:  # Limiter à 5 pour l'affichage console
			if alert["type"] == "secret_exposed":
				console.print(f"  • {alert['file']}:{alert['line']} - {alert['message']}")
			elif alert["type"] == "outdated_dependency":
				console.print(f"  • {alert['package']} {alert['current_version']} → {alert['min_safe_version']}")
			else:
				console.print(f"  • {alert.get('file', 'N/A')} - {alert['message']}")

		if len(alerts) > 5:
			console.print(f"  [dim]... et {len(alerts) - 5} autres (voir rapport)[/dim]")

def main():
	"""Point d'entrée du programme."""
	if len(sys.argv) != 2:
		console.print("[red]Usage:[/red] python3 src/main.py <github_url>")
		sys.exit(1)

	analyzer = None

	try:
		owner, repo = parse_github_url(sys.argv[1])
		console.print(f"\n[bold cyan]🔍 Analyse de : {owner}/{repo}[/bold cyan]\n")

		# API GitHub
		api = GitHubAPI()
		repo_info = api.get_repo_info(owner, repo)
		if not repo_info:
			sys.exit(1)

		languages = api.get_languages(owner, repo)
		contributors = api.get_contributors(owner, repo)

		# Clone et analyse
		analyzer = RepoAnalyzer(repo_info['clone_url'], repo_info['name'])
		if not analyzer.clone_repo():
			sys.exit(1)

		structure = analyzer.analyze_structure()
		dependencies = analyzer.find_dependencies()

		# Sécurité
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

		# Génération des rapports
		console.print("[yellow]⏳ Génération des rapports...[/yellow]")
		reporter = ReportGenerator()

		# Rapport Markdown
		md_path = reporter.generate_markdown(
			owner, repo, repo_info, languages, contributors,
			structure, dependencies, security_results
		)

		# Rapport HTML 🎨
		html_path = reporter.generate_html(
			owner, repo, repo_info, languages, contributors,
			structure, dependencies, security_results
		)

		# Affichage résumé
		console.print("\n[bold green]✅ Analyse terminée ![/bold green]\n")
		console.print(f"📊 **{repo_info['full_name']}**")
		console.print(f"⭐ {repo_info['stars']:,} stars | 🍴 {repo_info['forks']:,} forks")
		console.print(f"📂 {structure.get('total_files', 0):,} fichiers")

		display_security_results(security_results)

		console.print(f"\n[bold green]📄 Rapports générés :[/bold green]")
		console.print(f"  📝 Markdown: {md_path}")
		console.print(f"  🌐 HTML: [bold cyan]{html_path}[/bold cyan]")
		console.print(f"\n[dim]💡 Ouvrez le fichier HTML dans votre navigateur pour une vue interactive ![/dim]\n")

	except ValueError as e:
		console.print(f"[red]{e}[/red]")
		sys.exit(1)
	except KeyboardInterrupt:
		console.print("\n[yellow]⚠️  Annulé[/yellow]")
	finally:
		if analyzer:
			analyzer.cleanup()

if __name__ == "__main__":
	main()
