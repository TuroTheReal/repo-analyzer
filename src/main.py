#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
from rich.console import Console
from rich.table import Table
from github_api import GitHubAPI
from analyzer import RepoAnalyzer
from security import SecurityScanner

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
	"""Affiche les résultats de sécurité de manière lisible."""
	total = security_results['total']

	if total == 0:
		console.print("\n[bold green]🔒 Aucun problème de sécurité détecté ![/bold green]")
		return

	console.print(f"\n[bold red]⚠️  {total} problème(s) de sécurité détecté(s)[/bold red]\n")

	# Afficher par sévérité
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

		console.print(f"\n[bold {color}]{icon} {severity.upper()} ({len(alerts)})[/bold {color}]")

		for alert in alerts[:10]:  # Limiter à 10 par sévérité pour l'affichage
			if alert["type"] == "secret_exposed":
				console.print(f"  [{color}]•[/{color}] {alert['file']}:{alert['line']}")
				console.print(f"    {alert['message']}")
				console.print(f"    [dim]{alert['preview']}[/dim]")

			elif alert["type"] == "sensitive_file":
				console.print(f"  [{color}]•[/{color}] {alert['file']}")
				console.print(f"    {alert['message']}")

			elif alert["type"] == "outdated_dependency":
				console.print(f"  [{color}]•[/{color}] {alert['package']} {alert['current_version']}")
				console.print(f"    Recommandé: >={alert['min_safe_version']}")
				console.print(f"    [dim]{alert['message']}[/dim]")

			else:
				console.print(f"  [{color}]•[/{color}] {alert.get('file', 'N/A')}")
				console.print(f"    {alert['message']}")

		if len(alerts) > 10:
			console.print(f"  [dim]... et {len(alerts) - 10} autres[/dim]")

def main():
	"""Point d'entrée du programme."""
	if len(sys.argv) != 2:
		console.print("[red]Usage:[/red] python3 src/main.py <github_url>")
		sys.exit(1)

	analyzer = None

	try:
		owner, repo = parse_github_url(sys.argv[1])
		console.print(f"\n[bold cyan]🔍 Analyse de : {owner}/{repo}[/bold cyan]\n")

		# === PHASE 1: API GitHub ===
		api = GitHubAPI()

		repo_info = api.get_repo_info(owner, repo)
		if not repo_info:
			sys.exit(1)

		languages = api.get_languages(owner, repo)
		contributors = api.get_contributors(owner, repo)

		# === PHASE 2: Clone et analyse ===
		analyzer = RepoAnalyzer(repo_info['clone_url'], repo_info['name'])

		if not analyzer.clone_repo():
			sys.exit(1)

		structure = analyzer.analyze_structure()
		dependencies = analyzer.find_dependencies()

		# === PHASE 3: Sécurité ===
		scanner = SecurityScanner(analyzer.repo_path)
		security_results = scanner.scan()

		# Vérifier les dépendances obsolètes
		if dependencies:
			scanner.check_dependencies_versions(dependencies)
			# Re-organiser après ajout des dépendances
			security_results = {
				"critical": [a for a in scanner.alerts if a["severity"] == "critical"],
				"high": [a for a in scanner.alerts if a["severity"] == "high"],
				"medium": [a for a in scanner.alerts if a["severity"] == "medium"],
				"low": [a for a in scanner.alerts if a["severity"] == "low"],
				"total": len(scanner.alerts)
			}

		# === AFFICHAGE DES RÉSULTATS ===
		console.print("\n[bold green]✅ Analyse terminée[/bold green]\n")

		# Métadonnées
		console.print("[bold underline]📊 Métadonnées[/bold underline]")
		console.print(f"Nom: {repo_info['full_name']}")
		console.print(f"Description: {repo_info['description']}")
		console.print(f"⭐ Stars: {repo_info['stars']:,}")
		console.print(f"🍴 Forks: {repo_info['forks']:,}")
		console.print(f"📝 Issues: {repo_info['open_issues']}")
		console.print(f"⚖️  License: {repo_info['license']}")

		# Langages
		if languages:
			console.print("\n[bold underline]🔧 Langages[/bold underline]")
			for lang, percent in list(languages.items())[:5]:
				console.print(f"  {lang}: {percent}%")

		# Contributors
		if contributors:
			console.print("\n[bold underline]👥 Top Contributors[/bold underline]")
			for contrib in contributors[:5]:
				console.print(f"  {contrib['login']}: {contrib['contributions']} commits")

		# Structure
		console.print("\n[bold underline]📁 Structure[/bold underline]")
		console.print(f"Fichiers: {structure.get('total_files', 0)}")
		console.print(f"Dossiers: {structure.get('total_dirs', 0)}")
		console.print(f"Tests: {'✓' if structure.get('has_tests') else '✗'}")
		console.print(f"CI/CD: {'✓' if structure.get('has_ci') else '✗'}")
		console.print(f"Docker: {'✓' if structure.get('has_docker') else '✗'}")

		# Sécurité
		display_security_results(security_results)

		console.print("\n[dim]Prochaine étape: Génération du rapport markdown...[/dim]")

	except ValueError as e:
		console.print(f"[red]{e}[/red]")
		sys.exit(1)
	except KeyboardInterrupt:
		console.print("\n[yellow]⚠ Annulé[/yellow]")
	finally:
		if analyzer:
			analyzer.cleanup()

if __name__ == "__main__":
	main()