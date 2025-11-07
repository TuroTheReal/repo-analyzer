#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
GitHub Repository Analyzer
Analyse un repo GitHub et génère un rapport.
"""

import sys
from rich.console import Console
from github_api import GitHubAPI
from analyzer import RepoAnalyzer

console = Console()

def parse_github_url(url):
	"""
	Extrait owner et repo depuis une URL GitHub.

	Exemples:
		https://github.com/torvalds/linux -> ('torvalds', 'linux')
		github.com/user/repo -> ('user', 'repo')
	"""

	# Url cleaning
	url = url.strip().replace("https://", "").replace("http://", "")

	# Format == github.com/user/repo
	parts = url.split("/")

	if len(parts) < 3 or parts[0] != "github.com":
		raise ValueError("❌ URL invalide. Format: github.com/owner/repo")

	owner = parts[1]
	repo = parts[2].replace(".git", "")

	if not owner or not repo:
		raise ValueError("❌ URL incomplète. Il faut owner ET repo")

	return owner ,repo


def main():
	"""Point d'entrée du programme."""
	if len(sys.argv) != 2:
		console.print("[red]Usage:[/red] python3 src/main.py <github_url>")
		sys.exit(1)

	analyzer = None

	try:
		# Parser l'URL
		owner, repo = parse_github_url(sys.argv[1])
		console.print(f"\n[bold cyan]🔍 Analyse de : {owner}/{repo}[/bold cyan]\n")

		# Initialiser l'API
		api = GitHubAPI()

		# Récupérer les infos
		console.print("[yellow]⏳ Récupération des métadonnées...[/yellow]")
		repo_info = api.get_repo_info(owner, repo)

		if not repo_info:
			console.print("[red]✗ Impossible de récupérer les infos[/red]")
			sys.exit(1)

		languages = api.get_languages(owner, repo)
		contributors = api.get_contributors(owner, repo)

		# === PHASE 2: Clone et analyse ===
		analyzer = RepoAnalyzer(repo_info['clone_url'], repo_info['name'])
		if not analyzer.clone_repo():
			console.print("[red]✗ Échec du clone[/red]")
			sys.exit(1)

		structure = analyzer.analyze_structure()
		dependencies = analyzer.find_dependencies()

		# Affichage des résultats (temporaire)
		console.print("\n[bold green]✓ Analyse terminée[/bold green]\n")

		console.print(f"[bold]Nom:[/bold] {repo_info['full_name']}")
		console.print(f"[bold]Description:[/bold] {repo_info['description']}")
		console.print(f"[bold]⭐ Stars:[/bold] {repo_info['stars']:,}")
		console.print(f"[bold]🍴 Forks:[/bold] {repo_info['forks']:,}")
		console.print(f"[bold]📝 Issues ouvertes:[/bold] {repo_info['open_issues']}")
		console.print(f"[bold]📅 Dernière màj:[/bold] {repo_info['updated_at']}")
		console.print(f"[bold]⚖️  License:[/bold] {repo_info['license']}")

		if languages:
			console.print("\n[bold]🔧 Langages:[/bold]")
			for lang, percent in languages.items():
				console.print(f"  - {lang}: {percent}%")

		if contributors:
			console.print("\n[bold]👥 Top Contributors:[/bold]")
			for contrib in contributors:
				console.print(f"  - {contrib['login']}: {contrib['contributions']} commits")

		console.print("\n[bold underline]📁 Structure[/bold underline]")
		console.print(f"Fichiers: {structure.get('total_files', 0)}")
		console.print(f"Dossiers: {structure.get('total_dirs', 0)}")
		console.print(f"Profondeur max: {structure.get('max_depth', 0)}")
		console.print(f"Tests: {'✓' if structure.get('has_tests') else '✗'}")
		console.print(f"CI/CD: {'✓' if structure.get('has_ci') else '✗'}")
		console.print(f"Docker: {'✓' if structure.get('has_docker') else '✗'}")

		if structure.get('important_files'):
			console.print("\n[bold]Fichiers importants:[/bold]")
			for f in structure['important_files'][:10]:
				console.print(f"  ✓ {f}")

		if structure.get('file_types'):
			console.print("\n[bold]Types de fichiers:[/bold]")
			for ext, count in list(structure['file_types'].items())[:10]:
				console.print(f"  {ext}: {count} fichiers")

		if dependencies:
			console.print("\n[bold underline]📦 Dépendances[/bold underline]")
			for dep_type, deps in dependencies.items():
				console.print(f"\n[bold]{dep_type.capitalize()}:[/bold]")
				for dep in deps[:10]:
					console.print(f"  - {dep}")

		console.print("\n[dim]TODO: Génération du rapport markdown + sécurité...[/dim]")

	except ValueError as e:
		console.print(f"[red]{e}[/red]")
		sys.exit(1)
	except KeyboardInterrupt:
		console.print("\n[yellow]⚠ Annulé par l'utilisateur[/yellow]")
	finally:
		# Cleanup (toujours exécuté)
		if analyzer:
			analyzer.cleanup()

if __name__ == "__main__":
	main()