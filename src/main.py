#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
GitHub Repository Analyzer - Main Entry Point

Architecture de scanning en cascade:
1. Security Scanner (secrets) - toujours exécuté
2. Trivy (CVE complet) - si installé
3. Auditors natifs (pip-audit, npm, etc.) - complémentaire ou fallback
4. OSV API - fallback si pas Trivy ni auditors
5. Heuristiques - fallback offline

Scoring équitable:
- Sections N/A si non applicables (pas de Docker = pas de score Docker)
- Recommandations si outils manquants
- Déduplication des CVE entre sources
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
from osv_fallback import OSVFallbackScanner, check_internet_connection
from vulnerability_merger import VulnerabilityMerger, determine_fallback_strategy
from reporter import ReportGenerator

console = Console()


# ============================================================================
# URL / PATH DETECTION
# ============================================================================

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


# ============================================================================
# VULNERABILITY SCANNING CASCADE
# ============================================================================

def run_vulnerability_cascade(repo_path: str) -> dict:
    """
    Exécute la cascade de scanning des vulnérabilités.

    Cascade:
    1. Security Scanner (secrets) - TOUJOURS
    2. Trivy - si installé et fonctionnel
    3. Auditors natifs - complémentaire OU fallback
    4. OSV API - fallback si pas Trivy
    5. Heuristiques - fallback offline (TODO)

    Returns:
        dict: Résultats fusionnés et dédupliqués avec métadonnées
    """
    console.print("\n[bold cyan]🔒 Starting security analysis...[/bold cyan]\n")

    # 1. Security Scanner (secrets + fichiers sensibles) - TOUJOURS
    console.print("[cyan]Phase 1/4: Scanning for secrets and sensitive files...[/cyan]")
    security_scanner = SecurityScanner(repo_path)
    security_results = security_scanner.scan()

    # 2. Trivy scan (CVE complet)
    console.print("\n[cyan]Phase 2/4: Checking Trivy availability...[/cyan]")
    trivy_scanner = TrivyScanner(repo_path)
    trivy_results = None
    trivy_successful = False

    if trivy_scanner.is_available():
        trivy_results = trivy_scanner.scan_filesystem()
        trivy_successful = trivy_results.get('scan_successful', False)
    else:
        console.print("[yellow]ℹ️  Trivy not installed - will use fallback scanners[/yellow]")

    # 3. Déterminer les auditors disponibles
    console.print("\n[cyan]Phase 3/4: Running language-specific auditors...[/cyan]")
    auditor = DependencyScanner(repo_path)
    audit_results = auditor.audit_all()

    # Collecter les auditors qui ont fonctionné
    auditors_used = []
    for lang, result in audit_results.items():
        if result and result.get('total', 0) >= 0:  # Même 0 = auditor a fonctionné
            auditors_used.append(lang)

    # 4. Fallback OSV si nécessaire
    osv_results = None

    # Déterminer la stratégie de fallback
    has_internet = check_internet_connection()
    strategy = determine_fallback_strategy(
        trivy_available=trivy_scanner.is_available(),
        trivy_successful=trivy_successful,
        auditors_available=auditors_used,
        has_internet=has_internet
    )

    # Utiliser OSV si recommandé par la stratégie
    if strategy['use_osv'] and not trivy_successful:
        console.print("\n[cyan]Phase 4/4: Using OSV.dev API as fallback...[/cyan]")
        osv_scanner = OSVFallbackScanner(repo_path)
        osv_results = osv_scanner.scan_all()
    else:
        console.print("\n[cyan]Phase 4/4: Skipping OSV fallback (Trivy or auditors sufficient)[/cyan]")

    # 5. Fusionner et dédupliquer tous les résultats
    console.print("\n[cyan]Merging and deduplicating results...[/cyan]")
    merger = VulnerabilityMerger()
    merged_results = merger.merge_all(
        security_results=security_results,
        trivy_results=trivy_results,
        audit_results=audit_results,
        osv_results=osv_results
    )

    # Ajouter les recommandations de la stratégie
    merged_results['recommendations'] = strategy.get('recommendations', [])
    merged_results['scan_strategy'] = strategy

    # Afficher les recommandations
    if strategy.get('recommendations'):
        console.print("\n[yellow]💡 Recommendations:[/yellow]")
        for rec in strategy['recommendations']:
            console.print(f"   {rec}")

    return merged_results


# ============================================================================
# DISPLAY FUNCTIONS
# ============================================================================

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
                if alert.get("type") == "secret_exposed":
                    sample = f"{alert.get('file', 'N/A')}:{alert.get('line', '?')}"
                elif alert.get("type") == "sensitive_file":
                    sample = alert.get('file', 'N/A')
                elif alert.get("type") in ["vulnerability", "dependency_vulnerability"]:
                    sample = f"{alert.get('package', 'N/A')} ({alert.get('cve_id', 'N/A')})"
                else:
                    sample = alert.get('file', alert.get('package', 'N/A'))

            table.add_row(severity_label, str(count), sample)

    console.print(table)

    # Show stats if available
    if 'stats' in security_results:
        stats = security_results['stats']
        if stats.get('files_scanned'):
            console.print(f"\n[dim]📊 Scanned {stats.get('files_scanned', 0)} files[/dim]")

    # Show sources breakdown
    if 'sources' in security_results:
        sources = security_results['sources']
        if sources:
            sources_str = ", ".join(sources)
            console.print(f"[dim]📦 Vulnerability sources: {sources_str}[/dim]")

    # Show dedup stats if available
    if 'dedup_stats' in security_results:
        dedup = security_results['dedup_stats']
        if dedup.get('duplicates_removed', 0) > 0:
            console.print(f"[dim]🔄 {dedup['duplicates_removed']} duplicate CVEs removed[/dim]")


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


# ============================================================================
# ANALYSIS PIPELINE (FACTORIZED)
# ============================================================================

def run_analysis_pipeline(repo_path: str, repo_name: str, repo_info: dict,
                          languages: dict, contributors: list, owner: str):
    """
    Pipeline d'analyse commun pour GitHub et local.

    Args:
        repo_path: Chemin vers le repo à analyser
        repo_name: Nom du repo
        repo_info: Métadonnées du repo
        languages: Langages détectés (peut être vide pour local)
        contributors: Contributeurs (peut être vide pour local)
        owner: Propriétaire (ou "local")

    Returns:
        tuple: (structure, dependencies, merged_security, docker_results)
    """
    # Créer l'analyzer
    analyzer = RepoAnalyzer(None, repo_name, local_path=repo_path)

    # Analyser la structure
    structure = analyzer.analyze_structure()
    dependencies = analyzer.find_dependencies()

    # Cascade de scanning des vulnérabilités
    merged_security = run_vulnerability_cascade(repo_path)

    # Docker analysis
    console.print("\n[cyan]🐳 Analyzing Docker configuration...[/cyan]")
    docker_scanner = DockerScanner(repo_path)
    docker_results = docker_scanner.scan()

    # Generate reports
    console.print("\n[yellow]⏳ Generating reports...[/yellow]")
    reporter = ReportGenerator()

    md_path = reporter.generate_markdown(
        owner, repo_name, repo_info, languages, contributors,
        structure, dependencies, merged_security, docker_results
    )

    html_path = reporter.generate_html(
        owner, repo_name, repo_info, languages, contributors,
        structure, dependencies, merged_security, docker_results
    )

    return structure, dependencies, merged_security, docker_results, md_path, html_path


def display_summary(repo_info: dict, structure: dict, docker_results: dict,
                    merged_security: dict, md_path: str, html_path: str):
    """Affiche le résumé de l'analyse."""
    console.print("\n[bold green]✅ Analysis complete![/bold green]\n")

    # Repository info
    console.print(f"📊 [bold]{repo_info['full_name']}[/bold]")

    if repo_info.get('stars', 0) > 0:
        console.print(f"⭐ {repo_info['stars']:,} stars | 🔱 {repo_info['forks']:,} forks")

    console.print(f"📂 {structure.get('total_files', 0):,} files")

    if repo_info.get('size', 0) > 1024:
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


# ============================================================================
# MAIN ANALYSIS FUNCTIONS
# ============================================================================

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

        # Clone repository
        analyzer = RepoAnalyzer(repo_info['clone_url'], repo_info['name'])
        if not analyzer.clone_repo():
            sys.exit(1)

        # Run analysis pipeline
        (structure, dependencies, merged_security, docker_results,
         md_path, html_path) = run_analysis_pipeline(
            analyzer.repo_path, repo_info['name'], repo_info,
            languages, contributors, owner
        )

        # Display summary
        display_summary(repo_info, structure, docker_results,
                       merged_security, md_path, html_path)

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

        # No GitHub data for local repos
        languages = {}
        contributors = []

        # Validate path
        temp_analyzer = RepoAnalyzer(None, repo_name, local_path=path)
        if not temp_analyzer.prepare():
            sys.exit(1)

        # Run analysis pipeline
        (structure, dependencies, merged_security, docker_results,
         md_path, html_path) = run_analysis_pipeline(
            path, repo_name, repo_info, languages, contributors, "local"
        )

        # Display summary
        display_summary(repo_info, structure, docker_results,
                       merged_security, md_path, html_path)

    except Exception as e:
        console.print(f"[red]❌ Error analyzing local repository: {e}[/red]")
        import traceback
        console.print(f"[dim]{traceback.format_exc()}[/dim]")
        sys.exit(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️  Cancelled[/yellow]")


# ============================================================================
# ENTRY POINT
# ============================================================================

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
