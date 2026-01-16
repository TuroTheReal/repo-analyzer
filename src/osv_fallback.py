"""
OSV Fallback Scanner - Utilise l'API OSV.dev (Google) pour scanner les vulnérabilités CVE
Utilisé quand Trivy et les auditors natifs (pip-audit, npm audit) ne sont pas disponibles

API Documentation: https://osv.dev/docs/
Ecosystems supportés: PyPI, npm, Go, Cargo, Maven, NuGet, RubyGems, etc.
"""

import os
import re
import json
import requests
from typing import Dict, List, Optional, Tuple
from rich.console import Console

console = Console()

# Timeout pour les requêtes API
API_TIMEOUT = 10

# URL de l'API OSV
OSV_API_URL = "https://api.osv.dev/v1/query"
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"

# Mapping des ecosystems OSV
ECOSYSTEM_MAP = {
    'python': 'PyPI',
    'nodejs': 'npm',
    'go': 'Go',
    'rust': 'crates.io',
    'ruby': 'RubyGems',
    'java': 'Maven',
    'nuget': 'NuGet',
    'php': 'Packagist'
}

# Mapping severity OSV vers format interne
SEVERITY_MAP = {
    'CRITICAL': 'critical',
    'HIGH': 'high',
    'MODERATE': 'medium',
    'MEDIUM': 'medium',
    'LOW': 'low',
    'UNKNOWN': 'low'
}


class OSVFallbackScanner:
    """
    Scanner de vulnérabilités utilisant l'API OSV.dev
    Fallback quand Trivy et auditors natifs ne sont pas disponibles
    """

    def __init__(self, repo_path: str):
        self.repo_path = repo_path
        self.results = self._empty_results()
        self.packages_scanned = 0
        self.api_calls = 0

    def _empty_results(self) -> Dict:
        """Structure de résultats vide"""
        return {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'total': 0,
            'source': 'osv_api',
            'by_package': {},
            'stats': {
                'critical_count': 0,
                'high_count': 0,
                'medium_count': 0,
                'low_count': 0
            },
            'scan_info': {
                'packages_scanned': 0,
                'api_calls': 0,
                'ecosystems': []
            }
        }

    def scan_all(self) -> Dict:
        """
        Scanne toutes les dépendances détectées dans le repo
        Retourne les vulnérabilités trouvées via l'API OSV
        """
        console.print("[cyan]🔍 OSV Fallback: Scanning dependencies via OSV.dev API...[/cyan]")

        # Détecter et parser les fichiers de dépendances
        dependencies = self._detect_all_dependencies()

        if not dependencies:
            console.print("[yellow]⚠️  No dependency files found for OSV scanning[/yellow]")
            return self.results

        ecosystems_scanned = []

        # Scanner chaque ecosystem
        for ecosystem, packages in dependencies.items():
            if packages:
                ecosystems_scanned.append(ecosystem)
                self._scan_ecosystem(ecosystem, packages)

        # Mettre à jour les stats
        self.results['scan_info']['packages_scanned'] = self.packages_scanned
        self.results['scan_info']['api_calls'] = self.api_calls
        self.results['scan_info']['ecosystems'] = ecosystems_scanned

        # Calculer le total
        self.results['total'] = (
            len(self.results['critical']) +
            len(self.results['high']) +
            len(self.results['medium']) +
            len(self.results['low'])
        )

        self.results['stats'] = {
            'critical_count': len(self.results['critical']),
            'high_count': len(self.results['high']),
            'medium_count': len(self.results['medium']),
            'low_count': len(self.results['low'])
        }

        if self.results['total'] > 0:
            console.print(f"[red]⚠️  OSV found {self.results['total']} vulnerabilities[/red]")
        else:
            console.print("[green]✓ OSV scan complete: No vulnerabilities found[/green]")

        return self.results

    def _detect_all_dependencies(self) -> Dict[str, List[Tuple[str, str]]]:
        """
        Détecte et parse tous les fichiers de dépendances
        Retourne {ecosystem: [(package_name, version), ...]}
        """
        dependencies = {}

        # Python - requirements.txt
        python_deps = self._parse_requirements_txt()
        if python_deps:
            dependencies['python'] = python_deps

        # Node.js - package.json
        nodejs_deps = self._parse_package_json()
        if nodejs_deps:
            dependencies['nodejs'] = nodejs_deps

        # Go - go.mod
        go_deps = self._parse_go_mod()
        if go_deps:
            dependencies['go'] = go_deps

        # Rust - Cargo.toml
        rust_deps = self._parse_cargo_toml()
        if rust_deps:
            dependencies['rust'] = rust_deps

        # Ruby - Gemfile.lock
        ruby_deps = self._parse_gemfile_lock()
        if ruby_deps:
            dependencies['ruby'] = ruby_deps

        return dependencies

    def _parse_requirements_txt(self) -> List[Tuple[str, str]]:
        """Parse requirements.txt pour Python"""
        packages = []
        req_files = ['requirements.txt', 'requirements-dev.txt', 'requirements-prod.txt']

        for req_file in req_files:
            filepath = os.path.join(self.repo_path, req_file)
            if os.path.exists(filepath):
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            line = line.strip()
                            # Ignorer commentaires et lignes vides
                            if not line or line.startswith('#') or line.startswith('-'):
                                continue

                            # Parser package==version ou package>=version
                            match = re.match(r'^([a-zA-Z0-9_-]+)\s*([=<>!~]+)\s*([0-9][^\s;#]*)', line)
                            if match:
                                pkg_name = match.group(1).lower()
                                version = match.group(3)
                                packages.append((pkg_name, version))
                            else:
                                # Package sans version spécifiée
                                match = re.match(r'^([a-zA-Z0-9_-]+)', line)
                                if match:
                                    packages.append((match.group(1).lower(), None))
                except Exception:
                    pass

        return packages

    def _parse_package_json(self) -> List[Tuple[str, str]]:
        """Parse package.json pour Node.js"""
        packages = []
        filepath = os.path.join(self.repo_path, 'package.json')

        if os.path.exists(filepath):
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    data = json.load(f)

                # dependencies et devDependencies
                for dep_type in ['dependencies', 'devDependencies']:
                    deps = data.get(dep_type, {})
                    for pkg_name, version in deps.items():
                        # Nettoyer la version (enlever ^, ~, etc.)
                        clean_version = re.sub(r'^[\^~>=<]+', '', str(version))
                        if clean_version and not clean_version.startswith('*'):
                            packages.append((pkg_name, clean_version))
            except Exception:
                pass

        return packages

    def _parse_go_mod(self) -> List[Tuple[str, str]]:
        """Parse go.mod pour Go"""
        packages = []
        filepath = os.path.join(self.repo_path, 'go.mod')

        if os.path.exists(filepath):
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read()

                # Parser les require
                in_require = False
                for line in content.split('\n'):
                    line = line.strip()

                    if line.startswith('require ('):
                        in_require = True
                        continue
                    if line == ')':
                        in_require = False
                        continue

                    if in_require or line.startswith('require '):
                        # Format: module/path v1.2.3
                        match = re.search(r'([^\s]+)\s+v?([0-9][^\s]*)', line)
                        if match:
                            packages.append((match.group(1), match.group(2)))
            except Exception:
                pass

        return packages

    def _parse_cargo_toml(self) -> List[Tuple[str, str]]:
        """Parse Cargo.toml pour Rust"""
        packages = []
        filepath = os.path.join(self.repo_path, 'Cargo.toml')

        if os.path.exists(filepath):
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read()

                # Section [dependencies]
                in_deps = False
                for line in content.split('\n'):
                    line = line.strip()

                    if line == '[dependencies]' or line == '[dev-dependencies]':
                        in_deps = True
                        continue
                    if line.startswith('[') and in_deps:
                        in_deps = False
                        continue

                    if in_deps and '=' in line:
                        # Format: package = "version" ou package = { version = "x.y.z" }
                        match = re.match(r'^([a-zA-Z0-9_-]+)\s*=\s*"([^"]+)"', line)
                        if match:
                            packages.append((match.group(1), match.group(2)))
                        else:
                            # Format avec table inline
                            match = re.match(r'^([a-zA-Z0-9_-]+)\s*=.*version\s*=\s*"([^"]+)"', line)
                            if match:
                                packages.append((match.group(1), match.group(2)))
            except Exception:
                pass

        return packages

    def _parse_gemfile_lock(self) -> List[Tuple[str, str]]:
        """Parse Gemfile.lock pour Ruby"""
        packages = []
        filepath = os.path.join(self.repo_path, 'Gemfile.lock')

        if os.path.exists(filepath):
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read()

                # Section specs dans GEM
                in_specs = False
                for line in content.split('\n'):
                    if 'specs:' in line:
                        in_specs = True
                        continue
                    if in_specs:
                        if line and not line.startswith(' '):
                            in_specs = False
                            continue
                        # Format:     gem_name (version)
                        match = re.match(r'^\s{4}([a-zA-Z0-9_-]+)\s+\(([^)]+)\)', line)
                        if match:
                            packages.append((match.group(1), match.group(2)))
            except Exception:
                pass

        return packages

    def _scan_ecosystem(self, ecosystem: str, packages: List[Tuple[str, str]]) -> None:
        """
        Scanne les packages d'un ecosystem via l'API OSV
        Utilise le batch API pour optimiser les appels
        """
        osv_ecosystem = ECOSYSTEM_MAP.get(ecosystem)
        if not osv_ecosystem:
            return

        # Préparer les requêtes batch (max 1000 par batch)
        queries = []
        for pkg_name, version in packages:
            if version:
                queries.append({
                    'package': {
                        'name': pkg_name,
                        'ecosystem': osv_ecosystem
                    },
                    'version': version
                })
            self.packages_scanned += 1

        if not queries:
            return

        # Envoyer par batches de 100
        batch_size = 100
        for i in range(0, len(queries), batch_size):
            batch = queries[i:i + batch_size]
            self._query_osv_batch(batch, ecosystem)

    def _query_osv_batch(self, queries: List[Dict], ecosystem: str) -> None:
        """Envoie une requête batch à l'API OSV"""
        try:
            self.api_calls += 1
            response = requests.post(
                OSV_BATCH_URL,
                json={'queries': queries},
                timeout=API_TIMEOUT,
                headers={'Content-Type': 'application/json'}
            )

            if response.status_code == 200:
                data = response.json()
                results = data.get('results', [])

                for i, result in enumerate(results):
                    vulns = result.get('vulns', [])
                    if vulns and i < len(queries):
                        pkg_info = queries[i]
                        pkg_name = pkg_info['package']['name']
                        pkg_version = pkg_info.get('version', 'unknown')

                        for vuln in vulns:
                            self._process_vulnerability(vuln, pkg_name, pkg_version, ecosystem)

        except requests.exceptions.Timeout:
            console.print(f"[yellow]⚠️  OSV API timeout for {ecosystem} batch[/yellow]")
        except requests.exceptions.RequestException as e:
            console.print(f"[yellow]⚠️  OSV API error: {str(e)[:50]}[/yellow]")
        except Exception as e:
            console.print(f"[yellow]⚠️  OSV processing error: {str(e)[:50]}[/yellow]")

    def _process_vulnerability(self, vuln: Dict, pkg_name: str, pkg_version: str, ecosystem: str) -> None:
        """Traite une vulnérabilité retournée par OSV"""
        vuln_id = vuln.get('id', 'UNKNOWN')

        # Extraire la severity
        severity = self._extract_severity(vuln)

        # Extraire les versions affectées et fixes
        affected = vuln.get('affected', [{}])[0] if vuln.get('affected') else {}
        ranges = affected.get('ranges', [{}])[0] if affected.get('ranges') else {}
        fixed_version = None

        for event in ranges.get('events', []):
            if 'fixed' in event:
                fixed_version = event['fixed']
                break

        # Créer l'alerte
        alert = {
            'type': 'vulnerability',
            'source': 'osv_api',
            'ecosystem': ecosystem,
            'cve_id': vuln_id,
            'package': pkg_name,
            'installed_version': pkg_version,
            'fixed_version': fixed_version or 'No fix available',
            'severity': severity,
            'title': vuln.get('summary', vuln_id),
            'description': vuln.get('details', '')[:500],  # Limiter la taille
            'references': [ref.get('url') for ref in vuln.get('references', [])[:3]]
        }

        # Ajouter aux résultats
        self.results[severity].append(alert)

        # Tracking par package
        if pkg_name not in self.results['by_package']:
            self.results['by_package'][pkg_name] = {
                'count': 0,
                'highest_severity': 'low',
                'ecosystem': ecosystem
            }

        self.results['by_package'][pkg_name]['count'] += 1

        # Mettre à jour highest severity
        severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
        current = self.results['by_package'][pkg_name]['highest_severity']
        if severity_order.get(severity, 0) > severity_order.get(current, 0):
            self.results['by_package'][pkg_name]['highest_severity'] = severity

    def _extract_severity(self, vuln: Dict) -> str:
        """Extrait la severity d'une vulnérabilité OSV"""
        # Essayer d'abord la database_specific severity
        db_specific = vuln.get('database_specific', {})
        if 'severity' in db_specific:
            sev = db_specific['severity'].upper()
            return SEVERITY_MAP.get(sev, 'medium')

        # Ensuite essayer CVSS dans severity array
        severities = vuln.get('severity', [])
        for sev in severities:
            if sev.get('type') == 'CVSS_V3':
                score_str = sev.get('score', '')
                # Extraire le score numérique du vecteur CVSS
                try:
                    # Format: CVSS:3.1/AV:N/AC:L/... ou juste un score
                    if '/' in score_str:
                        # C'est un vecteur, on calcule approximativement
                        return self._cvss_vector_to_severity(score_str)
                except Exception:
                    pass

        # Fallback : chercher dans les aliases (CVE, GHSA)
        aliases = vuln.get('aliases', [])
        for alias in aliases:
            if alias.startswith('CVE-') or alias.startswith('GHSA-'):
                # Par défaut medium pour CVE/GHSA sans score
                return 'medium'

        return 'medium'  # Default

    def _cvss_vector_to_severity(self, vector: str) -> str:
        """Convertit un vecteur CVSS en severity approximative"""
        # Analyse simplifiée basée sur Attack Vector et Impact
        vector_upper = vector.upper()

        # Critères pour CRITICAL
        if 'AV:N' in vector_upper and 'AC:L' in vector_upper:
            if 'C:H' in vector_upper or 'I:H' in vector_upper:
                return 'critical'

        # Critères pour HIGH
        if 'AV:N' in vector_upper or 'AV:A' in vector_upper:
            if 'C:H' in vector_upper or 'I:H' in vector_upper or 'A:H' in vector_upper:
                return 'high'

        # Critères pour MEDIUM
        if 'C:L' in vector_upper or 'I:L' in vector_upper or 'A:L' in vector_upper:
            return 'medium'

        return 'medium'  # Default


def check_internet_connection() -> bool:
    """Vérifie si une connexion internet est disponible"""
    try:
        response = requests.get("https://api.osv.dev/v1", timeout=5)
        return response.status_code == 200
    except Exception:
        return False
