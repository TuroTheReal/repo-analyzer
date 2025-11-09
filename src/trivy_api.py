"""
Trivy integration for vulnerability scanning.

This module integrates Aqua Security's Trivy scanner to detect:
- CVE vulnerabilities in dependencies
- OS package vulnerabilities
- Docker image vulnerabilities
- License issues

IMPROVEMENTS:
- Full integration with main analyzer
- Deduplication with security scanner
- Enhanced vulnerability reporting
"""

import subprocess
import json
import os
import shutil
from pathlib import Path
from rich.console import Console

console = Console()

class TrivyScanner:
    """Integration with Trivy for vulnerability scanning."""

    def __init__(self, repo_path):
        """
        Args:
            repo_path: Path to repository to scan
        """
        self.repo_path = repo_path
        self.trivy_available = self._check_trivy_installed()

    def _check_trivy_installed(self):
        """Check if Trivy is installed and accessible."""
        if not shutil.which('trivy'):
            console.print("[yellow]⚠️  Trivy not installed - skipping vulnerability scan[/yellow]")
            console.print("[dim]💡 Install: curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh[/dim]")
            return False

        try:
            result = subprocess.run(
                ['trivy', '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                console.print("[green]✓[/green] Trivy detected")
                return True
            return False
        except Exception:
            return False

    def scan_filesystem(self):
        """
        Scan filesystem for vulnerabilities in dependencies.

        Returns:
            dict: Vulnerability results by severity
        """
        if not self.trivy_available:
            return self._empty_results()

        console.print("[yellow]⏳ Running Trivy vulnerability scan...[/yellow]")

        try:
            result = subprocess.run(
                [
                    'trivy', 'fs',
                    '--format', 'json',
                    '--severity', 'CRITICAL,HIGH,MEDIUM,LOW',
                    '--quiet',
                    '--scanners', 'vuln',
                    self.repo_path
                ],
                capture_output=True,
                text=True,
                timeout=180  # 3 min timeout
            )

            if result.returncode != 0:
                console.print(f"[yellow]⚠️  Trivy scan completed with warnings[/yellow]")
                # Continue anyway, Trivy may still return results

            if not result.stdout.strip():
                console.print("[dim]ℹ️  Trivy: No vulnerabilities found[/dim]")
                return self._empty_results()

            data = json.loads(result.stdout)
            parsed = self._parse_trivy_results(data)

            if parsed['total'] > 0:
                console.print(f"[green]✓[/green] Trivy scan complete: {parsed['total']} vulnerabilities found")
            else:
                console.print("[green]✓[/green] Trivy scan complete: No vulnerabilities")

            return parsed

        except subprocess.TimeoutExpired:
            console.print("[yellow]⚠️  Trivy scan timed out (180s)[/yellow]")
            return self._empty_results()
        except json.JSONDecodeError:
            console.print("[yellow]⚠️  Failed to parse Trivy output[/yellow]")
            return self._empty_results()
        except Exception as e:
            console.print(f"[yellow]⚠️  Trivy scan error: {e}[/yellow]")
            return self._empty_results()

    def scan_docker_images(self, dockerfiles):
        """
        Scan Docker images for vulnerabilities.

        Args:
            dockerfiles: List of Dockerfile paths

        Returns:
            dict: Vulnerability results per Dockerfile
        """
        if not self.trivy_available or not dockerfiles:
            return {}

        results = {}

        for dockerfile in dockerfiles[:3]:  # Limit to 3 Dockerfiles
            console.print(f"[yellow]⏳ Scanning Dockerfile: {dockerfile}[/yellow]")

            dockerfile_path = os.path.join(self.repo_path, dockerfile)

            try:
                result = subprocess.run(
                    [
                        'trivy', 'config',
                        '--format', 'json',
                        '--severity', 'CRITICAL,HIGH,MEDIUM,LOW',
                        '--quiet',
                        dockerfile_path
                    ],
                    capture_output=True,
                    text=True,
                    timeout=60
                )

                if result.stdout.strip():
                    data = json.loads(result.stdout)
                    parsed = self._parse_trivy_results(data)
                    if parsed['total'] > 0:
                        results[dockerfile] = parsed
                        console.print(f"[green]✓[/green] {dockerfile}: {parsed['total']} issues")

            except Exception as e:
                console.print(f"[yellow]⚠️  Error scanning {dockerfile}: {e}[/yellow]")

        return results

    def _parse_trivy_results(self, trivy_json):
        """
        Parse Trivy JSON output into our format.

        Args:
            trivy_json: Raw Trivy JSON output

        Returns:
            dict: Formatted vulnerability results
        """
        vulnerabilities = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'total': 0,
            'by_package': {},
            'stats': {
                'critical_count': 0,
                'high_count': 0,
                'medium_count': 0,
                'low_count': 0
            }
        }

        # Trivy returns "Results" array
        results = trivy_json.get('Results', [])

        for result in results:
            target = result.get('Target', 'unknown')
            vulns = result.get('Vulnerabilities', [])

            if not vulns:
                continue

            for vuln in vulns:
                severity = vuln.get('Severity', 'UNKNOWN').lower()

                # Skip if not a valid severity
                if severity not in ['critical', 'high', 'medium', 'low']:
                    continue

                pkg_name = vuln.get('PkgName', 'unknown')
                installed_ver = vuln.get('InstalledVersion', 'unknown')
                fixed_ver = vuln.get('FixedVersion', 'No fix available')

                alert = {
                    'type': 'vulnerability',
                    'cve_id': vuln.get('VulnerabilityID', 'N/A'),
                    'package': pkg_name,
                    'installed_version': installed_ver,
                    'fixed_version': fixed_ver,
                    'title': vuln.get('Title', 'N/A')[:150],  # Truncate
                    'description': vuln.get('Description', '')[:250],
                    'severity': severity,
                    'target': target,
                    'cvss_score': self._extract_cvss_score(vuln),
                    'references': vuln.get('References', [])[:2]  # Limit to 2
                }

                vulnerabilities[severity].append(alert)
                vulnerabilities['total'] += 1
                vulnerabilities['stats'][f'{severity}_count'] += 1

                # Track by package
                if pkg_name not in vulnerabilities['by_package']:
                    vulnerabilities['by_package'][pkg_name] = {
                        'count': 0,
                        'highest_severity': severity,
                        'installed_version': installed_ver,
                        'fixed_version': fixed_ver
                    }
                vulnerabilities['by_package'][pkg_name]['count'] += 1

                # Update highest severity for package
                severity_order = ['critical', 'high', 'medium', 'low']
                current_severity = vulnerabilities['by_package'][pkg_name]['highest_severity']
                if severity_order.index(severity) < severity_order.index(current_severity):
                    vulnerabilities['by_package'][pkg_name]['highest_severity'] = severity

        return vulnerabilities

    def _extract_cvss_score(self, vuln):
        """Extract CVSS score from vulnerability data."""
        cvss_data = vuln.get('CVSS', {})

        # Try different CVSS sources
        if 'nvd' in cvss_data and 'V3Score' in cvss_data['nvd']:
            return cvss_data['nvd']['V3Score']
        elif 'redhat' in cvss_data and 'V3Score' in cvss_data['redhat']:
            return cvss_data['redhat']['V3Score']

        return 0.0

    def _empty_results(self):
        """Return empty results structure."""
        return {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'total': 0,
            'by_package': {},
            'stats': {
                'critical_count': 0,
                'high_count': 0,
                'medium_count': 0,
                'low_count': 0
            }
        }