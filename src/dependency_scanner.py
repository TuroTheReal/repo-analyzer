"""
Dependency auditor for multiple languages.

Supports:
- Python: pip-audit
- Node.js: npm audit, yarn audit
- Ruby: bundler-audit
- Go: govulncheck
- Rust: cargo-audit
- Java: dependency-check (OWASP)

IMPROVEMENT: Centralized dependency vulnerability scanning
"""

import subprocess
import json
import os
import shutil
from pathlib import Path
from rich.console import Console

console = Console()

class DependencyScanner:
    """Multi-language dependency vulnerability auditor."""

    def __init__(self, repo_path):
        """
        Args:
            repo_path: Path to repository to scan
        """
        self.repo_path = repo_path
        self.available_tools = self._check_available_tools()

    def _check_available_tools(self):
        """Check which audit tools are installed."""
        tools = {
            'pip-audit': shutil.which('pip-audit'),
            'npm': shutil.which('npm'),
            'yarn': shutil.which('yarn'),
            'bundler-audit': shutil.which('bundle-audit'),
            'govulncheck': shutil.which('govulncheck'),
            'cargo-audit': shutil.which('cargo'),
        }

        available = {tool: path for tool, path in tools.items() if path}

        if available:
            console.print(f"[green]✓[/green] Dependency audit tools available: {', '.join(available.keys())}")
        else:
            console.print("[dim]ℹ️  No dependency audit tools installed (optional)[/dim]")

        return available

    def audit_all(self):
        """
        Run all available dependency audits.

        Returns:
            dict: Audit results by language
        """
        console.print("[yellow]⏳ Running dependency audits...[/yellow]")

        results = {
            'python': self._audit_python() if 'pip-audit' in self.available_tools else None,
            'nodejs': self._audit_nodejs() if 'npm' in self.available_tools else None,
            'ruby': self._audit_ruby() if 'bundler-audit' in self.available_tools else None,
            'go': self._audit_go() if 'govulncheck' in self.available_tools else None,
            'rust': self._audit_rust() if 'cargo-audit' in self.available_tools else None,
        }

        # Remove None values
        results = {k: v for k, v in results.items() if v is not None}

        total_vulns = sum(r.get('total', 0) for r in results.values())

        if total_vulns > 0:
            console.print(f"[yellow]⚠️  Dependency audits found {total_vulns} vulnerabilities[/yellow]")
        else:
            console.print("[green]✓[/green] No dependency vulnerabilities found")

        return results

    def _audit_python(self):
        """Audit Python dependencies with pip-audit."""
        req_file = os.path.join(self.repo_path, 'requirements.txt')

        if not os.path.exists(req_file):
            return None

        console.print("[yellow]  → Auditing Python dependencies...[/yellow]")

        try:
            result = subprocess.run(
                ['pip-audit', '-r', req_file, '--format', 'json'],
                capture_output=True,
                text=True,
                timeout=60,
                cwd=self.repo_path
            )

            if result.stdout.strip():
                data = json.loads(result.stdout)
                return self._parse_pip_audit(data)

            return {'total': 0, 'vulnerabilities': []}

        except subprocess.TimeoutExpired:
            console.print("[yellow]    ⚠️  pip-audit timed out[/yellow]")
            return {'total': 0, 'vulnerabilities': [], 'error': 'timeout'}
        except Exception as e:
            console.print(f"[yellow]    ⚠️  pip-audit error: {e}[/yellow]")
            return {'total': 0, 'vulnerabilities': [], 'error': str(e)}

    def _audit_nodejs(self):
        """Audit Node.js dependencies with npm audit."""
        pkg_file = os.path.join(self.repo_path, 'package.json')

        if not os.path.exists(pkg_file):
            return None

        console.print("[yellow]  → Auditing Node.js dependencies...[/yellow]")

        try:
            result = subprocess.run(
                ['npm', 'audit', '--json'],
                capture_output=True,
                text=True,
                timeout=60,
                cwd=self.repo_path
            )

            if result.stdout.strip():
                data = json.loads(result.stdout)
                return self._parse_npm_audit(data)

            return {'total': 0, 'vulnerabilities': []}

        except subprocess.TimeoutExpired:
            console.print("[yellow]    ⚠️  npm audit timed out[/yellow]")
            return {'total': 0, 'vulnerabilities': [], 'error': 'timeout'}
        except Exception as e:
            console.print(f"[yellow]    ⚠️  npm audit error: {e}[/yellow]")
            return {'total': 0, 'vulnerabilities': [], 'error': str(e)}

    def _audit_ruby(self):
        """Audit Ruby dependencies with bundler-audit."""
        gemfile = os.path.join(self.repo_path, 'Gemfile')

        if not os.path.exists(gemfile):
            return None

        console.print("[yellow]  → Auditing Ruby dependencies...[/yellow]")

        try:
            # Update database first
            subprocess.run(
                ['bundle-audit', 'update'],
                capture_output=True,
                timeout=30,
                cwd=self.repo_path
            )

            result = subprocess.run(
                ['bundle-audit', 'check', '--format', 'json'],
                capture_output=True,
                text=True,
                timeout=60,
                cwd=self.repo_path
            )

            if result.stdout.strip():
                data = json.loads(result.stdout)
                return self._parse_bundler_audit(data)

            return {'total': 0, 'vulnerabilities': []}

        except subprocess.TimeoutExpired:
            console.print("[yellow]    ⚠️  bundler-audit timed out[/yellow]")
            return {'total': 0, 'vulnerabilities': [], 'error': 'timeout'}
        except Exception as e:
            console.print(f"[yellow]    ⚠️  bundler-audit error: {e}[/yellow]")
            return {'total': 0, 'vulnerabilities': [], 'error': str(e)}

    def _audit_go(self):
        """Audit Go dependencies with govulncheck."""
        go_mod = os.path.join(self.repo_path, 'go.mod')

        if not os.path.exists(go_mod):
            return None

        console.print("[yellow]  → Auditing Go dependencies...[/yellow]")

        try:
            result = subprocess.run(
                ['govulncheck', '-json', './...'],
                capture_output=True,
                text=True,
                timeout=90,
                cwd=self.repo_path
            )

            if result.stdout.strip():
                return self._parse_govulncheck(result.stdout)

            return {'total': 0, 'vulnerabilities': []}

        except subprocess.TimeoutExpired:
            console.print("[yellow]    ⚠️  govulncheck timed out[/yellow]")
            return {'total': 0, 'vulnerabilities': [], 'error': 'timeout'}
        except Exception as e:
            console.print(f"[yellow]    ⚠️  govulncheck error: {e}[/yellow]")
            return {'total': 0, 'vulnerabilities': [], 'error': str(e)}

    def _audit_rust(self):
        """Audit Rust dependencies with cargo-audit."""
        cargo_toml = os.path.join(self.repo_path, 'Cargo.toml')

        if not os.path.exists(cargo_toml):
            return None

        console.print("[yellow]  → Auditing Rust dependencies...[/yellow]")

        try:
            result = subprocess.run(
                ['cargo', 'audit', '--json'],
                capture_output=True,
                text=True,
                timeout=60,
                cwd=self.repo_path
            )

            if result.stdout.strip():
                data = json.loads(result.stdout)
                return self._parse_cargo_audit(data)

            return {'total': 0, 'vulnerabilities': []}

        except subprocess.TimeoutExpired:
            console.print("[yellow]    ⚠️  cargo-audit timed out[/yellow]")
            return {'total': 0, 'vulnerabilities': [], 'error': 'timeout'}
        except Exception as e:
            console.print(f"[yellow]    ⚠️  cargo-audit error: {e}[/yellow]")
            return {'total': 0, 'vulnerabilities': [], 'error': str(e)}

    def _parse_pip_audit(self, data):
        """Parse pip-audit JSON output."""
        vulnerabilities = []

        for vuln in data.get('vulnerabilities', []):
            vulnerabilities.append({
                'type': 'dependency_vulnerability',
                'package': vuln.get('name', 'unknown'),
                'installed_version': vuln.get('installed_version', 'unknown'),
                'fixed_version': vuln.get('fixed_versions', ['N/A'])[0] if vuln.get('fixed_versions') else 'N/A',
                'cve_id': vuln.get('id', 'N/A'),
                'severity': self._normalize_severity(vuln.get('severity', 'medium')),
                'description': vuln.get('description', '')[:200]
            })

        return {
            'total': len(vulnerabilities),
            'vulnerabilities': vulnerabilities
        }

    def _parse_npm_audit(self, data):
        """Parse npm audit JSON output."""
        vulnerabilities = []

        for vuln_id, vuln in data.get('vulnerabilities', {}).items():
            vulnerabilities.append({
                'type': 'dependency_vulnerability',
                'package': vuln.get('name', 'unknown'),
                'installed_version': vuln.get('range', 'unknown'),
                'fixed_version': vuln.get('fixAvailable', {}).get('version', 'N/A') if isinstance(vuln.get('fixAvailable'), dict) else 'N/A',
                'cve_id': vuln.get('via', [{}])[0].get('cve', 'N/A') if isinstance(vuln.get('via'), list) else 'N/A',
                'severity': self._normalize_severity(vuln.get('severity', 'medium')),
                'description': vuln.get('via', [{}])[0].get('title', '')[:200] if isinstance(vuln.get('via'), list) else ''
            })

        return {
            'total': len(vulnerabilities),
            'vulnerabilities': vulnerabilities
        }

    def _parse_bundler_audit(self, data):
        """Parse bundler-audit JSON output."""
        vulnerabilities = []

        for vuln in data.get('results', []):
            vulnerabilities.append({
                'type': 'dependency_vulnerability',
                'package': vuln.get('gem', 'unknown'),
                'installed_version': vuln.get('version', 'unknown'),
                'fixed_version': vuln.get('patched_versions', ['N/A'])[0] if vuln.get('patched_versions') else 'N/A',
                'cve_id': vuln.get('cve', 'N/A'),
                'severity': 'high',  # bundler-audit doesn't provide severity
                'description': vuln.get('title', '')[:200]
            })

        return {
            'total': len(vulnerabilities),
            'vulnerabilities': vulnerabilities
        }

    def _parse_govulncheck(self, output):
        """Parse govulncheck JSON output (newline-delimited JSON)."""
        vulnerabilities = []

        for line in output.strip().split('\n'):
            try:
                data = json.loads(line)
                if data.get('finding'):
                    finding = data['finding']
                    vulnerabilities.append({
                        'type': 'dependency_vulnerability',
                        'package': finding.get('osv', {}).get('package', {}).get('name', 'unknown'),
                        'installed_version': 'N/A',
                        'fixed_version': 'See references',
                        'cve_id': finding.get('osv', {}).get('id', 'N/A'),
                        'severity': 'high',
                        'description': finding.get('osv', {}).get('summary', '')[:200]
                    })
            except:
                continue

        return {
            'total': len(vulnerabilities),
            'vulnerabilities': vulnerabilities
        }

    def _parse_cargo_audit(self, data):
        """Parse cargo-audit JSON output."""
        vulnerabilities = []

        for vuln in data.get('vulnerabilities', {}).get('list', []):
            vulnerabilities.append({
                'type': 'dependency_vulnerability',
                'package': vuln.get('package', 'unknown'),
                'installed_version': 'N/A',
                'fixed_version': vuln.get('patched_versions', 'N/A'),
                'cve_id': vuln.get('id', 'N/A'),
                'severity': self._normalize_severity(vuln.get('cvss', {}).get('severity', 'medium')),
                'description': vuln.get('title', '')[:200]
            })

        return {
            'total': len(vulnerabilities),
            'vulnerabilities': vulnerabilities
        }

    def _normalize_severity(self, severity):
        """Normalize severity levels across different tools."""
        severity_lower = str(severity).lower()

        if severity_lower in ['critical', 'high']:
            return 'high'
        elif severity_lower in ['moderate', 'medium']:
            return 'medium'
        elif severity_lower in ['low', 'info']:
            return 'low'
        else:
            return 'medium'