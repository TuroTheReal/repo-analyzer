"""
Checks de sécurité basiques sur un repository.
"""

import os
import re
from pathlib import Path
from rich.console import Console

console = Console()

class SecurityScanner:
	"""Scanner de sécurité pour détecter des problèmes courants."""

	# Patterns regex pour détecter des secrets
	SECRET_PATTERNS = {
		"aws_access_key": r'AKIA[0-9A-Z]{16}',
		"aws_secret_key": r'aws_secret_access_key\s*=\s*["\']?([A-Za-z0-9/+=]{40})["\']?',
		"github_token": r'gh[pousr]_[A-Za-z0-9]{36,}',
		"generic_api_key": r'api[_-]?key\s*[=:]\s*["\']([A-Za-z0-9_\-]{20,})["\']',
		"generic_secret": r'secret\s*[=:]\s*["\']([A-Za-z0-9_\-]{20,})["\']',
		"password": r'password\s*[=:]\s*["\']([^"\']{8,})["\']',
		"private_key": r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
		"slack_token": r'xox[baprs]-[0-9a-zA-Z]{10,48}',
		"stripe_key": r'sk_live_[0-9a-zA-Z]{24,}',
		"google_api": r'AIza[0-9A-Za-z\\-_]{35}',
	}

	# Fichiers sensibles qui ne devraient pas être commités
	SENSITIVE_FILES = [
		".env",
		".env.local",
		".env.production",
		"credentials.json",
		"secrets.yaml",
		"secrets.yml",
		"config/secrets.yml",
		"id_rsa",
		"id_dsa",
		".ssh/id_rsa",
		"*.pem",
		"*.key",
		"*.p12",
		"*.pfx",
		".aws/credentials",
		".docker/config.json",
	]

	# Extensions de fichiers à ignorer (binaires, médias, etc.)
	IGNORED_EXTENSIONS = {
		'.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg',
		'.mp4', '.mov', '.avi', '.mp3', '.wav',
		'.zip', '.tar', '.gz', '.rar', '.7z',
		'.exe', '.dll', '.so', '.dylib',
		'.pdf', '.doc', '.docx', '.xls', '.xlsx',
		'.pyc', '.pyo', '.class', '.o', '.a',
		'.min.js', '.min.css',  # Fichiers minifiés
	}

	def __init__(self, repo_path):
		"""
		Args:
			repo_path: Chemin vers le repo cloné
		"""
		self.repo_path = repo_path
		self.alerts = []

	def scan(self):
		"""
		Lance tous les scans de sécurité.

		Returns:
			dict: Résultats avec différents niveaux de sévérité
		"""
		console.print("[yellow]⏳ Scan de sécurité...[/yellow]")

		self.alerts = []

		# Scan 1: Secrets hardcodés
		self._scan_secrets()

		# Scan 2: Fichiers sensibles
		self._scan_sensitive_files()

		# Scan 3: Vérifier .gitignore
		self._check_gitignore()

		# Organiser par sévérité
		results = {
			"critical": [a for a in self.alerts if a["severity"] == "critical"],
			"high": [a for a in self.alerts if a["severity"] == "high"],
			"medium": [a for a in self.alerts if a["severity"] == "medium"],
			"low": [a for a in self.alerts if a["severity"] == "low"],
			"total": len(self.alerts)
		}

		console.print(f"[green]✓[/green] Scan terminé: {results['total']} alertes")

		return results

	def _scan_secrets(self):
		"""Scanne tous les fichiers texte pour détecter des secrets."""
		scanned_files = 0
		max_files = 500  # Limite pour éviter de scanner des gros repos trop longtemps

		for root, dirs, files in os.walk(self.repo_path):
			# Ignorer .git et node_modules
			dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', 'venv', '__pycache__']]

			if scanned_files >= max_files:
				break

			for file in files:
				if scanned_files >= max_files:
					break

				file_path = os.path.join(root, file)
				relative_path = os.path.relpath(file_path, self.repo_path)

				# Ignorer fichiers par extension
				if Path(file).suffix in self.IGNORED_EXTENSIONS:
					continue

				# Ignorer fichiers trop gros (>1MB)
				try:
					if os.path.getsize(file_path) > 1_000_000:
						continue
				except:
					continue

				# Scanner le fichier
				self._scan_file_for_secrets(file_path, relative_path)
				scanned_files += 1

	def _scan_file_for_secrets(self, file_path, relative_path):
		"""Scanne un fichier spécifique pour des secrets."""
		try:
			with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
				content = f.read()

				# Tester chaque pattern
				for secret_type, pattern in self.SECRET_PATTERNS.items():
					matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)

					for match in matches:
						# Trouver le numéro de ligne
						line_num = content[:match.start()].count('\n') + 1

						# Extraire la ligne complète
						lines = content.split('\n')
						line_content = lines[line_num - 1].strip() if line_num <= len(lines) else ""

						# Masquer la valeur secrète
						secret_value = match.group(0)
						masked_value = secret_value[:8] + "***" if len(secret_value) > 8 else "***"

						# Déterminer la sévérité
						severity = "critical"
						if secret_type in ["password", "generic_secret"]:
							# Peut être un faux positif (ex: password = "")
							if len(secret_value) < 15:
								severity = "medium"

						self.alerts.append({
							"type": "secret_exposed",
							"severity": severity,
							"secret_type": secret_type,
							"file": relative_path,
							"line": line_num,
							"preview": line_content[:100],
							"message": f"{secret_type.replace('_', ' ').title()} détecté"
						})

		except Exception as e:
			# Fichier illisible, on ignore
			pass

	def _scan_sensitive_files(self):
		"""Détecte des fichiers sensibles qui ne devraient pas être commités."""
		for root, dirs, files in os.walk(self.repo_path):
			dirs[:] = [d for d in dirs if d != '.git']

			for file in files:
				file_path = os.path.join(root, file)
				relative_path = os.path.relpath(file_path, self.repo_path)

				# Vérifier si c'est un fichier sensible
				for sensitive_pattern in self.SENSITIVE_FILES:
					# Support des wildcards basiques
					if '*' in sensitive_pattern:
						pattern = sensitive_pattern.replace('*', '.*')
						if re.match(pattern, file):
							self.alerts.append({
								"type": "sensitive_file",
								"severity": "high",
								"file": relative_path,
								"message": f"Fichier sensible détecté: {file}"
							})
					else:
						if file == sensitive_pattern or relative_path.endswith(sensitive_pattern):
							self.alerts.append({
								"type": "sensitive_file",
								"severity": "high",
								"file": relative_path,
								"message": f"Fichier sensible détecté: {file}"
							})

	def _check_gitignore(self):
		"""Vérifie si un .gitignore existe et contient les patterns importants."""
		gitignore_path = os.path.join(self.repo_path, '.gitignore')

		if not os.path.exists(gitignore_path):
			self.alerts.append({
				"type": "missing_gitignore",
				"severity": "low",
				"file": ".gitignore",
				"message": "Pas de .gitignore trouvé"
			})
			return

		# Patterns importants qui devraient être dans .gitignore
		important_patterns = [
			'.env',
			'*.log',
			'node_modules/',
			'__pycache__/',
			'*.pyc',
		]

		try:
			with open(gitignore_path, 'r', encoding='utf-8') as f:
				gitignore_content = f.read()

			missing_patterns = []
			for pattern in important_patterns:
				if pattern not in gitignore_content:
					missing_patterns.append(pattern)

			if missing_patterns:
				self.alerts.append({
					"type": "incomplete_gitignore",
					"severity": "low",
					"file": ".gitignore",
					"message": f"Patterns manquants: {', '.join(missing_patterns)}"
				})

		except:
			pass

	def check_dependencies_versions(self, dependencies):
		"""
		Vérifie si des dépendances Python sont obsolètes (basique).

		Args:
			dependencies: Dict des dépendances depuis analyzer
		"""
		console.print("[yellow]⏳ Vérification des dépendances...[/yellow]")

		if "python" not in dependencies:
			return

		# On va juste vérifier quelques packages connus avec des vulnérabilités
		vulnerable_packages = {
			"django": {"min_safe": "4.2", "reason": "Versions < 4.2 ont des CVE"},
			"requests": {"min_safe": "2.31.0", "reason": "Versions < 2.31 ont des CVE"},
			"flask": {"min_safe": "2.3.0", "reason": "Versions anciennes ont des CVE"},
			"pillow": {"min_safe": "10.0.0", "reason": "Vulnérabilités image parsing"},
		}

		for dep in dependencies["python"]:
			# Parser "package==version" ou "package>=version"
			if "==" in dep:
				pkg_name, version = dep.split("==")
			elif ">=" in dep:
				pkg_name, version = dep.split(">=")
			else:
				continue  # Pas de version spécifiée

			pkg_name = pkg_name.strip().lower()

			if pkg_name in vulnerable_packages:
				min_safe = vulnerable_packages[pkg_name]["min_safe"]
				reason = vulnerable_packages[pkg_name]["reason"]

				# Comparaison simplifiée de versions (pas robuste mais suffisant)
				if self._version_is_older(version, min_safe):
					self.alerts.append({
						"type": "outdated_dependency",
						"severity": "medium",
						"package": pkg_name,
						"current_version": version,
						"min_safe_version": min_safe,
						"message": f"{pkg_name} {version} est obsolète. {reason}"
					})

	def _version_is_older(self, version1, version2):
		"""
		Compare deux versions (très simplifiée).

		Returns:
			bool: True si version1 < version2
		"""
		try:
			v1_parts = [int(x) for x in version1.split('.')]
			v2_parts = [int(x) for x in version2.split('.')]

			# Comparer chaque partie
			for v1, v2 in zip(v1_parts, v2_parts):
				if v1 < v2:
					return True
				elif v1 > v2:
					return False

			# Si égales jusqu'ici, la plus courte est plus vieille
			return len(v1_parts) < len(v2_parts)

		except:
			return False  # En cas d'erreur, on assume que c'est ok