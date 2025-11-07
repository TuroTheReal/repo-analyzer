"""
Analyse locale d'un repository cloné.
"""

import os
import tempfile
import shutil
from pathlib import Path
from git import Repo
from rich.console import Console
from rich.progress import track

console = Console()

class RepoAnalyzer:
	"""Analyse la structure d'un repo cloné."""

	def __init__(self, clone_url, repo_name):
		"""
		Args:
			clone_url: URL de clone (depuis l'API)
			repo_name: Nom du repo (pour le dossier)
		"""

		self.clone_url = clone_url
		self.repo_name = repo_name
		self.temp_dir = None
		self.repo_path = None

	def clone_repo(self):
		"""Clone le repo dans un dossier temporaire."""

		try:
			self.temp_dir = tempfile.mkdtemp(prefix="gh_analyzer")
			self.repo_path = os.path.join(self.temp_dir, self.repo_name)

			console.print(f"[yellow]⏳ Clone du repo (shallow)...[/yellow]")

			# Clone shallow (depth=1) = seulement le dernier commit
			# Plus rapide et moins lourd
			Repo.clone_from(
				self.clone_url,
				self.repo_path,
				depth=1,  # Seulement le dernier commit
				single_branch=True  # Seulement la branche principale
			)


			console.print(f"[green]✓[/green] Cloné dans {self.temp_dir}")
			return True

		except Exception as e:
			console.print(f"[red]✗ Erreur clone: {e}[/red]")
			return False


	def analyze_structure(self):
		"""
		Analyse la structure du repo.

		Returns:
			dict: Statistiques sur la structure
		"""
		if not self.repo_path or not os.path.exists(self.repo_path):
			return {}

		console.print("[yellow]⏳ Analyse de la structure...[/yellow]")

		stats = {
			"important_files": [],
			"file_types": {},
			"total_files": 0,
			"total_dirs": 0,
			"max_depth": 0,
			"has_tests": False,
			"has_ci": False,
			"has_docker": False
		}

		# Fichiers importants à détecter
		important_files = [
			"README.md", "README.rst", "README.txt",
			"LICENSE", "LICENSE.md", "LICENSE.txt",
			"CONTRIBUTING.md",
			".gitignore",
			"Makefile",
			"Dockerfile", "docker-compose.yml",
			".github/workflows", ".gitlab-ci.yml", "Jenkinsfile",
			"requirements.txt", "setup.py", "pyproject.toml",
			"package.json", "Cargo.toml", "go.mod", "pom.xml"
		]

		# Parcourir tous les fichiers
		for root, dirs, files in os.walk(self.repo_path):
			# Ignorer .git
			if '.git' in root:
				continue

			# Calculer la profondeur
			depth = root.replace(self.repo_path, '').count(os.sep)
			stats["max_depth"] = max(stats["max_depth"], depth)

			stats["total_dirs"] += len(dirs)

			# Détecter dossiers spéciaux
			if 'test' in [d.lower() for d in dirs] or 'tests' in [d.lower() for d in dirs]:
				stats["has_tests"] = True

			for file in files:
				stats["total_files"] += 1

				# Extension
				ext = Path(file).suffix or "no_extension"
				stats["file_types"][ext] = stats["file_types"].get(ext, 0) + 1

				# Fichiers importants
				for important in important_files:
					if file == important or important in os.path.join(root, file):
						stats["important_files"].append(important)

						# Flags spéciaux
						if "docker" in important.lower():
							stats["has_docker"] = True
						if "workflow" in important or ".gitlab-ci" in important or "Jenkinsfile" in important:
							stats["has_ci"] = True

		# Dédupliquer fichiers importants
		stats["important_files"] = list(set(stats["important_files"]))

		# Trier les types de fichiers par fréquence
		stats["file_types"] = dict(
			sorted(stats["file_types"].items(), key=lambda x: x[1], reverse=True)
		)

		return stats

	def find_dependencies(self):
		"""
		Trouve et parse les fichiers de dépendances.

		Returns:
			dict: {"type": "python", "dependencies": [...]}
		"""
		if not self.repo_path:
			return {}

		console.print("[yellow]⏳ Recherche des dépendances...[/yellow]")

		deps = {}

		# Python - requirements.txt
		req_file = os.path.join(self.repo_path, "requirements.txt")
		if os.path.exists(req_file):
			try:
				with open(req_file, 'r', encoding='utf-8') as f:
					lines = f.readlines()
					deps["python"] = [
						line.strip()
						for line in lines
						if line.strip() and not line.startswith('#')
					][:10]  # Limiter à 10 pour l'affichage
			except:
				pass

		# Node.js - package.json
		pkg_file = os.path.join(self.repo_path, "package.json")
		if os.path.exists(pkg_file):
			try:
				import json
				with open(pkg_file, 'r', encoding='utf-8') as f:
					data = json.load(f)
					deps["nodejs"] = list(data.get("dependencies", {}).keys())[:10]
			except:
				pass


	def cleanup(self):
			"""Supprime le dossier temporaire."""
			if self.temp_dir and os.path.exists(self.temp_dir):
				try:
					shutil.rmtree(self.temp_dir)
					console.print(f"[dim]✓ Nettoyage terminé[/dim]")
				except Exception as e:
					console.print(f"[yellow]⚠ Erreur nettoyage: {e}[/yellow]")