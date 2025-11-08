"""
Analyse locale d'un repository cloné ou local.
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
	"""Analyse la structure d'un repo cloné ou local."""

	def __init__(self, clone_url, repo_name, local_path=None):
		"""
		Args:
			clone_url: URL de clone (depuis l'API) - None pour local
			repo_name: Nom du repo (pour le dossier)
			local_path: Chemin local du projet (None pour GitHub)
		"""
		self.clone_url = clone_url
		self.repo_name = repo_name
		self.local_path = local_path
		self.temp_dir = None

		# Determine if this is local or needs cloning
		if local_path:
			self.repo_path = os.path.abspath(local_path)
			self.is_local = True
		else:
			self.repo_path = None
			self.is_local = False

	def prepare(self):
		"""Prepare the repository for analysis (validate local path)."""
		if not self.is_local:
			# Should use clone_repo() instead
			return False

		# Validate local path exists
		if not os.path.exists(self.repo_path):
			console.print(f"[red]✗ Local path does not exist: {self.repo_path}[/red]")
			return False

		if not os.path.isdir(self.repo_path):
			console.print(f"[red]✗ Path is not a directory: {self.repo_path}[/red]")
			return False

		console.print(f"[green]✓[/green] Using local directory: {self.repo_path}")
		return True

	def clone_repo(self):
		"""Clone le repo dans un dossier temporaire (GitHub only)."""
		if self.is_local:
			console.print(f"[green]✓[/green] Using local directory: {self.repo_path}")
			return True

		try:
			self.temp_dir = tempfile.mkdtemp(prefix="gh_analyzer_")
			self.repo_path = os.path.join(self.temp_dir, self.repo_name)

			console.print(f"[yellow]⏳ Cloning repository (shallow)...[/yellow]")

			# Clone shallow (depth=1) = seulement le dernier commit
			# Plus rapide et moins lourd
			Repo.clone_from(
				self.clone_url,
				self.repo_path,
				depth=1,  # Seulement le dernier commit
				single_branch=True  # Seulement la branche principale
			)

			console.print(f"[green]✓[/green] Cloned to {self.temp_dir}")
			return True

		except Exception as e:
			console.print(f"[red]✗ Clone error: {e}[/red]")
			return False

	def analyze_structure(self):
		"""
		Analyse la structure du repo.

		Returns:
			dict: Statistiques sur la structure
		"""
		if not self.repo_path or not os.path.exists(self.repo_path):
			return {}

		console.print("[yellow]⏳ Analyzing structure...[/yellow]")

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

		console.print(f"[green]✓[/green] Structure analyzed: {stats['total_files']:,} files")

		return stats

	def find_dependencies(self):
		"""
		Trouve et parse les fichiers de dépendances.

		Returns:
			dict: {"python": [...], "nodejs": [...], ...}
		"""
		if not self.repo_path:
			return {}

		console.print("[yellow]⏳ Searching for dependencies...[/yellow]")

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
				console.print(f"[green]✓[/green] Found Python dependencies: {len(deps['python'])} packages")
			except Exception as e:
				console.print(f"[yellow]⚠[/yellow] Error reading requirements.txt: {e}")

		# Node.js - package.json
		pkg_file = os.path.join(self.repo_path, "package.json")
		if os.path.exists(pkg_file):
			try:
				import json
				with open(pkg_file, 'r', encoding='utf-8') as f:
					data = json.load(f)
					node_deps = list(data.get("dependencies", {}).keys())[:10]
					if node_deps:
						deps["nodejs"] = node_deps
						console.print(f"[green]✓[/green] Found Node.js dependencies: {len(deps['nodejs'])} packages")
			except Exception as e:
				console.print(f"[yellow]⚠[/yellow] Error reading package.json: {e}")

		if not deps:
			console.print("[dim]ℹ No dependency files found[/dim]")

		return deps

	def cleanup(self):
		"""Supprime le dossier temporaire (GitHub only)."""
		if self.is_local:
			# NEVER delete local directories!
			console.print(f"[dim]✓ Local analysis - no cleanup needed[/dim]")
			return

		# Only cleanup temporary cloned repos
		if self.temp_dir and os.path.exists(self.temp_dir):
			try:
				shutil.rmtree(self.temp_dir)
				console.print(f"[dim]✓ Cleanup complete[/dim]")
			except Exception as e:
				console.print(f"[yellow]⚠ Cleanup error: {e}[/yellow]")