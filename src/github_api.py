"""
Interactions avec l'API GitHub.
"""

import requests
import os
from rich.console import Console

console = Console()

class GitHubAPI:
	"""Classe pour interagir avec l'API GitHub."""

	BASE_URL = "https://api.github.com"

	def __init__(self):
		"""Initialise avec un token."""
		# Token GitHub depuis variable d'environnement
		self.token = os.getenv("GITHUB_TOKEN")
		self.headers = {}

		if self.token:
			self.headers["Authorization"] = f"token {self.token}"
			console.print("[green]✓[/green] Token GitHub détecté")
		else:
			console.print("[yellow]⚠[/yellow] Pas de token (rate limit: 60 req/h)")

	def get_repo_info(self, owner, repo):
		"""
		Récupère les infos générales d'un repo.

		Returns:
			dict: Métadonnées du repo ou None si erreur
		"""

		url = f"{self.BASE_URL}/repos/{owner}/{repo}"

		try:
			response = requests.get(url, headers=self.headers, timeout=10)

			if response.status_code == 404:
				console.print(f"[red]✗[/red] Repo {owner}/{repo} introuvable")
				return None
			elif response.status_code == 403:
				console.print("[red]✗[/red] Rate limit dépassé. Utilisez un token GitHub")
				return None
			elif response.status_code != 200:
				console.print(f"[red]✗[/red] Erreur API: {response.status_code}")
				return None

			data = response.json()

			return {
				"name": data["name"],
				"full_name": data["full_name"],
				"description": data.get("description", "Pas de description"),
				"stars": data["stargazers_count"],
				"forks": data["forks_count"],
				"watchers": data["watchers_count"],
				"open_issues": data["open_issues_count"],
				"language": data.get("language", "Non spécifié"),
				"created_at": data["created_at"],
				"updated_at": data["updated_at"],
				"license": data["license"]["name"] if data.get("license") else "Aucune",
				"default_branch": data["default_branch"],
				"size": data["size"],  # En KB
				"clone_url": data["clone_url"]
			}

		except requests.exceptions.Timeout:
			console.print("[red]✗[/red] Timeout API")
			return None

		except requests.exceptions.RequestException as e:
			console.print(f"[red]✗[/red] Erreur réseau: {e}")
			return None

	def get_languages(self, owner, repo):
		"""
		Récupère les langages utilisés avec pourcentages.

		Returns:
			dict: {"Python": 45.2, "JavaScript": 30.1, ...}
		"""

		url = f"{self.BASE_URL}/repo/{owner}/{repo}/languages"

		try:
			response = requests.get(url, headers=self.headers, timeout=10)

			if response.status_code != 200:
				return {}

			data = response.json()

			# Calc %
			total_bytes = sum(data.values())
			if total_bytes == 0:
				return{}

			percentages = {
				lang: round((bytes_count / total_bytes) * 100, 1)
				for lang, bytes_count in data.items()
			}

			return dict(sorted(percentages.items(), key=lambda x: x[1], reverse=True))

		except Exception as e:
			console.print(f"[yellow]⚠[/yellow] Erreur langages: {e}")
			return {}

	def get_contributors(self, owner, repo, limit=5):
		"""
		Récupère les top contributors.

		Returns:
			list: [{"login": "torvalds", "contributions": 1234}, ...]
		"""

		url = f"{self.BASE_URL}/repos/{owner}/{repo}/contributors"

		try:
			response = requests.get(
				url,
				headers=self.headers,
				params={"per_page": limit},
				timeout=10
			)

			if response.status_code != 200:
				return[]

			data = response.json()

			return [
				{
					"login": contributor["login"],
					"contributions": contributor["contributions"]
				}
				for contributor in data[:limit]
			]

		except Exception as e:
			console.print(f"[yellow]⚠[/yellow] Erreur contributors: {e}")
			return []