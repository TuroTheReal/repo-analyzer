"""
Génération de rapports d'analyse.
"""

import os
from datetime import datetime
from pathlib import Path

class ReportGenerator:
	"""Génère des rapports d'analyse en différents formats."""

	def __init__(self, output_dir="output"):
		"""
		Args:
			output_dir: Dossier où sauvegarder les rapports
		"""
		self.output_dir = output_dir

		# Créer le dossier s'il n'existe pas
		Path(output_dir).mkdir(exist_ok=True)

	def generate_markdown(self, owner, repo, repo_info, languages,
						contributors, structure, dependencies, security_results):
		"""
		Génère un rapport complet en Markdown.
		Returns:
			str: Chemin du fichier généré
		"""
  
		timestamp = datetime.now().strftime("%Y-%m-%d")
		filename = f"{repo}-{timestamp}.md"
		filepath = os.path.join(self.output_dir, filename)

		# Construire le contenu markdown
		md_content = self._build_markdown_content(
			owner, repo, repo_info, languages, contributors,
			structure, dependencies, security_results
		)

		# Écrire le fichier
		with open(filepath, 'w', encoding='utf-8') as f:
			f.write(md_content)

		return filepath

	def _build_markdown_content(self, owner, repo, repo_info, languages,
								contributors, structure, dependencies, security_results):
		"""Construit le contenu markdown."""

		# Header
		md = f"# Analyse de {owner}/{repo}\n\n"
		md += f"**Généré le :** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
		md += f"**URL :** https://github.com/{owner}/{repo}\n\n"
		md += "---\n\n"

		# Table des matières
		md += "## 📑 Table des matières\n\n"
		md += "- [Métadonnées](#métadonnées)\n"
		md += "- [Langages](#langages)\n"
		md += "- [Contributors](#contributors)\n"
		md += "- [Structure](#structure)\n"
		md += "- [Dépendances](#dépendances)\n"
		md += "- [Sécurité](#sécurité)\n"
		md += "- [Recommandations](#recommandations)\n\n"
		md += "---\n\n"

		# Métadonnées
		md += "## 📊 Métadonnées\n\n"
		md += f"**Nom complet :** {repo_info['full_name']}\n\n"
		md += f"**Description :** {repo_info['description']}\n\n"

		md += "| Métrique | Valeur |\n"
		md += "|----------|--------|\n"
		md += f"| ⭐ Stars | {repo_info['stars']:,} |\n"
		md += f"| 🍴 Forks | {repo_info['forks']:,} |\n"
		md += f"| 👀 Watchers | {repo_info['watchers']:,} |\n"
		md += f"| 📝 Issues ouvertes | {repo_info['open_issues']} |\n"
		md += f"| ⚖️ License | {repo_info['license']} |\n"
		md += f"| 📅 Créé le | {repo_info['created_at'][:10]} |\n"
		md += f"| 🔄 Dernière màj | {repo_info['updated_at'][:10]} |\n"
		md += f"| 🌿 Branche par défaut | {repo_info['default_branch']} |\n"
		md += f"| 💾 Taille | {repo_info['size'] / 1024:.1f} MB |\n\n"

		# Langages
		if languages:
			md += "## 🔧 Langages\n\n"
			md += "```\n"
			for lang, percent in languages.items():
				bar_length = int(percent / 2)  # 1 char = 2%
				bar = "█" * bar_length
				md += f"{lang:<15} {bar} {percent}%\n"
			md += "```\n\n"

		# Contributors
		if contributors:
			md += "## 👥 Contributors\n\n"
			md += "Top 5 contributeurs :\n\n"
			md += "| Rang | Contributeur | Commits |\n"
			md += "|------|--------------|----------|\n"
			for i, contrib in enumerate(contributors[:5], 1):
				md += f"| {i} | [{contrib['login']}](https://github.com/{contrib['login']}) | {contrib['contributions']:,} |\n"
			md += "\n"

		# Structure
		md += "## 📁 Structure\n\n"
		md += "### Statistiques générales\n\n"
		md += f"- **Fichiers totaux :** {structure.get('total_files', 0):,}\n"
		md += f"- **Dossiers :** {structure.get('total_dirs', 0):,}\n"
		md += f"- **Profondeur max :** {structure.get('max_depth', 0)} niveaux\n\n"

		md += "### Fonctionnalités détectées\n\n"
		md += f"- **Tests :** {'✅ Présents' if structure.get('has_tests') else '❌ Absents'}\n"
		md += f"- **CI/CD :** {'✅ Configuré' if structure.get('has_ci') else '❌ Non configuré'}\n"
		md += f"- **Docker :** {'✅ Présent' if structure.get('has_docker') else '❌ Absent'}\n\n"

		# Fichiers importants
		if structure.get('important_files'):
			md += "### Fichiers importants détectés\n\n"
			for f in sorted(structure['important_files']):
				md += f"- ✅ `{f}`\n"
			md += "\n"

		# Types de fichiers
		if structure.get('file_types'):
			md += "### Distribution des types de fichiers\n\n"
			md += "| Extension | Nombre |\n"
			md += "|-----------|--------|\n"
			for ext, count in list(structure['file_types'].items())[:15]:
				md += f"| `{ext}` | {count} |\n"
			md += "\n"

		# Dépendances
		if dependencies:
			md += "## 📦 Dépendances\n\n"
			for dep_type, deps in dependencies.items():
				md += f"### {dep_type.capitalize()}\n\n"
				if deps:
					for dep in deps:
						md += f"- `{dep}`\n"
					md += "\n"
				else:
					md += "*Aucune dépendance détectée*\n\n"

		# Sécurité
		md += "## 🔒 Sécurité\n\n"

		total_issues = security_results['total']

		if total_issues == 0:
			md += "✅ **Aucun problème de sécurité détecté !**\n\n"
			md += "Le scan n'a trouvé aucun secret exposé, fichier sensible ou dépendance obsolète.\n\n"
		else:
			md += f"⚠️ **{total_issues} problème(s) détecté(s)**\n\n"

			# Résumé par sévérité
			md += "### Résumé\n\n"
			md += "| Sévérité | Nombre |\n"
			md += "|----------|--------|\n"
			md += f"| 🔴 Critique | {len(security_results['critical'])} |\n"
			md += f"| 🟠 Élevée | {len(security_results['high'])} |\n"
			md += f"| 🟡 Moyenne | {len(security_results['medium'])} |\n"
			md += f"| 🔵 Basse | {len(security_results['low'])} |\n\n"

			# Détails par sévérité
			severity_names = {
				"critical": "🔴 Critique",
				"high": "🟠 Élevée",
				"medium": "🟡 Moyenne",
				"low": "🔵 Basse"
			}

			for severity in ["critical", "high", "medium", "low"]:
				alerts = security_results.get(severity, [])
				if not alerts:
					continue

				md += f"### {severity_names[severity]} ({len(alerts)})\n\n"

				for alert in alerts:
					if alert["type"] == "secret_exposed":
						md += f"**Secret détecté : {alert['secret_type'].replace('_', ' ').title()}**\n\n"
						md += f"- **Fichier :** `{alert['file']}:{alert['line']}`\n"
						md += f"- **Aperçu :** `{alert['preview'][:80]}...`\n\n"

					elif alert["type"] == "sensitive_file":
						md += f"**Fichier sensible : `{alert['file']}`**\n\n"
						md += f"- {alert['message']}\n\n"

					elif alert["type"] == "outdated_dependency":
						md += f"**Dépendance obsolète : {alert['package']}**\n\n"
						md += f"- **Version actuelle :** {alert['current_version']}\n"
						md += f"- **Version recommandée :** >={alert['min_safe_version']}\n"
						md += f"- **Raison :** {alert['message']}\n\n"

					else:
						md += f"**{alert.get('message', 'Alerte')}**\n\n"
						if 'file' in alert:
							md += f"- **Fichier :** `{alert['file']}`\n\n"

		# Recommandations
		md += "## 💡 Recommandations\n\n"
		recommendations = self._generate_recommendations(structure, security_results, dependencies)

		if recommendations:
			for i, rec in enumerate(recommendations, 1):
				md += f"{i}. {rec}\n"
			md += "\n"
		else:
			md += "✅ Aucune recommandation particulière. Le projet semble bien configuré !\n\n"

		# Footer
		md += "---\n\n"
		md += "*Rapport généré automatiquement par [GitHub Repository Analyzer](https://github.com/TuroTheReal/repo-analyzer)*\n"

		return md

	def _generate_recommendations(self, structure, security_results, dependencies):
		"""Génère des recommandations basées sur l'analyse."""
		recommendations = []

		# Tests
		if not structure.get('has_tests'):
			recommendations.append("**Ajouter des tests** : Aucun dossier de tests détecté. Considérez pytest (Python) ou Jest (JS).")

		# CI/CD
		if not structure.get('has_ci'):
			recommendations.append("**Configurer CI/CD** : Automatisez vos tests avec GitHub Actions ou GitLab CI.")

		# Docker
		if not structure.get('has_docker'):
			recommendations.append("**Containeriser l'application** : Ajoutez un Dockerfile pour faciliter le déploiement.")

		# Sécurité
		if security_results['total'] > 0:
			if security_results['critical'] or security_results['high']:
				recommendations.append("**🚨 URGENT : Corriger les problèmes de sécurité critiques/élevés** avant de continuer.")

			if any(a['type'] == 'secret_exposed' for a in security_results['critical'] + security_results['high']):
				recommendations.append("**Révoquer les secrets exposés** : Changez immédiatement les tokens/passwords détectés.")

		# Dépendances
		if dependencies:
			recommendations.append("**Mettre à jour les dépendances régulièrement** : Utilisez `pip-audit` (Python) ou `npm audit` (Node).")

		# Documentation
		if 'CONTRIBUTING.md' not in structure.get('important_files', []):
			recommendations.append("**Ajouter CONTRIBUTING.md** : Guidez les contributeurs potentiels.")

		return recommendations