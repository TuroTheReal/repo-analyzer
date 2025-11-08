"""
Unified security score calculator.
Takes into account security, Docker, and best practices.
Works with both GitHub repos and local projects.
"""

class SecurityScoreCalculator:
	"""Calculates a unified security score from all scan results."""

	def calculate_unified_score(self, security_results, docker_results, structure, has_github_data=True):
		"""
		Calculate unified score out of 100.

		Args:
			security_results: Results from SecurityScanner
			docker_results: Results from DockerScanner
			structure: Repository structure info
			has_github_data: Boolean indicating if GitHub API data is available

		Returns:
			dict: {
				'total_score': int,
				'grade': str,
				'security_score': int,
				'docker_score': int,
				'best_practices_score': int,
				'breakdown': dict,
				'description': str,
				'is_local_analysis': bool
			}
		"""
		# 1. Security score (50% weight)
		security_score = self._calculate_security_score(security_results)

		# 2. Docker score (30% weight)
		docker_score = self._calculate_docker_score(docker_results)

		# 3. Best practices score (20% weight)
		best_practices_score = self._calculate_best_practices_score(
			security_results, structure
		)

		# Calculate weighted total
		total_score = (
			security_score * 0.5 +
			docker_score * 0.3 +
			best_practices_score * 0.2
		)

		total_score = round(max(0, min(100, total_score)))

		# Grade
		grade = self._calculate_grade(total_score)

		# Breakdown
		breakdown = {
			'security': {
				'score': security_score,
				'weight': 50,
				'critical': len(security_results['critical']),
				'high': len(security_results['high']),
				'medium': len(security_results['medium']),
				'low': len(security_results['low'])
			},
			'docker': {
				'score': docker_score,
				'weight': 30,
				'critical': len(docker_results['critical']),
				'high': len(docker_results['high']),
				'medium': len(docker_results['medium']),
				'low': len(docker_results['low'])
			},
			'best_practices': {
				'score': best_practices_score,
				'weight': 20
			}
		}

		# Description avec note si analyse locale
		description = self._get_score_description(total_score)
		if not has_github_data:
			description += " (Local analysis - limited metadata)"

		return {
			'total_score': total_score,
			'grade': grade,
			'security_score': security_score,
			'docker_score': docker_score,
			'best_practices_score': best_practices_score,
			'breakdown': breakdown,
			'description': description,
			'is_local_analysis': not has_github_data
		}

	def _calculate_security_score(self, security_results):
		"""Calculate security score out of 100."""
		score = 100

		# Penalties by severity
		score -= len(security_results['critical']) * 15
		score -= len(security_results['high']) * 8
		score -= len(security_results['medium']) * 4
		score -= len(security_results['low']) * 1

		return max(0, score)

	def _calculate_docker_score(self, docker_results):
		"""Calculate Docker score out of 100."""
		# If no Docker files, neutral score
		if not docker_results['dockerfiles'] and not docker_results['compose_files']:
			return 50

		score = 100

		# Penalties by severity
		score -= len(docker_results['critical']) * 15
		score -= len(docker_results['high']) * 8
		score -= len(docker_results['medium']) * 4
		score -= len(docker_results['low']) * 1
		score -= len(docker_results.get('info', [])) * 0.5

		return max(0, score)

	def _calculate_best_practices_score(self, security_results, structure):
		"""Calculate best practices score out of 100."""
		score = 0

		# Tests present (+30 points)
		if structure.get('has_tests'):
			score += 30

		# CI/CD configured (+25 points)
		if structure.get('has_ci'):
			score += 25

		# Proper .gitignore (+20 points)
		has_proper_gitignore = not any(
			a['type'] in ['incomplete_gitignore', 'missing_gitignore']
			for a in security_results['low']
		)
		if has_proper_gitignore:
			score += 20

		# No exposed secrets (+25 points)
		no_secrets = not any(
			a['type'] == 'secret_exposed'
			for a in security_results['critical'] + security_results['high']
		)
		if no_secrets:
			score += 25

		return score

	def _calculate_grade(self, score):
		"""Return letter grade based on score."""
		if score >= 95:
			return 'A+'
		elif score >= 90:
			return 'A'
		elif score >= 85:
			return 'A-'
		elif score >= 80:
			return 'B+'
		elif score >= 75:
			return 'B'
		elif score >= 70:
			return 'B-'
		elif score >= 65:
			return 'C+'
		elif score >= 60:
			return 'C'
		elif score >= 55:
			return 'C-'
		elif score >= 50:
			return 'D'
		else:
			return 'F'

	def _get_score_description(self, score):
		"""Return description based on score."""
		if score >= 90:
			return "Excellent! Very few security issues detected."
		elif score >= 75:
			return "Good. Some improvements recommended."
		elif score >= 60:
			return "Average. Several issues need attention."
		elif score >= 40:
			return "Below average. Important issues to fix."
		else:
			return "⚠️ CRITICAL! Major security problems detected."