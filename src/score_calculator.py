"""
Unified security score calculator with enhanced weighting.

IMPROVEMENTS:
- Better test quality assessment
- Enhanced Docker scoring
- More nuanced best practices scoring
"""

# === SCORING CONSTANTS ===
WEIGHT_SECURITY = 0.5  # 50%
WEIGHT_DOCKER = 0.3  # 30%
WEIGHT_BEST_PRACTICES = 0.2  # 20%

# Severity penalties
PENALTY_CRITICAL = 15
PENALTY_HIGH = 8
PENALTY_MEDIUM = 4
PENALTY_LOW = 1
PENALTY_INFO = 0.5

# Best practices points (total = 100)
POINTS_TESTS_BASE = 20  # Base points for having tests
POINTS_TESTS_QUALITY = 10  # Additional points for quality
POINTS_CI_CD = 25
POINTS_GITIGNORE = 20
POINTS_NO_SECRETS = 25

# Docker neutral score
DOCKER_NEUTRAL_SCORE = 70

class SecurityScoreCalculator:
	"""Calculates unified security score from all scan results."""

	def calculate_unified_score(self, security_results, docker_results, structure, has_github_data=True):
		"""
		Calculate unified score out of 100.

		Args:
			security_results: Results from SecurityScanner
			docker_results: Results from DockerScanner
			structure: Repository structure info
			has_github_data: Boolean indicating if GitHub API data is available

		Returns:
			dict: Complete scoring breakdown
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
			security_score * WEIGHT_SECURITY +
			docker_score * WEIGHT_DOCKER +
			best_practices_score * WEIGHT_BEST_PRACTICES
		)

		total_score = round(max(0, min(100, total_score)))

		# Grade
		grade = self._calculate_grade(total_score)

		# Breakdown
		breakdown = {
			'security': {
				'score': security_score,
				'weight': int(WEIGHT_SECURITY * 100),
				'critical': len(security_results['critical']),
				'high': len(security_results['high']),
				'medium': len(security_results['medium']),
				'low': len(security_results['low'])
			},
			'docker': {
				'score': docker_score,
				'weight': int(WEIGHT_DOCKER * 100),
				'critical': len(docker_results['critical']),
				'high': len(docker_results['high']),
				'medium': len(docker_results['medium']),
				'low': len(docker_results['low']),
				'info': len(docker_results.get('info', []))
			},
			'best_practices': {
				'score': best_practices_score,
				'weight': int(WEIGHT_BEST_PRACTICES * 100)
			}
		}

		# Description
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
		"""
		Calculate security score out of 100.

		Enhanced: Weight critical issues more heavily.
		"""
		score = 100

		# Apply penalties
		score -= len(security_results['critical']) * PENALTY_CRITICAL
		score -= len(security_results['high']) * PENALTY_HIGH
		score -= len(security_results['medium']) * PENALTY_MEDIUM
		score -= len(security_results['low']) * PENALTY_LOW

		# Extra penalty if many critical issues
		if len(security_results['critical']) >= 3:
			score -= 10  # Additional penalty for multiple critical issues

		return max(0, score)

	def _calculate_docker_score(self, docker_results):
		"""
		Calculate Docker score out of 100.
		"""
		has_docker_files = docker_results['dockerfiles'] or docker_results['compose_files']

		# No Docker files = neutral score
		if not has_docker_files:
			return DOCKER_NEUTRAL_SCORE

		# Has Docker files - start at 100 and deduct
		score = 100

		score -= len(docker_results['critical']) * PENALTY_CRITICAL
		score -= len(docker_results['high']) * PENALTY_HIGH
		score -= len(docker_results['medium']) * PENALTY_MEDIUM
		score -= len(docker_results['low']) * PENALTY_LOW
		score -= len(docker_results.get('info', [])) * PENALTY_INFO

		return max(0, score)

	def _calculate_best_practices_score(self, security_results, structure):
		"""
		Calculate best practices score out of 100.

		Enhanced: Consider test quality.
		"""
		score = 0

		# Tests present (up to 30 points)
		if structure.get('has_tests'):
			score += POINTS_TESTS_BASE

			# Bonus for test quality
			test_quality = structure.get('test_quality', 'unknown')
			quality_bonus = {
				'extensive': 10,
				'good': 7,
				'basic': 4,
				'minimal': 2,
				'empty': 0,
				'unknown': 5
			}
			score += quality_bonus.get(test_quality, 5)

		# CI/CD configured (+25 points)
		if structure.get('has_ci'):
			score += POINTS_CI_CD

		# Proper .gitignore (+20 points)
		has_proper_gitignore = not any(
			a['type'] in ['incomplete_gitignore', 'missing_gitignore']
			for a in security_results['low']
		)
		if has_proper_gitignore:
			score += POINTS_GITIGNORE

		# No exposed secrets (+25 points)
		no_secrets = not any(
			a['type'] == 'secret_exposed'
			for a in security_results['critical'] + security_results['high']
		)
		if no_secrets:
			score += POINTS_NO_SECRETS

		return min(100, score)  # Cap at 100

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
		"""Return human-readable description based on score."""
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