"""
Unified security score calculator with unbiased Docker scoring.

IMPROVEMENTS:
- Fixed Docker scoring bias (projects without Docker no longer get free points)
- Named constants instead of magic numbers
- Full English comments
- Configurable weights
"""

# === SCORING CONSTANTS ===
# Component weights (must sum to 1.0)
WEIGHT_SECURITY = 0.5  # 50%
WEIGHT_DOCKER = 0.3  # 30%
WEIGHT_BEST_PRACTICES = 0.2  # 20%

# Severity penalties (deducted from base score of 100)
PENALTY_CRITICAL = 15
PENALTY_HIGH = 8
PENALTY_MEDIUM = 4
PENALTY_LOW = 1
PENALTY_INFO = 0.5

# Best practices points
POINTS_TESTS = 30
POINTS_CI_CD = 25
POINTS_GITIGNORE = 20
POINTS_NO_SECRETS = 25

# Docker neutral score (when no Docker files present)
DOCKER_NEUTRAL_SCORE = 70  # More fair: slightly positive but not perfect

class SecurityScoreCalculator:
	"""
	Calculates unified security score from all scan results.
	Works with both GitHub repos and local projects.
	"""

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
				'low': len(docker_results['low'])
			},
			'best_practices': {
				'score': best_practices_score,
				'weight': int(WEIGHT_BEST_PRACTICES * 100)
			}
		}

		# Description with note if local analysis
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
		Base score 100, deduct points for each issue.

		Returns:
			int: Score 0-100
		"""
		score = 100

		# Deduct penalties by severity
		score -= len(security_results['critical']) * PENALTY_CRITICAL
		score -= len(security_results['high']) * PENALTY_HIGH
		score -= len(security_results['medium']) * PENALTY_MEDIUM
		score -= len(security_results['low']) * PENALTY_LOW

		return max(0, score)

	def _calculate_docker_score(self, docker_results):
		"""
		Calculate Docker score out of 100 (FIXED: unbiased scoring).

		Scoring logic:
		- No Docker files: Neutral score (70/100) - not penalized, not rewarded
		- Has Docker files with no issues: Perfect (100/100)
		- Has Docker files with issues: Deduct points based on severity

		Returns:
			int: Score 0-100
		"""
		has_docker_files = docker_results['dockerfiles'] or docker_results['compose_files']

		# If no Docker files, give neutral score
		if not has_docker_files:
			return DOCKER_NEUTRAL_SCORE

		# Has Docker files - start at 100 and deduct for issues
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
		Sum of points for each practice followed.

		Returns:
			int: Score 0-100
		"""
		score = 0

		# Tests present (+30 points)
		if structure.get('has_tests'):
			score += POINTS_TESTS

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

		return score

	def _calculate_grade(self, score):
		"""
		Return letter grade based on score.

		Args:
			score: Numeric score 0-100

		Returns:
			str: Letter grade (A+ to F)
		"""
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
		"""
		Return human-readable description based on score.

		Args:
			score: Numeric score 0-100

		Returns:
			str: Description
		"""
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