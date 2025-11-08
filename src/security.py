"""
Basic security checks on a repository.
"""

import os
import re
import math
from pathlib import Path
from collections import Counter
from rich.console import Console

console = Console()

class SecurityScanner:
	"""Security scanner to detect common issues."""

	# Extended secret patterns - Cloud providers
	SECRET_PATTERNS = {
		# AWS
		"aws_access_key": r'AKIA[0-9A-Z]{16}',
		"aws_secret_key": r'aws_secret_access_key\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?',
		"aws_session_token": r'aws_session_token\s*[=:]\s*["\']?([A-Za-z0-9/+=]{16,})["\']?',

		# Azure
		"azure_storage_key": r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}',

		# Google Cloud
		"google_api": r'AIza[0-9A-Za-z\\-_]{35}',
		"gcp_service_account": r'"type":\s*"service_account"',

		# DigitalOcean & Heroku
		"digitalocean_token": r'dop_v1_[a-f0-9]{64}',
		"heroku_api_key": r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',

		# GitHub & GitLab
		"github_token": r'gh[pousrt]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}',
		"github_app_token": r'(ghu|ghs|ghr)_[A-Za-z0-9]{36,}',
		"github_refresh_token": r'ghr_[A-Za-z0-9]{36,}',
		"gitlab_token": r'glpat-[A-Za-z0-9\-_]{20,}',

		# Communication platforms
		"slack_token": r'xox[baprs]-[0-9a-zA-Z]{10,48}',
		"slack_webhook": r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{24}',
		"discord_token": r'[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}',
		"discord_webhook": r'https://discord\.com/api/webhooks/\d+/[\w-]+',
		"telegram_bot_token": r'\d{8,10}:[A-Za-z0-9_-]{35}',

		# Payment services
		"stripe_key": r'sk_live_[0-9a-zA-Z]{24,}',
		"stripe_restricted_key": r'rk_live_[0-9a-zA-Z]{24,}',
		"paypal_braintree": r'access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}',
		"square_token": r'sq0atp-[0-9A-Za-z\-_]{22}',

		# Databases
		"mongodb_uri": r'mongodb(\+srv)?://[^:]+:[^@]+@[^/]+',
		"postgres_uri": r'postgres(ql)?://[^:]+:[^@]+@[^/]+',
		"mysql_uri": r'mysql://[^:]+:[^@]+@[^/]+',
		"redis_uri": r'redis://[^:]*:[^@]+@[^/]+',

		# Email & Communication APIs
		"sendgrid_api_key": r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}',
		"twilio_api_key": r'SK[a-f0-9]{32}',
		"mailgun_api_key": r'key-[a-f0-9]{32}',
		"mailchimp_api_key": r'[a-f0-9]{32}-us\d{1,2}',

		# Other services
		"firebase_api_key": r'AIza[0-9A-Za-z\-_]{35}',
		"cloudinary_url": r'cloudinary://[0-9]+:[A-Za-z0-9_-]+@[a-z]+',

		# Authentication
		"jwt_token": r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*',
		"basic_auth": r'://[^:/@]+:[^@/]+@',

		# Private keys & certificates
		"private_key": r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
		"pgp_private_key": r'-----BEGIN PGP PRIVATE KEY BLOCK-----',

		# Generic patterns
		"generic_api_key": r'api[_-]?key\s*[=:]\s*["\']([A-Za-z0-9_\-]{20,})["\']',
		"generic_secret": r'secret\s*[=:]\s*["\']([A-Za-z0-9_\-]{20,})["\']',
		"password": r'password\s*[=:]\s*["\']([^"\']{8,})["\']',
		"generic_token": r'token\s*[=:]\s*["\']([A-Za-z0-9_\-]{20,})["\']',

		# Package managers
		"npm_token": r'npm_[A-Za-z0-9]{36}',
		"pypi_token": r'pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}',
	}

	# Patterns for dynamic variables (SAFE - not real secrets)
	DYNAMIC_VAR_PATTERNS = [
		r'\$\{[^}]+\}',                    # ${VAR}, ${ENV_PASSWORD}
		r'\$[A-Z_][A-Z0-9_]*',             # $VAR, $PASSWORD
		r'\{\{[^}]+\}\}',                  # {{VAR}}, Ansible/Jinja2
		r'%[A-Z_][A-Z0-9_]*%',             # %VAR%, Windows
		r'os\.getenv\(["\'][^"\']+["\']\)', # os.getenv('VAR')
		r'process\.env\.[A-Z_][A-Z0-9_]*', # process.env.VAR
		r'ENV\[["\'][^"\']+["\']\]',       # ENV['VAR'], Ruby
		r'System\.getenv\(["\'][^"\']+["\']\)', # Java
	]

	# False positive patterns
	FALSE_POSITIVE_PATTERNS = [
		r'example\.com',
		r'test[_-]?api[_-]?key',
		r'your[_-]?api[_-]?key',
		r'insert[_-]?key[_-]?here',
		r'replace[_-]?with[_-]?your',
		r'dummy[_-]?(key|token|secret)',
		r'fake[_-]?(key|token|secret)',
		r'placeholder',
		r'xxx+',
		r'000+',
		r'abc123',
		r'sample[_-]?key',
		r'<[A-Z_]+>',  # <API_KEY>
	]

	# Sensitive files that shouldn't be committed
	SENSITIVE_FILES = [
		".env",
		".env.local",
		".env.production",
		".env.development",
		"credentials.json",
		"secrets.yaml",
		"secrets.yml",
		"config/secrets.yml",
		"id_rsa",
		"id_dsa",
		"id_ecdsa",
		".ssh/id_rsa",
		"*.pem",
		"*.key",
		"*.p12",
		"*.pfx",
		".aws/credentials",
		".docker/config.json",
		"*.keystore",
		"*.jks",
	]

	# File extensions to ignore (binaries, media, etc.)
	IGNORED_EXTENSIONS = {
		'.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.webp',
		'.mp4', '.mov', '.avi', '.mp3', '.wav', '.flac',
		'.zip', '.tar', '.gz', '.rar', '.7z', '.bz2',
		'.exe', '.dll', '.so', '.dylib',
		'.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
		'.pyc', '.pyo', '.class', '.o', '.a',
		'.min.js', '.min.css', '.bundle.js',
		'.woff', '.woff2', '.ttf', '.eot',
	}

	def __init__(self, repo_path):
		"""
		Args:
			repo_path: Path to cloned repo
		"""
		self.repo_path = repo_path
		self.alerts = []

	def scan(self):
		"""
		Run all security scans.

		Returns:
			dict: Results with different severity levels
		"""
		console.print("[yellow]⏳ Running security scan...[/yellow]")

		self.alerts = []

		# Scan 1: Hardcoded secrets
		self._scan_secrets()

		# Scan 2: Sensitive files
		self._scan_sensitive_files()

		# Scan 3: Check .gitignore
		self._check_gitignore()

		# Organize by severity
		results = {
			"critical": [a for a in self.alerts if a["severity"] == "critical"],
			"high": [a for a in self.alerts if a["severity"] == "high"],
			"medium": [a for a in self.alerts if a["severity"] == "medium"],
			"low": [a for a in self.alerts if a["severity"] == "low"],
			"total": len(self.alerts)
		}

		console.print(f"[green]✓[/green] Scan complete: {results['total']} alerts")

		return results

	def _is_dynamic_variable(self, text):
		"""
		Check if text is a dynamic variable reference (not a real secret).

		Args:
			text: Text to check

		Returns:
			bool: True if it's a dynamic variable
		"""
		for pattern in self.DYNAMIC_VAR_PATTERNS:
			if re.search(pattern, text):
				return True
		return False

	def _is_likely_false_positive(self, text):
		"""Check if text matches common false positive patterns."""
		text_lower = text.lower()

		for pattern in self.FALSE_POSITIVE_PATTERNS:
			if re.search(pattern, text_lower):
				return True

		# Empty or very short values
		if len(text.strip()) < 10:
			return True

		# Only repeated characters
		if len(set(text)) <= 3:
			return True

		return False

	def _calculate_entropy(self, text):
		"""Calculate Shannon entropy to detect random strings (likely secrets)."""
		if not text:
			return 0

		counts = Counter(text)
		length = len(text)

		entropy = -sum(
			(count / length) * math.log2(count / length)
			for count in counts.values()
		)

		return entropy

	def _is_high_entropy_string(self, text, threshold=4.5):
		"""
		Detect high-entropy strings (possible secrets).
		threshold: typically 4.0-5.0 for detecting secrets
		"""
		if len(text) < 20:
			return False

		entropy = self._calculate_entropy(text)
		return entropy > threshold

	def _scan_secrets(self):
		"""Scan all text files for secrets."""
		scanned_files = 0
		max_files = 1000  # Increased limit

		for root, dirs, files in os.walk(self.repo_path):
			# Ignore .git, node_modules, etc.
			dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', 'venv', '__pycache__', 'vendor', 'dist', 'build']]

			if scanned_files >= max_files:
				break

			for file in files:
				if scanned_files >= max_files:
					break

				file_path = os.path.join(root, file)
				relative_path = os.path.relpath(file_path, self.repo_path)

				# Ignore by extension
				if Path(file).suffix in self.IGNORED_EXTENSIONS:
					continue

				# Ignore large files (>2MB)
				try:
					if os.path.getsize(file_path) > 2_000_000:
						continue
				except:
					continue

				# Scan the file
				self._scan_file_for_secrets(file_path, relative_path)
				scanned_files += 1

	def _scan_file_for_secrets(self, file_path, relative_path):
		"""Scan a specific file for secrets."""
		try:
			with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
				content = f.read()

				# Test each pattern
				for secret_type, pattern in self.SECRET_PATTERNS.items():
					matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)

					for match in matches:
						# Get line number
						line_num = content[:match.start()].count('\n') + 1

						# Extract full line
						lines = content.split('\n')
						line_content = lines[line_num - 1].strip() if line_num <= len(lines) else ""

						# CHECK: Is this a dynamic variable? If yes, SKIP
						if self._is_dynamic_variable(line_content):
							continue

						# CHECK: False positive?
						if self._is_likely_false_positive(line_content):
							continue

						# Mask the secret value
						secret_value = match.group(0)
						masked_value = secret_value[:8] + "***" if len(secret_value) > 8 else "***"

						# Determine severity
						severity = "critical"
						if secret_type in ["password", "generic_secret", "generic_token"]:
							# Check entropy for generic patterns
							if not self._is_high_entropy_string(secret_value):
								severity = "medium"

						self.alerts.append({
							"type": "secret_exposed",
							"severity": severity,
							"secret_type": secret_type,
							"file": relative_path,
							"line": line_num,
							"preview": line_content[:100],
							"message": f"{secret_type.replace('_', ' ').title()} detected"
						})

		except Exception as e:
			# Unreadable file, ignore
			pass

	def _scan_sensitive_files(self):
		"""Detect sensitive files that shouldn't be committed."""
		for root, dirs, files in os.walk(self.repo_path):
			dirs[:] = [d for d in dirs if d != '.git']

			for file in files:
				file_path = os.path.join(root, file)
				relative_path = os.path.relpath(file_path, self.repo_path)

				# Check if it's a sensitive file
				for sensitive_pattern in self.SENSITIVE_FILES:
					# Support basic wildcards
					if '*' in sensitive_pattern:
						pattern = sensitive_pattern.replace('*', '.*')
						if re.match(pattern, file):
							self.alerts.append({
								"type": "sensitive_file",
								"severity": "high",
								"file": relative_path,
								"message": f"Sensitive file detected: {file}"
							})
					else:
						if file == sensitive_pattern or relative_path.endswith(sensitive_pattern):
							self.alerts.append({
								"type": "sensitive_file",
								"severity": "high",
								"file": relative_path,
								"message": f"Sensitive file detected: {file}"
							})

	def _check_gitignore(self):
		"""Check if .gitignore exists and contains important patterns."""
		gitignore_path = os.path.join(self.repo_path, '.gitignore')

		if not os.path.exists(gitignore_path):
			self.alerts.append({
				"type": "missing_gitignore",
				"severity": "low",
				"file": ".gitignore",
				"message": "No .gitignore found"
			})
			return

		# Important patterns that should be in .gitignore
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
					"message": f"Missing patterns: {', '.join(missing_patterns)}"
				})

		except:
			pass

	def check_dependencies_versions(self, dependencies):
		"""
		Check if dependencies are outdated (basic check).
		For real vulnerability checking, see vulnerability_checker.py

		Args:
			dependencies: Dict of dependencies from analyzer
		"""
		console.print("[yellow]⏳ Checking dependencies...[/yellow]")

		if "python" not in dependencies:
			return

		# Basic known vulnerable packages (for offline check)
		vulnerable_packages = {
			"django": {"min_safe": "4.2", "reason": "Versions < 4.2 have CVEs"},
			"requests": {"min_safe": "2.31.0", "reason": "Versions < 2.31 have CVEs"},
			"flask": {"min_safe": "2.3.0", "reason": "Old versions have CVEs"},
			"pillow": {"min_safe": "10.0.0", "reason": "Image parsing vulnerabilities"},
			"pyyaml": {"min_safe": "6.0", "reason": "Arbitrary code execution vulnerability"},
			"jinja2": {"min_safe": "3.1.0", "reason": "XSS vulnerabilities"},
			"cryptography": {"min_safe": "41.0.0", "reason": "Security vulnerabilities"},
		}

		for dep in dependencies["python"]:
			# Parse "package==version" or "package>=version"
			if "==" in dep:
				pkg_name, version = dep.split("==")
			elif ">=" in dep:
				pkg_name, version = dep.split(">=")
			else:
				continue

			pkg_name = pkg_name.strip().lower()

			if pkg_name in vulnerable_packages:
				min_safe = vulnerable_packages[pkg_name]["min_safe"]
				reason = vulnerable_packages[pkg_name]["reason"]

				if self._version_is_older(version, min_safe):
					self.alerts.append({
						"type": "outdated_dependency",
						"severity": "medium",
						"package": pkg_name,
						"current_version": version,
						"min_safe_version": min_safe,
						"message": f"{pkg_name} {version} is outdated. {reason}"
					})

	def _version_is_older(self, version1, version2):
		"""
		Compare two versions (simplified).

		Returns:
			bool: True if version1 < version2
		"""
		try:
			v1_parts = [int(x) for x in version1.split('.')]
			v2_parts = [int(x) for x in version2.split('.')]

			for v1, v2 in zip(v1_parts, v2_parts):
				if v1 < v2:
					return True
				elif v1 > v2:
					return False

			return len(v1_parts) < len(v2_parts)

		except:
			return False
