"""
Basic security checks on a repository.
"""

import os
import re
from pathlib import Path
from rich.console import Console

console = Console()

class SecurityScanner:
	"""Security scanner to detect common issues."""

	# Regex patterns to detect secrets
	SECRET_PATTERNS = {
		"aws_access_key": r'AKIA[0-9A-Z]{16}',
		"aws_secret_key": r'aws_secret_access_key\s*=\s*["\']?([A-Za-z0-9/+=]{40})["\']?',
		"github_token": r'gh[pousrt]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}',
		"github_app_token": r'(ghu|ghs|ghr)_[A-Za-z0-9]{36,}',
		"generic_api_key": r'api[_-]?key\s*[=:]\s*["\']([A-Za-z0-9_\-]{20,})["\']',
		"generic_secret": r'secret\s*[=:]\s*["\']([A-Za-z0-9_\-]{20,})["\']',
		"password": r'password\s*[=:]\s*["\']([^"\']{8,})["\']',
		"private_key": r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
		"slack_token": r'xox[baprs]-[0-9a-zA-Z]{10,48}',
		"stripe_key": r'sk_live_[0-9a-zA-Z]{24,}',
		"google_api": r'AIza[0-9A-Za-z\\-_]{35}',
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

	# Sensitive files that shouldn't be committed
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

	# File extensions to ignore (binaries, media, etc.)
	IGNORED_EXTENSIONS = {
		'.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg',
		'.mp4', '.mov', '.avi', '.mp3', '.wav',
		'.zip', '.tar', '.gz', '.rar', '.7z',
		'.exe', '.dll', '.so', '.dylib',
		'.pdf', '.doc', '.docx', '.xls', '.xlsx',
		'.pyc', '.pyo', '.class', '.o', '.a',
		'.min.js', '.min.css',
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

	def _scan_secrets(self):
		"""Scan all text files for secrets."""
		scanned_files = 0
		max_files = 500  # Limit to avoid scanning huge repos too long

		for root, dirs, files in os.walk(self.repo_path):
			# Ignore .git, node_modules, etc.
			dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', 'venv', '__pycache__']]

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

				# Ignore large files (>1MB)
				try:
					if os.path.getsize(file_path) > 1_000_000:
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

						# Mask the secret value
						secret_value = match.group(0)
						masked_value = secret_value[:8] + "***" if len(secret_value) > 8 else "***"

						# Determine severity
						severity = "critical"
						if secret_type in ["password", "generic_secret"]:
							# Might be a false positive (e.g., password = "")
							if len(secret_value) < 15:
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
		Check if Python dependencies are outdated (basic).

		Args:
			dependencies: Dict of dependencies from analyzer
		"""
		console.print("[yellow]⏳ Checking dependencies...[/yellow]")

		if "python" not in dependencies:
			return

		# Check some known packages with vulnerabilities
		vulnerable_packages = {
			"django": {"min_safe": "4.2", "reason": "Versions < 4.2 have CVEs"},
			"requests": {"min_safe": "2.31.0", "reason": "Versions < 2.31 have CVEs"},
			"flask": {"min_safe": "2.3.0", "reason": "Old versions have CVEs"},
			"pillow": {"min_safe": "10.0.0", "reason": "Image parsing vulnerabilities"},
		}

		for dep in dependencies["python"]:
			# Parse "package==version" or "package>=version"
			if "==" in dep:
				pkg_name, version = dep.split("==")
			elif ">=" in dep:
				pkg_name, version = dep.split(">=")
			else:
				continue  # No version specified

			pkg_name = pkg_name.strip().lower()

			if pkg_name in vulnerable_packages:
				min_safe = vulnerable_packages[pkg_name]["min_safe"]
				reason = vulnerable_packages[pkg_name]["reason"]

				# Simplified version comparison (not robust but sufficient)
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
		Compare two versions (very simplified).

		Returns:
			bool: True if version1 < version2
		"""
		try:
			v1_parts = [int(x) for x in version1.split('.')]
			v2_parts = [int(x) for x in version2.split('.')]

			# Compare each part
			for v1, v2 in zip(v1_parts, v2_parts):
				if v1 < v2:
					return True
				elif v1 > v2:
					return False

			# If equal so far, shorter is older
			return len(v1_parts) < len(v2_parts)

		except:
			return False  # On error, assume it's ok
