"""
Enhanced security scanner with better false positive filtering and contextual analysis.

IMPROVEMENTS:
- Better context-aware secret detection
- Improved entropy calculation for generic patterns
- File extension validation
- Better .env file handling
- Integration with Trivy and dependency auditors
- Deduplication of vulnerability findings

CHANGEMENTS:
- Suppression des détections de vulnérabilités de dépendances (géré par Trivy + auditors)
- Focus sur la détection de secrets exposés et fichiers sensibles
"""

import os
import re
import math
from pathlib import Path
from collections import Counter
from rich.console import Console

console = Console()

# === CONSTANTS ===
MAX_FILES_TO_SCAN = 10000
MAX_FILE_SIZE_BYTES = 2_000_000
MAX_REPO_SIZE_BYTES = 500_000_000

ENTROPY_THRESHOLD_HIGH = 4.8
ENTROPY_THRESHOLD_MEDIUM = 4.5
ENTROPY_THRESHOLD_LOW = 4.0

PENALTY_CRITICAL = 15
PENALTY_HIGH = 8
PENALTY_MEDIUM = 4
PENALTY_LOW = 1

MIN_SECRET_LENGTH = 12

class SecurityScanner:
	"""Advanced security scanner for detecting secrets and sensitive files."""

	SECRET_PATTERNS = {
		# AWS
		"aws_access_key": r'\b(AKIA[0-9A-Z]{16})\b',
		"aws_secret_key": r'aws_secret_access_key\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?',
		"aws_session_token": r'aws_session_token\s*[=:]\s*["\']?([A-Za-z0-9/+=]{100,})["\']?',

		# Azure
		"azure_storage_key": r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=([A-Za-z0-9+/=]{88})',

		# Google Cloud
		"google_api": r'\b(AIza[0-9A-Za-z\-_]{35})\b',
		"gcp_service_account": r'"type":\s*"service_account"',

		# DigitalOcean
		"digitalocean_token": r'\b(dop_v1_[a-f0-9]{64})\b',

		# GitHub & GitLab
		"github_token": r'\b(gh[pousrt]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59})\b',
		"github_app_token": r'\b((ghu|ghs|ghr)_[A-Za-z0-9]{36,})\b',
		"gitlab_token": r'\b(glpat-[A-Za-z0-9\-_]{20,})\b',

		# Communication platforms
		"slack_token": r'\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b',
		"slack_webhook": r'(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{24})',
		"discord_token": r'\b([MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27})\b',
		"discord_webhook": r'(https://discord\.com/api/webhooks/\d+/[\w-]+)',
		"telegram_bot_token": r'\b(\d{8,10}:[A-Za-z0-9_-]{35})\b',

		# Payment services
		"stripe_key": r'\b(sk_live_[0-9a-zA-Z]{24,})\b',
		"stripe_restricted_key": r'\b(rk_live_[0-9a-zA-Z]{24,})\b',
		"paypal_braintree": r'\b(access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32})\b',
		"square_token": r'\b(sq0atp-[0-9A-Za-z\-_]{22})\b',

		# Databases
		"mongodb_uri": r'(mongodb(\+srv)?://[^:]+:[^@]+@[^/\s]+)',
		"postgres_uri": r'(postgres(ql)?://[^:]+:[^@]+@[^/\s]+)',
		"mysql_uri": r'(mysql://[^:]+:[^@]+@[^/\s]+)',
		"redis_uri": r'(redis://[^:]*:[^@]+@[^/\s]+)',

		# Email & Communication APIs
		"sendgrid_api_key": r'\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b',
		"twilio_api_key": r'\b(SK[a-f0-9]{32})\b',
		"mailgun_api_key": r'\b(key-[a-f0-9]{32})\b',
		"mailchimp_api_key": r'\b([a-f0-9]{32}-us\d{1,2})\b',

		# Other services
		"firebase_api_key": r'\b(AIza[0-9A-Za-z\-_]{35})\b',
		"cloudinary_url": r'(cloudinary://[0-9]+:[A-Za-z0-9_-]+@[a-z]+)',

		# Authentication
		"jwt_token": r'\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b',
		"basic_auth": r'(://[^:/@\s]+:[^@/\s]{8,}@)',

		# Private keys
		"private_key": r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
		"pgp_private_key": r'-----BEGIN PGP PRIVATE KEY BLOCK-----',

		# Package managers
		"npm_token": r'\b(npm_[A-Za-z0-9]{36})\b',
		"pypi_token": r'\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,})\b',
	}

	# Generic patterns - ONLY for high entropy strings
	GENERIC_PATTERNS = {
		"generic_api_key": r'api[_-]?key\s*[=:]\s*["\']([A-Za-z0-9_\-/+=]{24,})["\']',
		"generic_secret": r'secret\s*[=:]\s*["\']([A-Za-z0-9_\-/+=]{24,})["\']',
		"generic_token": r'token\s*[=:]\s*["\']([A-Za-z0-9_\-/+=]{24,})["\']',
		"generic_password": r'password\s*[=:]\s*["\']([A-Za-z0-9_\-/+=!@#$%^&*]{16,})["\']',
	}

	DYNAMIC_VAR_PATTERNS = [
		r'\$\{[^}]+\}',
		r'\$[A-Z_][A-Z0-9_]*',
		r'\{\{[^}]+\}\}',
		r'%[A-Z_][A-Z0-9_]*%',
		r'os\.getenv\(["\'][^"\']+["\']\)',
		r'process\.env\.[A-Z_][A-Z0-9_]*',
		r'ENV\[["\'][^"\']+["\']\]',
		r'System\.getenv\(["\'][^"\']+["\']\)',
		r'<[A-Z_][A-Z0-9_]*>',
		r'\[[A-Z_][A-Z0-9_]*\]',
	]

	FALSE_POSITIVE_PATTERNS = [
		r'example\.com',
		r'localhost',
		r'127\.0\.0\.1',
		r'test[_-]?api[_-]?key',
		r'your[_-]?api[_-]?key',
		r'your[_-]?(token|secret|password)',
		r'insert[_-]?key[_-]?here',
		r'replace[_-]?with[_-]?your',
		r'dummy[_-]?(key|token|secret)',
		r'fake[_-]?(key|token|secret)',
		r'placeholder',
		r'xxx+',
		r'000+',
		r'111+',
		r'abc123',
		r'test123',
		r'sample[_-]?key',
		r'<[A-Z_]+>',
		r'\[YOUR_.*\]',
		r'changeme',
		r'change[_-]?this',
		r'put[_-]?your',
		r'enter[_-]?your',
	]

	# Config UUID patterns
	CONFIG_UUID_PATTERNS = [
		r'"uid":\s*"[0-9a-fA-F-]+"',
		r'"id":\s*"[0-9a-fA-F-]+"',
		r'"uuid":\s*"[0-9a-fA-F-]+"',
		r'"puuid":\s*"[0-9a-fA-F-]+"',
		r'dashboard.*[0-9a-fA-F]{8}-[0-9a-fA-F]{4}',
		r'panel[Ii]d.*[0-9a-fA-F-]+',
		r'datasource.*[0-9a-fA-F-]+',
		r'/view/[0-9a-fA-F-]+',
		r'"guid":\s*"[0-9a-fA-F-]+"',
		r'userId.*[0-9a-fA-F-]+',
	]

	SENSITIVE_FILES = [
		".env", ".env.local", ".env.production", ".env.development",
		".env.staging", ".env.test",
		"credentials.json", "secrets.yaml", "secrets.yml",
		"config/secrets.yml", "id_rsa", "id_dsa", "id_ecdsa",
		".ssh/id_rsa", "*.pem", "*.key", "*.p12", "*.pfx",
		".aws/credentials", ".docker/config.json",
		"*.keystore", "*.jks",
	]

	IGNORED_EXTENSIONS = {
		'.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.webp',
		'.mp4', '.mov', '.avi', '.mp3', '.wav', '.flac',
		'.zip', '.tar', '.gz', '.rar', '.7z', '.bz2',
		'.exe', '.dll', '.so', '.dylib',
		'.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
		'.pyc', '.pyo', '.class', '.o', '.a',
		'.min.js', '.min.css', '.bundle.js',
		'.woff', '.woff2', '.ttf', '.eot',
		'.db', '.sqlite', '.sqlite3',
		'.lock', '.sum',  # Lock files
	}

	IGNORED_DIRECTORIES = {
		'.git', 'node_modules', 'venv', '__pycache__',
		'vendor', 'dist', 'build', '.next', '.nuxt',
		'target', 'out', 'bin', 'obj', '.pytest_cache',
		'coverage', '.coverage', 'htmlcov'
	}

	def __init__(self, repo_path, max_files=MAX_FILES_TO_SCAN):
		self.repo_path = repo_path
		self.max_files = max_files
		self.alerts = []
		self.sensitive_files_found = set()
		self.stats = {
			'files_scanned': 0,
			'secrets_found': 0,
			'false_positives_filtered': 0
		}

	def scan(self):
		console.print("[yellow]⏳ Running security scan...[/yellow]")
		self.alerts = []
		self.sensitive_files_found = set()

		self._scan_sensitive_files()
		self._scan_secrets()
		self._check_gitignore()

		results = {
			"critical": [a for a in self.alerts if a["severity"] == "critical"],
			"high": [a for a in self.alerts if a["severity"] == "high"],
			"medium": [a for a in self.alerts if a["severity"] == "medium"],
			"low": [a for a in self.alerts if a["severity"] == "low"],
			"total": len(self.alerts),
			"stats": self.stats
		}

		console.print(f"[green]✓[/green] Scan complete: {results['total']} alerts ({self.stats['files_scanned']} files scanned)")
		if self.stats['false_positives_filtered'] > 0:
			console.print(f"[dim]  ℹ️  Filtered {self.stats['false_positives_filtered']} false positives[/dim]")

		return results

	def _is_config_uuid(self, line_content):
		"""Check if line contains configuration UUID (not a secret)."""
		for pattern in self.CONFIG_UUID_PATTERNS:
			if re.search(pattern, line_content, re.IGNORECASE):
				return True
		return False

	def _is_dynamic_variable(self, text):
		"""Check if text is a dynamic variable reference."""
		for pattern in self.DYNAMIC_VAR_PATTERNS:
			if re.search(pattern, text):
				return True
		return False

	def _is_likely_false_positive(self, text, context=""):
		"""Enhanced false positive detection with context."""
		text_lower = text.lower().strip()

		if len(text_lower) < MIN_SECRET_LENGTH:
			return True

		# Check common false positive patterns
		for pattern in self.FALSE_POSITIVE_PATTERNS:
			if re.search(pattern, text_lower):
				return True

		# Common placeholder values
		generic_values = [
			'abcdef', 'abc123', '123456', 'qwerty',
			'xxxxxxxx', '00000000', '11111111',
			'test', 'sample', 'example', 'demo',
			'your-key-here', 'insert-key-here',
			'sk_test_', 'pk_test_',
			'password123', 'admin123'
		]

		for generic in generic_values:
			if generic in text_lower:
				return True

		# Low character diversity = likely fake
		if len(set(text)) <= 3:
			return True

		# Only lowercase letters = likely not a secret
		if re.match(r'^[a-z]{8,}$', text_lower):
			return True

		# Only digits and short = likely not a secret
		if text.isdigit() and len(text) < 20:
			return True

		# Context-based detection
		if context:
			context_lower = context.lower()
			# Check if surrounded by documentation indicators
			if any(word in context_lower for word in ['example', 'sample', 'todo', 'fixme', 'placeholder']):
				return True

		return False

	def _calculate_entropy(self, text):
		"""Calculate Shannon entropy of a string."""
		if not text:
			return 0
		counts = Counter(text)
		length = len(text)
		entropy = -sum((count / length) * math.log2(count / length) for count in counts.values())
		return entropy

	def _is_high_entropy_string(self, text, threshold=ENTROPY_THRESHOLD_MEDIUM):
		"""Check if string has high entropy (randomness)."""
		if len(text) < 20:
			return False
		entropy = self._calculate_entropy(text)
		return entropy > threshold

	def _scan_secrets(self):
		"""Scan files for exposed secrets."""
		scanned_files = 0
		for root, dirs, files in os.walk(self.repo_path):
			dirs[:] = [d for d in dirs if d not in self.IGNORED_DIRECTORIES]

			if scanned_files >= self.max_files:
				console.print(f"[yellow]⚠️  Reached max file limit ({self.max_files})[/yellow]")
				break

			for file in files:
				if scanned_files >= self.max_files:
					break

				file_path = os.path.join(root, file)
				relative_path = os.path.relpath(file_path, self.repo_path)

				if relative_path in self.sensitive_files_found:
					continue
				if Path(file).suffix in self.IGNORED_EXTENSIONS:
					continue

				try:
					if os.path.getsize(file_path) > MAX_FILE_SIZE_BYTES:
						continue
				except:
					continue

				self._scan_file_for_secrets(file_path, relative_path)
				scanned_files += 1

		self.stats['files_scanned'] = scanned_files

	def _scan_file_for_secrets(self, file_path, relative_path):
		"""Scan a single file for secrets."""
		try:
			with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
				content = f.read()

			# Scan specific patterns first
			for secret_type, pattern in self.SECRET_PATTERNS.items():
				self._check_pattern(secret_type, pattern, content, relative_path, require_high_entropy=False)

			# Scan generic patterns with strict entropy requirements
			for secret_type, pattern in self.GENERIC_PATTERNS.items():
				self._check_pattern(secret_type, pattern, content, relative_path, require_high_entropy=True)

		except:
			pass

	def _check_pattern(self, secret_type, pattern, content, relative_path, require_high_entropy=False):
		"""Check a pattern in file content."""
		matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)

		for match in matches:
			line_num = content[:match.start()].count('\n') + 1
			lines = content.split('\n')
			line_content = lines[line_num - 1].strip() if line_num <= len(lines) else ""

			# Get surrounding context (5 lines before and after)
			context_start = max(0, line_num - 5)
			context_end = min(len(lines), line_num + 5)
			context_lines = lines[context_start:context_end]
			context = '\n'.join(context_lines)

			secret_value = match.group(1) if match.groups() else match.group(0)

			# Apply filters
			if self._is_config_uuid(line_content):
				self.stats['false_positives_filtered'] += 1
				continue

			if self._is_dynamic_variable(line_content):
				self.stats['false_positives_filtered'] += 1
				continue

			if self._is_likely_false_positive(secret_value, context):
				self.stats['false_positives_filtered'] += 1
				continue

			if self._is_false_positive_by_context(line_content, context, relative_path):
				self.stats['false_positives_filtered'] += 1
				continue

			# For example files, require very high entropy
			if self._is_example_file(relative_path):
				if not self._is_high_entropy_string(secret_value, threshold=ENTROPY_THRESHOLD_HIGH):
					self.stats['false_positives_filtered'] += 1
					continue

			# For generic patterns, ALWAYS require high entropy
			if require_high_entropy:
				if not self._is_high_entropy_string(secret_value, threshold=ENTROPY_THRESHOLD_HIGH):
					self.stats['false_positives_filtered'] += 1
					continue

			severity = self._determine_severity(secret_type, secret_value, line_content)

			self.alerts.append({
				"type": "secret_exposed",
				"severity": severity,
				"secret_type": secret_type,
				"file": relative_path,
				"line": line_num,
				"preview": line_content[:100],
				"message": f"{secret_type.replace('_', ' ').title()} detected",
				"entropy": round(self._calculate_entropy(secret_value), 2)
			})
			self.stats['secrets_found'] += 1

	def _is_false_positive_by_context(self, line_content, context, file_path):
		"""Enhanced context-based false positive detection."""
		line_lower = line_content.lower()
		context_lower = context.lower()

		# Documentation indicators
		doc_indicators = [
			'example', 'sample', 'template', 'placeholder', 'demo',
			'your_api_key', 'your_token', 'your_secret',
			'insert_here', 'replace_with', 'replace_me',
			'<api_key>', '<token>', '<secret>',
			'todo:', 'fixme:', 'xxx', 'fill in',
			'set this', 'configure this', 'add your'
		]

		for indicator in doc_indicators:
			if indicator in line_lower or indicator in context_lower:
				return True

		# Comment detection
		comment_patterns = [r'^\s*#', r'^\s*//', r'^\s*/\*', r'^\s*\*', r'^\s*<!--']
		for pattern in comment_patterns:
			if re.match(pattern, line_content):
				return True

		# Test/mock indicators
		test_indicators = [
			'test_', '_test.', '.spec.', '.test.',
			'mock', 'fixture', 'stub', 'fake',
			'def test_', 'it(', 'describe(',
			'@pytest', '@unittest', '@test'
		]

		file_lower = file_path.lower()
		for indicator in test_indicators:
			if indicator in file_lower or indicator in context_lower:
				return True

		# Example files
		example_patterns = ['.example', '.sample', '.template', '.dist', 'example.', 'sample.', 'template.']
		for pattern in example_patterns:
			if pattern in file_lower:
				return True

		# Documentation directories
		doc_dirs = [
			'readme', 'contributing', 'changelog',
			'/docs/', '/documentation/', '/examples/',
			'/samples/', '/demo/'
		]
		for doc in doc_dirs:
			if doc in file_lower:
				return True

		return False

	def _is_example_file(self, file_path):
		"""Check if file is an example/template file."""
		file_lower = file_path.lower()
		example_patterns = [
			'.example', '.sample', '.template', '.dist', '.tmpl',
			'example.', 'sample.', 'template.',
			'/examples/', '/samples/', '/templates/',
			'config.example', 'settings.example',
			'.env.example', '.env.sample', '.env.template'
		]
		return any(pattern in file_lower for pattern in example_patterns)

	def _determine_severity(self, secret_type, secret_value, line_content):
		"""Determine severity based on secret type and characteristics."""
		critical_types = [
			'aws_access_key', 'aws_secret_key',
			'azure_storage_key',
			'google_api', 'gcp_service_account',
			'github_token', 'github_app_token',
			'private_key', 'pgp_private_key'
		]
		if secret_type in critical_types:
			return 'critical'

		high_types = [
			'stripe_key', 'paypal_braintree',
			'mongodb_uri', 'postgres_uri', 'mysql_uri',
			'slack_token', 'discord_token',
			'sendgrid_api_key', 'twilio_api_key'
		]
		if secret_type in high_types:
			return 'high'

		# Generic patterns - severity based on entropy
		generic_types = ['generic_api_key', 'generic_secret', 'generic_token', 'generic_password']
		if secret_type in generic_types:
			entropy = self._calculate_entropy(secret_value)
			if entropy > ENTROPY_THRESHOLD_HIGH:
				return 'high'
			elif entropy > ENTROPY_THRESHOLD_MEDIUM:
				return 'medium'
			else:
				return 'low'

		return 'medium'

	def _scan_sensitive_files(self):
		"""Scan for sensitive files."""
		for root, dirs, files in os.walk(self.repo_path):
			dirs[:] = [d for d in dirs if d != '.git']

			for file in files:
				file_path = os.path.join(root, file)
				relative_path = os.path.relpath(file_path, self.repo_path)

				# Check for .env files (but not .env.example)
				if file.endswith('.env') or file.startswith('.env'):
					# Skip example/template files
					if any(ex in file for ex in ['.example', '.sample', '.template', '.dist']):
						continue

					self.sensitive_files_found.add(relative_path)

					# Analyze .env content to determine if it contains real secrets
					env_analysis = self._analyze_env_file(file_path)

					if env_analysis['has_real_secrets']:
						# Real secrets detected - HIGH severity
						self.alerts.append({
							"type": "sensitive_file",
							"severity": "high",
							"file": relative_path,
							"message": f"⚠️ Environment file with secrets: {file}",
							"recommendation": "🔒 CRITICAL: Ensure this file is in .gitignore and NEVER commit secrets. Create a .env.example file with placeholder values for documentation.",
							"details": env_analysis
						})
					elif env_analysis['has_values']:
						# Has values but likely placeholders - MEDIUM severity
						self.alerts.append({
							"type": "sensitive_file",
							"severity": "medium",
							"file": relative_path,
							"message": f"Environment file detected: {file}",
							"recommendation": "Verify this file doesn't contain real secrets. Consider using .env.example for templates.",
							"details": env_analysis
						})
					# If only empty values or comments, no alert (file is safe)
					continue

				# Check other sensitive files
				for sensitive_file in self.SENSITIVE_FILES:
					if '*' in sensitive_file:
						continue
					if file == sensitive_file or relative_path.endswith(sensitive_file):
						self.sensitive_files_found.add(relative_path)
						self.alerts.append({
							"type": "sensitive_file",
							"severity": "high",
							"file": relative_path,
							"message": f"Sensitive file detected: {file}",
							"recommendation": "Ensure this file is in .gitignore and contains no hardcoded secrets"
						})
						break

	def _analyze_env_file(self, file_path):
		"""
		Analyse le contenu d'un fichier .env pour déterminer s'il contient de vrais secrets.

		Returns:
			dict: Analyse du fichier avec:
				- has_real_secrets: bool - True si secrets réels détectés
				- has_values: bool - True si des valeurs non-vides existent
				- total_vars: int - Nombre de variables
				- empty_vars: int - Variables vides ou placeholders
				- suspicious_vars: list - Variables suspectes
		"""
		result = {
			'has_real_secrets': False,
			'has_values': False,
			'total_vars': 0,
			'empty_vars': 0,
			'placeholder_vars': 0,
			'suspicious_vars': []
		}

		# Patterns indiquant des placeholders (pas de vrais secrets)
		placeholder_patterns = [
			r'^$',  # Vide
			r'^your[_-]?',  # your_, your-, your_api_key_here
			r'.*_here$',  # xxx_here, your_key_here
			r'^change[_-]?me',
			r'^xxx+',  # xxx, xxxx, etc.
			r'^placeholder',
			r'^example',
			r'^insert[_-]?',
			r'^replace[_-]?',
			r'^todo',
			r'^fixme',
			r'^\<.*\>$',  # <YOUR_KEY>
			r'^\[.*\]$',  # [YOUR_KEY]
			r'^\$\{.*\}$',  # ${VAR}
			r'^dummy',
			r'^test$',
			r'^sample',
			r'^none$',
			r'^null$',
			r'^undefined$',
			r'^fill[_-]?in',  # fill_in, fillin
			r'^enter[_-]?here',
			r'^put[_-]?here',
			r'^add[_-]?here',
			r'^\*+$',  # ***, ****
			r'^\.\.\.+$',  # ..., ....
		]

		try:
			with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
				for line in f:
					line = line.strip()

					# Skip comments and empty lines
					if not line or line.startswith('#'):
						continue

					# Parse KEY=VALUE
					if '=' in line:
						key, _, value = line.partition('=')
						key = key.strip()
						value = value.strip().strip('"').strip("'")

						result['total_vars'] += 1

						# Check if value is empty
						if not value:
							result['empty_vars'] += 1
							continue

						# Check if value is a placeholder
						value_lower = value.lower()
						is_placeholder = any(
							re.match(pattern, value_lower)
							for pattern in placeholder_patterns
						)

						if is_placeholder:
							result['placeholder_vars'] += 1
							continue

						# Value exists and is not a placeholder
						result['has_values'] = True

						# Check if it looks like a real secret (high entropy or known patterns)
						if self._looks_like_real_secret(key, value):
							result['has_real_secrets'] = True
							result['suspicious_vars'].append(key)

		except Exception:
			pass

		return result

	def _looks_like_real_secret(self, key, value):
		"""
		Détermine si une valeur ressemble à un vrai secret.

		Args:
			key: Nom de la variable
			value: Valeur de la variable

		Returns:
			bool: True si ça ressemble à un vrai secret
		"""
		key_lower = key.lower()
		value_lower = value.lower()

		# Keys qui indiquent des secrets
		secret_key_patterns = [
			'password', 'passwd', 'pwd',
			'secret', 'token', 'api_key', 'apikey',
			'private_key', 'access_key', 'auth',
			'credential', 'jwt', 'bearer'
		]

		is_secret_key = any(pattern in key_lower for pattern in secret_key_patterns)

		# Si c'est une clé de secret, vérifier la valeur
		if is_secret_key:
			# Valeurs génériques qui ne sont pas de vrais secrets
			generic_values = [
				'password', 'secret', 'token', 'changeme', 'admin',
				'test', 'demo', 'example', 'sample', '123456', 'password123'
			]
			if value_lower in generic_values:
				return False

			# Vérifier l'entropie
			if len(value) >= 16 and self._calculate_entropy(value) > ENTROPY_THRESHOLD_MEDIUM:
				return True

			# Vérifier les patterns de vrais secrets
			for pattern in self.SECRET_PATTERNS.values():
				if re.search(pattern, value):
					return True

		# Vérifier si la valeur matche un pattern de secret connu
		for secret_type, pattern in self.SECRET_PATTERNS.items():
			if re.search(pattern, value):
				return True

		return False

	def _check_gitignore(self):
		"""Check .gitignore configuration."""
		gitignore_path = os.path.join(self.repo_path, '.gitignore')
		git_exclude_path = os.path.join(self.repo_path, '.git', 'info', 'exclude')

		gitignore_exists = os.path.exists(gitignore_path)
		git_exclude_exists = os.path.exists(git_exclude_path)

		if not gitignore_exists and not git_exclude_exists:
			self.alerts.append({
				"type": "missing_gitignore",
				"severity": "low",
				"file": ".gitignore",
				"message": "No .gitignore or .git/info/exclude found",
				"recommendation": "Create a .gitignore file to prevent committing sensitive files"
			})
			return

		gitignore_content = ""
		try:
			if gitignore_exists:
				with open(gitignore_path, 'r', encoding='utf-8') as f:
					gitignore_content = f.read()
		except:
			pass

		try:
			if git_exclude_exists:
				with open(git_exclude_path, 'r', encoding='utf-8') as f:
					gitignore_content += "\n" + f.read()
		except:
			pass

		if not gitignore_content.strip():
			return

		detected_extensions = self._detect_file_extensions()
		expected_patterns = self._get_expected_patterns(detected_extensions)

		missing_patterns = []
		for pattern_info in expected_patterns:
			pattern = pattern_info['pattern']
			if not self._pattern_exists_in_gitignore(pattern, gitignore_content):
				missing_patterns.append(pattern_info)

		if missing_patterns:
			critical_missing = [p for p in missing_patterns if p['severity'] == 'high']
			if critical_missing:
				patterns_str = ', '.join([p['pattern'] for p in critical_missing])
				self.alerts.append({
					"type": "incomplete_gitignore",
					"severity": "medium",
					"file": ".gitignore",
					"message": f"Missing critical patterns: {patterns_str}",
					"recommendation": f"Add these patterns to prevent committing sensitive files"
				})
			elif len(missing_patterns) >= 3:
				patterns_str = ', '.join([p['pattern'] for p in missing_patterns[:3]])
				self.alerts.append({
					"type": "incomplete_gitignore",
					"severity": "low",
					"file": ".gitignore",
					"message": f"Missing recommended patterns: {patterns_str} (+{len(missing_patterns)-3} more)",
					"recommendation": "Add these patterns to keep repository clean"
				})

	def _detect_file_extensions(self):
		"""Detect file extensions in repository."""
		extensions = set()
		max_files = 500
		file_count = 0
		for root, dirs, files in os.walk(self.repo_path):
			dirs[:] = [d for d in dirs if d not in self.IGNORED_DIRECTORIES]
			if file_count >= max_files:
				break
			for file in files:
				ext = Path(file).suffix.lower()
				if ext:
					extensions.add(ext)
				file_count += 1
		return extensions

	def _get_expected_patterns(self, extensions):
		"""Get expected .gitignore patterns based on detected file types."""
		expected = [
			{'pattern': '.env', 'severity': 'high', 'reason': 'Environment variables'},
			{'pattern': '.env.local', 'severity': 'high', 'reason': 'Local environment config'},
			{'pattern': '*.log', 'severity': 'medium', 'reason': 'Log files'},
			{'pattern': '.DS_Store', 'severity': 'low', 'reason': 'macOS system file'},
		]

		if '.py' in extensions:
			expected.extend([
				{'pattern': '__pycache__/', 'severity': 'medium', 'reason': 'Python cache'},
				{'pattern': '*.pyc', 'severity': 'medium', 'reason': 'Compiled Python'},
				{'pattern': 'venv/', 'severity': 'medium', 'reason': 'Virtual environment'},
				{'pattern': '.pytest_cache/', 'severity': 'low', 'reason': 'Pytest cache'},
			])

		if any(ext in extensions for ext in ['.js', '.ts', '.jsx', '.tsx']):
			expected.extend([
				{'pattern': 'node_modules/', 'severity': 'high', 'reason': 'Node dependencies'},
				{'pattern': 'dist/', 'severity': 'medium', 'reason': 'Build output'},
				{'pattern': '.next/', 'severity': 'medium', 'reason': 'Next.js build'},
			])

		return expected

	def _pattern_exists_in_gitignore(self, pattern, gitignore_content):
		"""Check if pattern exists in .gitignore."""
		lines = gitignore_content.lower().split('\n')
		pattern_lower = pattern.lower()

		variations = [pattern_lower, pattern_lower.rstrip('/'), pattern_lower + '/', '**/' + pattern_lower]
		return any(var in lines for var in variations)