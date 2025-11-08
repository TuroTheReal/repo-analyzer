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
		"""Check if text matches common false positive patterns (VERSION AMÉLIORÉE)."""
		text_lower = text.lower().strip()

		# Empty ou très court
		if len(text_lower) < 8:
			return True

		# Patterns existants
		for pattern in self.FALSE_POSITIVE_PATTERNS:
			if re.search(pattern, text_lower):
				return True

		# NOUVEAU: Valeurs génériques communes
		generic_values = [
			'abcdef', 'abc123', '123456', 'qwerty',
			'xxxxxxxx', '00000000', '11111111',
			'test', 'sample', 'example', 'demo',
			'your-key-here', 'insert-key-here',
			'sk_test_', 'pk_test_',  # Stripe test keys
		]

		for generic in generic_values:
			if generic in text_lower:
				return True

		# NOUVEAU: Seulement des caractères répétés
		if len(set(text)) <= 3:
			return True

		# NOUVEAU: Pattern alphanumérique simple (pas aléatoire)
		if re.match(r'^[a-z]{8,}$', text_lower):  # "testpassword"
			return True

		# NOUVEAU: Valeurs numériques simples
		if text.isdigit() and len(text) < 20:
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
		"""Scan a specific file for secrets (VERSION AMÉLIORÉE)."""
		try:
			with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
				content = f.read()

			# Test each pattern
			for secret_type, pattern in self.SECRET_PATTERNS.items():
				matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)

				for match in matches:
					# Get line number
					line_num = content[:match.start()].count('\n') + 1

					# Extract full line + context
					lines = content.split('\n')
					line_content = lines[line_num - 1].strip() if line_num <= len(lines) else ""

					# NOUVEAU: Get context (3 lignes avant/après)
					context_start = max(0, line_num - 3)
					context_end = min(len(lines), line_num + 3)
					context_lines = lines[context_start:context_end]
					context = '\n'.join(context_lines)

					# SECRET VALUE
					secret_value = match.group(0)

					# ===== FILTRAGE AMÉLIORÉ =====

					# 1. CHECK: Variable dynamique?
					if self._is_dynamic_variable(line_content):
						continue

					# 2. CHECK: Faux positif basique?
					if self._is_likely_false_positive(secret_value):
						continue

					# 3. NOUVEAU: Check contexte de la ligne
					if self._is_false_positive_by_context(line_content, context, relative_path):
						continue

					# 4. NOUVEAU: Check si dans un fichier de configuration d'exemple
					if self._is_example_file(relative_path):
						# Patterns plus stricts pour les fichiers d'exemple
						if not self._is_high_entropy_string(secret_value, threshold=4.8):
							continue

					# 5. Pour patterns génériques, vérifier l'entropie
					if secret_type in ["password", "generic_secret", "generic_token", "generic_api_key"]:
						if not self._is_high_entropy_string(secret_value, threshold=4.5):
							continue

					# Mask the secret value
					masked_value = secret_value[:8] + "***" if len(secret_value) > 8 else "***"

					# Determine severity (plus nuancée)
					severity = self._determine_severity(secret_type, secret_value, line_content)

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

	def _is_false_positive_by_context(self, line_content, context, file_path):
		"""
		Vérifier si c'est un faux positif basé sur le contexte (NOUVEAU).

		Args:
			line_content: Ligne contenant le match
			context: Contexte (3 lignes avant/après)
			file_path: Chemin du fichier

		Returns:
			bool: True si faux positif
		"""
		line_lower = line_content.lower()
		context_lower = context.lower()

		# ===== 1. CONTEXTE DE DOCUMENTATION =====
		doc_indicators = [
			'example', 'sample', 'template', 'placeholder', 'demo',
			'your_api_key', 'your_token', 'your_secret',
			'insert_here', 'replace_with', 'replace_me',
			'<api_key>', '<token>', '<secret>',
			'todo:', 'fixme:', 'xxx'
		]

		for indicator in doc_indicators:
			if indicator in line_lower or indicator in context_lower:
				return True

		# ===== 2. COMMENTAIRES =====
		comment_patterns = [
			r'^\s*#',           # Python, Ruby, Shell
			r'^\s*//',          # JavaScript, Go, Java
			r'^\s*/\*',         # Multi-line comment start
			r'^\s*\*',          # Multi-line comment middle
			r'^\s*<!--',        # HTML, XML
		]

		for pattern in comment_patterns:
			if re.match(pattern, line_content):
				return True

		# ===== 3. FICHIERS DE TEST =====
		test_indicators = [
			'test_', '_test.', '.spec.', '.test.',
			'mock', 'fixture', 'stub',
			'def test_', 'it(', 'describe(',
			'@pytest', '@unittest'
		]

		# Check filename
		file_lower = file_path.lower()
		for indicator in test_indicators:
			if indicator in file_lower:
				return True

		# Check context
		for indicator in test_indicators:
			if indicator in context_lower:
				return True

		# ===== 4. CONFIGURATION D'EXEMPLE =====
		example_file_patterns = [
			'.example', '.sample', '.template', '.dist',
			'example.', 'sample.', 'template.'
		]

		for pattern in example_file_patterns:
			if pattern in file_lower:
				return True

		# ===== 5. DOCUMENTATION (README, docs, etc.) =====
		doc_files = [
			'readme', 'contributing', 'changelog',
			'/docs/', '/documentation/', '/examples/'
		]

		for doc in doc_files:
			if doc in file_lower:
				return True

		# ===== 6. VARIABLES D'ENVIRONNEMENT (définition) =====
		env_definition_patterns = [
			r'export\s+[A-Z_]+=',           # export API_KEY=
			r'[A-Z_]+\s*=\s*["\']?\$',      # API_KEY="${...}"
			r'process\.env\.[A-Z_]+\s*=',   # process.env.API_KEY =
			r'os\.environ\[["\'][A-Z_]',    # os.environ["API_KEY"]
		]

		for pattern in env_definition_patterns:
			if re.search(pattern, line_content):
				return True

		# ===== 7. CONSTANTES DÉCLARÉES COMME PLACEHOLDER =====
		if re.match(r'^\s*[A-Z_]+\s*=\s*["\']', line_content):
			# C'est une constante (ex: API_KEY = "...")
			# Vérifier si valeur générique
			if any(x in line_lower for x in ['xxx', 'your-', 'placeholder', 'insert-', 'replace-']):
				return True

		return False

	def _is_example_file(self, file_path):
		"""
		Vérifier si c'est un fichier d'exemple/template (NOUVEAU).

		Args:
			file_path: Chemin relatif du fichier

		Returns:
			bool: True si fichier d'exemple
		"""
		file_lower = file_path.lower()

		example_patterns = [
			'.example', '.sample', '.template', '.dist', '.tmpl',
			'example.', 'sample.', 'template.',
			'/examples/', '/samples/', '/templates/',
			'config.example', 'settings.example',
			'.env.example', '.env.sample'
		]

		for pattern in example_patterns:
			if pattern in file_lower:
				return True

		return False

	def _determine_severity(self, secret_type, secret_value, line_content):
		"""
		Déterminer la sévérité de manière plus nuancée (NOUVEAU).

		Args:
			secret_type: Type de secret détecté
			secret_value: Valeur du secret
			line_content: Ligne contenant le secret

		Returns:
			str: 'critical', 'high', 'medium', ou 'low'
		"""
		# ===== CRITICAL: Clés cloud providers et tokens GitHub =====
		critical_types = [
			'aws_access_key', 'aws_secret_key',
			'azure_storage_key',
			'google_api', 'gcp_service_account',
			'github_token', 'github_app_token',
			'private_key', 'pgp_private_key'
		]

		if secret_type in critical_types:
			return 'critical'

		# ===== HIGH: Tokens API, DB credentials, payment =====
		high_types = [
			'stripe_key', 'paypal_braintree',
			'mongodb_uri', 'postgres_uri', 'mysql_uri',
			'slack_token', 'discord_token',
			'sendgrid_api_key', 'twilio_api_key'
		]

		if secret_type in high_types:
			return 'high'

		# ===== MEDIUM: Patterns génériques avec entropie élevée =====
		generic_types = ['generic_api_key', 'generic_secret', 'generic_token', 'password']

		if secret_type in generic_types:
			entropy = self._calculate_entropy(secret_value)

			if entropy > 4.8:
				return 'high'  # Entropie très élevée = probablement réel
			elif entropy > 4.3:
				return 'medium'
			else:
				return 'low'  # Faible entropie = possiblement faux positif

		# ===== LOW: Patterns moins critiques =====
		return 'medium'  # Default

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
		"""Check if .gitignore exists and contains important patterns (INTELLIGENT VERSION)."""
		gitignore_path = os.path.join(self.repo_path, '.gitignore')

		if not os.path.exists(gitignore_path):
			self.alerts.append({
				"type": "missing_gitignore",
				"severity": "low",
				"file": ".gitignore",
				"message": "No .gitignore found"
			})
			return

		# STEP 1: Détecter les extensions présentes dans le repo
		detected_extensions = self._detect_file_extensions()

		# STEP 2: Construire la liste des patterns attendus selon les extensions
		expected_patterns = self._get_expected_patterns(detected_extensions)

		# STEP 3: Lire le .gitignore
		try:
			with open(gitignore_path, 'r', encoding='utf-8') as f:
				gitignore_content = f.read()
		except:
			return

		# STEP 4: Vérifier les patterns manquants
		missing_patterns = []
		for pattern_info in expected_patterns:
			pattern = pattern_info['pattern']
			# Support wildcards et variations
			if not self._pattern_exists_in_gitignore(pattern, gitignore_content):
				missing_patterns.append(pattern_info)

		# STEP 5: Alerter seulement si patterns critiques manquants
		if missing_patterns:
			critical_missing = [p for p in missing_patterns if p['severity'] == 'high']

			if critical_missing:
				# Patterns critiques manquants (ex: .env)
				patterns_str = ', '.join([p['pattern'] for p in critical_missing])
				self.alerts.append({
					"type": "incomplete_gitignore",
					"severity": "medium",  # Upgraded si .env manquant
					"file": ".gitignore",
					"message": f"Missing critical patterns: {patterns_str}"
				})
			elif len(missing_patterns) >= 3:
				# Plusieurs patterns recommandés manquants
				patterns_str = ', '.join([p['pattern'] for p in missing_patterns[:3]])
				self.alerts.append({
					"type": "incomplete_gitignore",
					"severity": "low",
					"file": ".gitignore",
					"message": f"Missing recommended patterns: {patterns_str} (+{len(missing_patterns)-3} more)"
				})

	def _detect_file_extensions(self):
		"""
		Détecter les extensions présentes dans le repo (mode local-friendly).

		Returns:
			set: Extensions détectées (ex: {'.py', '.js', '.go'})
		"""
		extensions = set()
		max_files = 500  # Limiter le scan

		file_count = 0
		for root, dirs, files in os.walk(self.repo_path):
			# Skip .git et node_modules
			dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', 'venv', '__pycache__', 'vendor']]

			if file_count >= max_files:
				break

			for file in files:
				ext = Path(file).suffix.lower()
				if ext:
					extensions.add(ext)
				file_count += 1

		return extensions

	def _get_expected_patterns(self, extensions):
		"""
		Retourner les patterns .gitignore attendus selon les extensions détectées.

		Args:
			extensions: Set d'extensions (ex: {'.py', '.js'})

		Returns:
			list: [{'pattern': '.env', 'severity': 'high', 'reason': '...'}, ...]
		"""
		expected = []

		# ===== PATTERNS UNIVERSELS (toujours requis) =====
		universal_patterns = [
			{'pattern': '.env', 'severity': 'high', 'reason': 'Environment variables with secrets'},
			{'pattern': '.env.local', 'severity': 'high', 'reason': 'Local environment config'},
			{'pattern': '*.log', 'severity': 'medium', 'reason': 'Log files can contain sensitive data'},
			{'pattern': '.DS_Store', 'severity': 'low', 'reason': 'macOS system file'},
		]
		expected.extend(universal_patterns)

		# ===== PYTHON =====
		if '.py' in extensions:
			expected.extend([
				{'pattern': '__pycache__/', 'severity': 'medium', 'reason': 'Python bytecode cache'},
				{'pattern': '*.pyc', 'severity': 'medium', 'reason': 'Compiled Python files'},
				{'pattern': '*.pyo', 'severity': 'low', 'reason': 'Optimized Python files'},
				{'pattern': 'venv/', 'severity': 'medium', 'reason': 'Virtual environment'},
				{'pattern': '.pytest_cache/', 'severity': 'low', 'reason': 'Pytest cache'},
				{'pattern': '*.egg-info/', 'severity': 'low', 'reason': 'Python package metadata'},
			])

		# ===== JAVASCRIPT / NODE.JS =====
		if '.js' in extensions or '.ts' in extensions or '.jsx' in extensions or '.tsx' in extensions:
			expected.extend([
				{'pattern': 'node_modules/', 'severity': 'high', 'reason': 'Node dependencies (large)'},
				{'pattern': 'dist/', 'severity': 'medium', 'reason': 'Build output'},
				{'pattern': 'build/', 'severity': 'medium', 'reason': 'Build output'},
				{'pattern': '*.min.js', 'severity': 'low', 'reason': 'Minified files'},
				{'pattern': '.npm/', 'severity': 'low', 'reason': 'NPM cache'},
			])

		# ===== GO =====
		if '.go' in extensions:
			expected.extend([
				{'pattern': 'vendor/', 'severity': 'medium', 'reason': 'Go dependencies'},
				{'pattern': '*.exe', 'severity': 'low', 'reason': 'Compiled binaries'},
				{'pattern': '*.test', 'severity': 'low', 'reason': 'Test binaries'},
			])

		# ===== JAVA =====
		if '.java' in extensions or '.class' in extensions:
			expected.extend([
				{'pattern': 'target/', 'severity': 'medium', 'reason': 'Maven build directory'},
				{'pattern': '*.class', 'severity': 'medium', 'reason': 'Compiled Java files'},
				{'pattern': '*.jar', 'severity': 'low', 'reason': 'Java archives'},
			])

		# ===== RUST =====
		if '.rs' in extensions:
			expected.extend([
				{'pattern': 'target/', 'severity': 'medium', 'reason': 'Cargo build directory'},
				{'pattern': 'Cargo.lock', 'severity': 'low', 'reason': 'Lock file (often ignored in libs)'},
			])

		# ===== C/C++ =====
		if '.c' in extensions or '.cpp' in extensions or '.h' in extensions:
			expected.extend([
				{'pattern': '*.o', 'severity': 'low', 'reason': 'Object files'},
				{'pattern': '*.a', 'severity': 'low', 'reason': 'Static libraries'},
				{'pattern': '*.so', 'severity': 'low', 'reason': 'Shared libraries'},
			])

		# ===== IDE CONFIGS (si beaucoup de fichiers) =====
		# On suggère seulement si le projet est assez gros
		if len(extensions) > 10:  # Projet conséquent
			expected.extend([
				{'pattern': '.vscode/', 'severity': 'low', 'reason': 'VS Code settings'},
				{'pattern': '.idea/', 'severity': 'low', 'reason': 'JetBrains IDE settings'},
			])

		return expected

	def _pattern_exists_in_gitignore(self, pattern, gitignore_content):
		"""
		Vérifier si un pattern existe dans .gitignore (avec variations).

		Args:
			pattern: Pattern à chercher (ex: '*.pyc')
			gitignore_content: Contenu du .gitignore

		Returns:
			bool: True si le pattern est couvert
		"""
		lines = gitignore_content.lower().split('\n')
		pattern_lower = pattern.lower()

		# Exact match
		if pattern_lower in lines:
			return True

		# Check variations communes
		variations = [
			pattern_lower,
			pattern_lower.rstrip('/'),  # 'venv/' -> 'venv'
			pattern_lower + '/',         # 'venv' -> 'venv/'
			'**/' + pattern_lower,       # '*.pyc' -> '**/*.pyc'
		]

		for var in variations:
			if var in lines:
				return True

		# Check si pattern est un wildcard et qu'une variation existe
		if '*' in pattern_lower:
			# Ex: '*.pyc' -> chercher toute ligne qui matche
			import fnmatch
			for line in lines:
				line_clean = line.strip()
				if fnmatch.fnmatch(pattern_lower, line_clean) or fnmatch.fnmatch(line_clean, pattern_lower):
					return True

		return False

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