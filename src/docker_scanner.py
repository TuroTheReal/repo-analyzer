"""
Docker configuration analysis and best practices checker.
"""

import os
import re
from pathlib import Path
from rich.console import Console

console = Console()

class DockerScanner:
	"""Analyzes Dockerfiles and docker-compose.yml for best practices."""

	# Dangerous/outdated base images
	RISKY_BASE_IMAGES = {
		"ubuntu:latest": "Use specific version tags (e.g., ubuntu:22.04)",
		"debian:latest": "Use specific version tags (e.g., debian:bullseye)",
		"alpine:latest": "Use specific version tags (e.g., alpine:3.18)",
		"node:latest": "Use specific version tags (e.g., node:18-alpine)",
		"python:latest": "Use specific version tags (e.g., python:3.11-slim)",
		"centos:latest": "CentOS is EOL, consider AlmaLinux or Rocky Linux",
		"ubuntu:14.04": "Ubuntu 14.04 is EOL (End of Life)",
		"ubuntu:16.04": "Ubuntu 16.04 is EOL (End of Life)",
		"debian:jessie": "Debian Jessie is EOL (End of Life)",
		"debian:stretch": "Debian Stretch is EOL (End of Life)",
	}

	# Preferred slim/alpine variants for smaller images
	RECOMMENDED_VARIANTS = {
		"python": "python:3.11-slim or python:3.11-alpine",
		"node": "node:18-alpine or node:18-slim",
		"nginx": "nginx:alpine",
		"redis": "redis:alpine",
	}

	# Security patterns to detect
	SECURITY_PATTERNS = {
		"run_as_root": {
			"pattern": r'^USER\s+root',
			"severity": "high",
			"message": "Running as root user - security risk"
		},
		"no_user": {
			"severity": "medium",
			"message": "No USER instruction - container runs as root by default"
		},
		"curl_bash": {
			"pattern": r'curl.*\|.*bash|wget.*\|.*sh',
			"severity": "high",
			"message": "Piping curl/wget to bash - security risk"
		},
		"apt_no_clean": {
			"pattern": r'apt-get\s+install.*(?!&&\s*rm\s+-rf\s+/var/lib/apt/lists)',
			"severity": "low",
			"message": "apt-get without cleanup - increases image size"
		},
		"sudo_usage": {
			"pattern": r'\bsudo\b',
			"severity": "medium",
			"message": "Using sudo in Dockerfile - unnecessary in containers"
		},
		"hardcoded_secrets": {
			"pattern": r'(ENV|ARG)\s+(PASSWORD|SECRET|API_KEY|TOKEN)\s*=\s*["\']?(?!\$)[A-Za-z0-9]+',
			"severity": "critical",
			"message": "Hardcoded secret in ENV/ARG"
		},
	}

	def __init__(self, repo_path):
		"""
		Args:
			repo_path: Path to the repository
		"""
		self.repo_path = repo_path
		self.alerts = []
		self.dockerfiles = []
		self.compose_files = []
		self.dockerfile_healthchecks = {}  # Track healthchecks per Dockerfile
		self.compose_healthchecks = {}     # Track healthchecks in compose

	def scan(self):
		"""
		Run Docker analysis.

		Returns:
			dict: Analysis results
		"""
		console.print("[yellow]⏳ Analyzing Docker configuration...[/yellow]")

		# Find all Docker-related files
		self._find_docker_files()

		if not self.dockerfiles and not self.compose_files:
			console.print("[dim]ℹ No Docker files found[/dim]")
			return self._format_results()

		# Analyze Dockerfiles
		for dockerfile in self.dockerfiles:
			self._analyze_dockerfile(dockerfile)

		# Analyze docker-compose files
		for compose_file in self.compose_files:
			self._analyze_compose(compose_file)

		console.print(f"[green]✓[/green] Docker analysis complete: {len(self.alerts)} issues found")

		return self._format_results()

	def _find_docker_files(self):
		"""Find all Dockerfiles and docker-compose.yml in repo."""
		for root, dirs, files in os.walk(self.repo_path):
			# Skip .git
			if '.git' in root:
				continue

			for file in files:
				file_lower = file.lower()
				file_path = os.path.join(root, file)
				relative_path = os.path.relpath(file_path, self.repo_path)

				# Dockerfiles
				if file_lower == 'dockerfile' or file_lower.startswith('dockerfile.'):
					self.dockerfiles.append(relative_path)

				# docker-compose files
				elif 'docker-compose' in file_lower and file_lower.endswith(('.yml', '.yaml')):
					self.compose_files.append(relative_path)

	def _analyze_dockerfile(self, dockerfile_path):
		"""Analyze a single Dockerfile."""
		full_path = os.path.join(self.repo_path, dockerfile_path)

		try:
			with open(full_path, 'r', encoding='utf-8') as f:
				content = f.read()

			lines = content.split('\n')

			# Analysis checks
			self._check_base_image(dockerfile_path, lines)
			self._check_user_instruction(dockerfile_path, lines)
			self._check_security_issues(dockerfile_path, content, lines)
			self._check_healthcheck(dockerfile_path, lines)
			self._check_multistage_build(dockerfile_path, lines)
			self._check_layer_optimization(dockerfile_path, lines)

		except Exception as e:
			console.print(f"[yellow]⚠ Error reading {dockerfile_path}: {e}[/yellow]")

	def _check_base_image(self, dockerfile_path, lines):
		"""Check for outdated or risky base images."""
		for i, line in enumerate(lines, 1):
			line_stripped = line.strip()

			if line_stripped.upper().startswith('FROM'):
				# Extract image name
				parts = line_stripped.split()
				if len(parts) >= 2:
					image = parts[1].lower()

					# Check against risky images
					for risky_image, recommendation in self.RISKY_BASE_IMAGES.items():
						if image.startswith(risky_image.split(':')[0]):
							if ':latest' in image or image == risky_image.split(':')[0]:
								self.alerts.append({
									"type": "docker_base_image",
									"severity": "medium",
									"file": dockerfile_path,
									"line": i,
									"message": f"Risky base image: {image}",
									"recommendation": recommendation
								})
							elif risky_image in image:
								self.alerts.append({
									"type": "docker_base_image",
									"severity": "high",
									"file": dockerfile_path,
									"line": i,
									"message": f"EOL base image: {image}",
									"recommendation": recommendation
								})

	def _check_user_instruction(self, dockerfile_path, lines):
		"""Check if USER instruction is present and not root."""
		has_user = False
		last_user_is_root = False

		for i, line in enumerate(lines, 1):
			line_stripped = line.strip().upper()

			if line_stripped.startswith('USER'):
				has_user = True
				# Check if it's USER root
				if 'ROOT' in line_stripped or 'USER 0' in line_stripped:
					last_user_is_root = True
					self.alerts.append({
						"type": "docker_security",
						"severity": "high",
						"file": dockerfile_path,
						"line": i,
						"message": "Container runs as root user",
						"recommendation": "Use a non-root user (e.g., USER node, USER nobody)"
					})
				else:
					last_user_is_root = False

		# No USER instruction at all
		if not has_user:
			self.alerts.append({
				"type": "docker_security",
				"severity": "medium",
				"file": dockerfile_path,
				"line": 0,
				"message": "No USER instruction - runs as root by default",
				"recommendation": "Add USER instruction with non-root user"
			})

	def _check_security_issues(self, dockerfile_path, content, lines):
		"""Check for various security issues."""
		for pattern_name, pattern_config in self.SECURITY_PATTERNS.items():
			if "pattern" not in pattern_config:
				continue

			pattern = pattern_config["pattern"]
			matches = re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE)

			for match in matches:
				# Get line number
				line_num = content[:match.start()].count('\n') + 1

				self.alerts.append({
					"type": "docker_security",
					"severity": pattern_config["severity"],
					"file": dockerfile_path,
					"line": line_num,
					"message": pattern_config["message"],
					"recommendation": self._get_security_recommendation(pattern_name)
				})

	def _check_healthcheck(self, dockerfile_path, lines):
		"""Check if HEALTHCHECK is defined."""
		has_healthcheck = any(
			line.strip().upper().startswith('HEALTHCHECK')
			for line in lines
		)

		if not has_healthcheck:
			self.alerts.append({
				"type": "docker_best_practice",
				"severity": "low",
				"file": dockerfile_path,
				"line": 0,
				"message": "No HEALTHCHECK instruction",
				"recommendation": "Add HEALTHCHECK to monitor container health"
			})

	def _check_multistage_build(self, dockerfile_path, lines):
		"""Detect if using multi-stage builds."""
		from_count = sum(
			1 for line in lines
			if line.strip().upper().startswith('FROM')
		)

		if from_count == 1:
			# Check if it's a compiled language that could benefit
			content_lower = '\n'.join(lines).lower()
			if any(keyword in content_lower for keyword in ['go build', 'mvn', 'gradle', 'npm run build', 'cargo build']):
				self.alerts.append({
					"type": "docker_optimization",
					"severity": "low",
					"file": dockerfile_path,
					"line": 0,
					"message": "Could benefit from multi-stage build",
					"recommendation": "Use multi-stage builds to reduce final image size"
				})

	def _check_layer_optimization(self, dockerfile_path, lines):
		"""Check for layer optimization opportunities."""
		run_count = sum(
			1 for line in lines
			if line.strip().upper().startswith('RUN')
		)

		# Too many RUN commands
		if run_count > 10:
			self.alerts.append({
				"type": "docker_optimization",
				"severity": "low",
				"file": dockerfile_path,
				"line": 0,
				"message": f"{run_count} separate RUN commands",
				"recommendation": "Combine RUN commands with && to reduce layers"
			})

	def _analyze_compose(self, compose_path):
		"""Analyze docker-compose.yml file."""
		full_path = os.path.join(self.repo_path, compose_path)

		try:
			with open(full_path, 'r', encoding='utf-8') as f:
				content = f.read()

			# Check for version
			if 'version:' not in content:
				self.alerts.append({
					"type": "docker_compose",
					"severity": "low",
					"file": compose_path,
					"line": 0,
					"message": "No version specified in docker-compose",
					"recommendation": "Specify version (e.g., version: '3.8')"
				})

			# Check for privileged mode
			if 'privileged: true' in content:
				self.alerts.append({
					"type": "docker_compose",
					"severity": "high",
					"file": compose_path,
					"line": 0,
					"message": "Privileged mode enabled",
					"recommendation": "Avoid privileged mode unless absolutely necessary"
				})

			# Check for restart policy
			if 'restart:' not in content and 'deploy:' not in content:
				self.alerts.append({
					"type": "docker_compose",
					"severity": "low",
					"file": compose_path,
					"line": 0,
					"message": "No restart policy defined",
					"recommendation": "Add restart policy (e.g., restart: unless-stopped)"
				})

		except Exception as e:
			console.print(f"[yellow]⚠ Error reading {compose_path}: {e}[/yellow]")

	def _get_security_recommendation(self, pattern_name):
		"""Get recommendation for security issue."""
		recommendations = {
			"curl_bash": "Download script, verify, then execute separately",
			"apt_no_clean": "Add '&& rm -rf /var/lib/apt/lists/*' after apt-get install",
			"sudo_usage": "Remove sudo - containers don't need it",
			"hardcoded_secrets": "Use build args or runtime environment variables",
		}
		return recommendations.get(pattern_name, "Follow Docker security best practices")

	def _format_results(self):
		"""Format results by severity."""
		return {
			"critical": [a for a in self.alerts if a["severity"] == "critical"],
			"high": [a for a in self.alerts if a["severity"] == "high"],
			"medium": [a for a in self.alerts if a["severity"] == "medium"],
			"low": [a for a in self.alerts if a["severity"] == "low"],
			"total": len(self.alerts),
			"dockerfiles": self.dockerfiles,
			"compose_files": self.compose_files
		}
