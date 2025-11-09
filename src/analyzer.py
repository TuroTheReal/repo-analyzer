"""
Repository structure analysis for cloned or local repositories.

FIXES:
- Full English translation
- Enhanced dependency detection for local repos
- Better error handling
"""

import os
import re
import tempfile
import shutil
from pathlib import Path
from git import Repo
from rich.console import Console
from rich.progress import track

console = Console()

class RepoAnalyzer:
	"""Analyzes the structure of a cloned or local repository."""

	def __init__(self, clone_url, repo_name, local_path=None):
		"""
		Args:
			clone_url: Clone URL (from API) - None for local
			repo_name: Repository name (for folder)
			local_path: Local project path (None for GitHub)
		"""
		self.clone_url = clone_url
		self.repo_name = repo_name
		self.local_path = local_path
		self.temp_dir = None

		# Determine if this is local or needs cloning
		if local_path:
			self.repo_path = os.path.abspath(local_path)
			self.is_local = True
		else:
			self.repo_path = None
			self.is_local = False

	def prepare(self):
		"""Prepare the repository for analysis (validate local path)."""
		if not self.is_local:
			# Should use clone_repo() instead
			return False

		# Validate local path exists
		if not os.path.exists(self.repo_path):
			console.print(f"[red]✗ Local path does not exist: {self.repo_path}[/red]")
			return False

		if not os.path.isdir(self.repo_path):
			console.print(f"[red]✗ Path is not a directory: {self.repo_path}[/red]")
			return False

		console.print(f"[green]✓[/green] Using local directory: {self.repo_path}")
		return True

	def clone_repo(self):
		"""Clone repository to temporary folder (GitHub only)."""
		if self.is_local:
			console.print(f"[green]✓[/green] Using local directory: {self.repo_path}")
			return True

		try:
			self.temp_dir = tempfile.mkdtemp(prefix="gh_analyzer_")
			self.repo_path = os.path.join(self.temp_dir, self.repo_name)

			console.print(f"[yellow]⏳ Cloning repository (shallow)...[/yellow]")

			# Clone shallow (depth=1) = only the last commit
			# Faster and lighter
			Repo.clone_from(
				self.clone_url,
				self.repo_path,
				depth=1,  # Only the last commit
				single_branch=True  # Only the main branch
			)

			console.print(f"[green]✓[/green] Cloned to {self.temp_dir}")
			return True

		except Exception as e:
			console.print(f"[red]✗ Clone error: {e}[/red]")
			return False

	def analyze_structure(self):
		"""
		Analyze repository structure (ENHANCED VERSION).

		Returns:
			dict: Structure statistics
		"""
		if not self.repo_path or not os.path.exists(self.repo_path):
			return {}

		console.print("[yellow]⏳ Analyzing structure...[/yellow]")

		stats = {
			"important_files": [],
			"file_types": {},
			"total_files": 0,
			"total_dirs": 0,
			"max_depth": 0,
			"has_tests": False,
			"has_ci": False,
			"has_docker": False,
			"test_details": {}  # NEW: Details about detected tests
		}

		# Important files to detect
		important_files = [
			"README.md", "README.rst", "README.txt",
			"LICENSE", "LICENSE.md", "LICENSE.txt",
			"CONTRIBUTING.md",
			".gitignore",
			"Makefile",
			"Dockerfile", "docker-compose.yml",
			".github/workflows", ".gitlab-ci.yml", "Jenkinsfile",
			"requirements.txt", "setup.py", "pyproject.toml",
			"package.json", "Cargo.toml", "go.mod", "pom.xml"
		]

		# Walk through all files
		for root, dirs, files in os.walk(self.repo_path):
			# Ignore .git
			if '.git' in root:
				continue

			# Calculate depth
			depth = root.replace(self.repo_path, '').count(os.sep)
			stats["max_depth"] = max(stats["max_depth"], depth)

			stats["total_dirs"] += len(dirs)

			# ENHANCEMENT: Robust test detection
			if not stats["has_tests"]:
				test_result = self._detect_tests_in_directory(root, dirs, files)
				if test_result['found']:
					stats["has_tests"] = True
					stats["test_details"] = test_result

			for file in files:
				stats["total_files"] += 1

				# Extension
				ext = Path(file).suffix or "no_extension"
				stats["file_types"][ext] = stats["file_types"].get(ext, 0) + 1

				# Important files
				for important in important_files:
					if file == important or important in os.path.join(root, file):
						stats["important_files"].append(important)

						# Special flags
						if "docker" in important.lower():
							stats["has_docker"] = True
						if "workflow" in important or ".gitlab-ci" in important or "Jenkinsfile" in important:
							stats["has_ci"] = True

		# Deduplicate important files
		stats["important_files"] = list(set(stats["important_files"]))

		# Sort file types by frequency
		stats["file_types"] = dict(
			sorted(stats["file_types"].items(), key=lambda x: x[1], reverse=True)
		)

		console.print(f"[green]✓[/green] Structure analyzed: {stats['total_files']:,} files")

		# Display test info if found
		if stats["has_tests"]:
			test_type = stats["test_details"].get('type', 'unknown')
			console.print(f"[green]✓[/green] Tests detected: {test_type}")

		return stats

	def _detect_tests_in_directory(self, root, dirs, files):
		"""
		Robust test detection (folders + files).

		Args:
			root: Current directory path
			dirs: List of subdirectories
			files: List of files

		Returns:
			dict: {'found': bool, 'type': str, 'location': str}
		"""
		result = {
			'found': False,
			'type': None,
			'location': None
		}

		# ===== 1. DETECTION BY FOLDER =====
		test_dir_names = [
			'test', 'tests', '__tests__',
			'spec', 'specs',
			'e2e', 'integration',
			'unit', 'unittest'
		]

		for dir_name in dirs:
			if dir_name.lower() in test_dir_names:
				result['found'] = True
				result['type'] = f'Test directory ({dir_name}/)'
				result['location'] = os.path.relpath(os.path.join(root, dir_name), self.repo_path)
				return result

		# ===== 2. DETECTION BY FILES (patterns) =====
		test_file_patterns = {
			# Python
			r'^test_.*\.py$': 'Python tests (test_*.py)',
			r'^.*_test\.py$': 'Python tests (*_test.py)',
			r'^test.*\.py$': 'Python tests (test*.py)',

			# JavaScript / TypeScript
			r'^.*\.spec\.(js|ts|jsx|tsx)$': 'JS/TS spec files (*.spec.js)',
			r'^.*\.test\.(js|ts|jsx|tsx)$': 'JS/TS test files (*.test.js)',

			# Go
			r'^.*_test\.go$': 'Go tests (*_test.go)',

			# Ruby
			r'^.*_spec\.rb$': 'Ruby specs (*_spec.rb)',
			r'^test_.*\.rb$': 'Ruby tests (test_*.rb)',

			# Java
			r'^.*Test\.java$': 'Java tests (*Test.java)',
			r'^Test.*\.java$': 'Java tests (Test*.java)',

			# PHP
			r'^.*Test\.php$': 'PHP tests (*Test.php)',

			# Rust
			r'^.*_test\.rs$': 'Rust tests (*_test.rs)',
		}

		for file_name in files:
			for pattern, test_type in test_file_patterns.items():
				if re.match(pattern, file_name, re.IGNORECASE):
					result['found'] = True
					result['type'] = test_type
					result['location'] = os.path.relpath(os.path.join(root, file_name), self.repo_path)
					return result

		# ===== 3. DETECTION BY FRAMEWORKS (if imports detected) =====
		# Scan a few files to detect test frameworks
		for file_name in files:
			if file_name.endswith('.py'):
				file_path = os.path.join(root, file_name)
				framework = self._detect_test_framework_in_file(file_path)
				if framework:
					result['found'] = True
					result['type'] = f'{framework} tests'
					result['location'] = os.path.relpath(file_path, self.repo_path)
					return result

		return result

	def _detect_test_framework_in_file(self, file_path):
		"""
		Detect if a file contains test framework imports.

		Args:
			file_path: Path of file to analyze

		Returns:
			str: Detected framework name (e.g., 'pytest', 'unittest') or None
		"""
		try:
			with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
				content = f.read(2000)  # Only read the beginning

			# Framework patterns
			frameworks = {
				'pytest': [r'import pytest', r'from pytest'],
				'unittest': [r'import unittest', r'from unittest'],
				'nose': [r'import nose', r'from nose'],
				'jest': [r'describe\(', r'test\(', r'it\('],
				'mocha': [r'describe\(', r'it\('],
				'jasmine': [r'describe\(', r'it\(', r'expect\('],
				'go test': [r'func Test', r't \*testing\.T'],
				'rspec': [r'describe ', r'context ', r'it '],
			}

			for framework, patterns in frameworks.items():
				for pattern in patterns:
					if re.search(pattern, content, re.IGNORECASE):
						return framework

		except:
			pass

		return None

	def find_dependencies(self):
		"""
		Find and parse dependency files.
		FIXED: Better support for local repositories.

		Returns:
			dict: {"python": [...], "nodejs": [...], ...}
		"""
		if not self.repo_path:
			return {}

		console.print("[yellow]⏳ Searching for dependencies...[/yellow]")

		deps = {}

		# Python - requirements.txt
		req_file = os.path.join(self.repo_path, "requirements.txt")
		if os.path.exists(req_file):
			try:
				with open(req_file, 'r', encoding='utf-8') as f:
					lines = f.readlines()
					python_deps = [
						line.strip()
						for line in lines
						if line.strip() and not line.startswith('#')
					][:10]  # Limit to 10 for display
					if python_deps:
						deps["python"] = python_deps
						console.print(f"[green]✓[/green] Found Python dependencies: {len(python_deps)} packages")
			except Exception as e:
				console.print(f"[yellow]⚠[/yellow] Error reading requirements.txt: {e}")

		# Node.js - package.json
		pkg_file = os.path.join(self.repo_path, "package.json")
		if os.path.exists(pkg_file):
			try:
				import json
				with open(pkg_file, 'r', encoding='utf-8') as f:
					data = json.load(f)
					node_deps = list(data.get("dependencies", {}).keys())[:10]
					if node_deps:
						deps["nodejs"] = node_deps
						console.print(f"[green]✓[/green] Found Node.js dependencies: {len(node_deps)} packages")
			except Exception as e:
				console.print(f"[yellow]⚠[/yellow] Error reading package.json: {e}")

		# Go - go.mod
		go_file = os.path.join(self.repo_path, "go.mod")
		if os.path.exists(go_file):
			try:
				with open(go_file, 'r', encoding='utf-8') as f:
					lines = f.readlines()
					go_deps = []
					in_require = False
					for line in lines:
						line = line.strip()
						if line.startswith('require'):
							in_require = True
							continue
						if in_require:
							if line == ')':
								break
							if line and not line.startswith('//'):
								# Extract package name (first part)
								parts = line.split()
								if parts:
									go_deps.append(parts[0])
					if go_deps:
						deps["go"] = go_deps[:10]
						console.print(f"[green]✓[/green] Found Go dependencies: {len(go_deps)} packages")
			except Exception as e:
				console.print(f"[yellow]⚠[/yellow] Error reading go.mod: {e}")

		# Rust - Cargo.toml
		cargo_file = os.path.join(self.repo_path, "Cargo.toml")
		if os.path.exists(cargo_file):
			try:
				with open(cargo_file, 'r', encoding='utf-8') as f:
					lines = f.readlines()
					rust_deps = []
					in_dependencies = False
					for line in lines:
						line = line.strip()
						if line == '[dependencies]':
							in_dependencies = True
							continue
						if in_dependencies:
							if line.startswith('['):
								break
							if '=' in line and not line.startswith('#'):
								dep_name = line.split('=')[0].strip()
								rust_deps.append(dep_name)
					if rust_deps:
						deps["rust"] = rust_deps[:10]
						console.print(f"[green]✓[/green] Found Rust dependencies: {len(rust_deps)} crates")
			except Exception as e:
				console.print(f"[yellow]⚠[/yellow] Error reading Cargo.toml: {e}")

		if not deps:
			console.print("[dim]ℹ No dependency files found[/dim]")

		return deps

	def cleanup(self):
		"""Delete temporary folder (GitHub only)."""
		if self.is_local:
			# NEVER delete local directories!
			console.print(f"[dim]✓ Local analysis - no cleanup needed[/dim]")
			return

		# Only cleanup temporary cloned repos
		if self.temp_dir and os.path.exists(self.temp_dir):
			try:
				shutil.rmtree(self.temp_dir)
				console.print(f"[dim]✓ Cleanup complete[/dim]")
			except Exception as e:
				console.print(f"[yellow]⚠ Cleanup error: {e}[/yellow]")