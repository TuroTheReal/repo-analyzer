# repo-analyzer
# GITHUB REPOSITORY ANALYZER

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue.svg"/>
  <img src="https://img.shields.io/badge/Security-Scanner-red.svg"/>
  <img src="https://img.shields.io/badge/Docker-Analysis-2496ED.svg"/>
  <img src="https://img.shields.io/badge/Reports-HTML%20%7C%20MD-green.svg"/>
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg"/>
</p>

<p align="center">
  <i>A comprehensive security and quality analysis tool for GitHub repositories and local projects</i>
</p>

---

## Table of Contents
- [About](#about)
- [Features](#features)
- [Demo](#demo)
- [Installation](#installation)
- [Usage](#usage)
- [Analysis Components](#analysis-components)
- [Report Examples](#report-examples)
- [Technical Architecture](#technical-architecture)
- [Key Concepts Learned](#key-concepts-learned)
- [Skills Developed](#skills-developed)
- [Testing & Validation](#testing--validation)
- [Configuration](#configuration)
- [Contributing](#contributing)
- [Contact](#contact)

## About

**GitHub Repository Analyzer** is an automated security and code quality analysis tool designed to help developers, security teams, and DevOps engineers assess the health and security posture of both GitHub repositories and local projects.

The tool performs comprehensive scans covering:
- 🔒 **Security vulnerabilities** (exposed secrets, sensitive files)
- 🐳 **Docker best practices** (Dockerfile security, image optimization)
- ✨ **Development practices** (testing, CI/CD, documentation)
- 📦 **Dependency management** (outdated packages, known vulnerabilities)

### Why This Tool?

In modern software development, security and code quality are paramount. This analyzer:
- **Prevents security breaches** by detecting exposed API keys, tokens, and credentials
- **Enforces best practices** by checking for tests, CI/CD, and proper configurations
- **Improves Docker security** by analyzing Dockerfile and docker-compose configurations
- **Generates actionable reports** in both HTML (interactive) and Markdown formats

**Use Cases:**
- Pre-commit security checks
- Repository audits before deployment
- Security training and awareness
- Open-source project evaluation
- DevOps pipeline integration

## Features

### 🔒 Security Analysis
- **Secret Detection**: 50+ patterns for API keys, tokens, passwords
  - Cloud providers (AWS, Azure, GCP, DigitalOcean)
  - Version control (GitHub, GitLab)
  - Communication (Slack, Discord, Telegram)
  - Payment services (Stripe, PayPal, Square)
  - Databases (MongoDB, PostgreSQL, MySQL, Redis)
- **Entropy Analysis**: Detects high-entropy strings (likely secrets)
- **Sensitive File Detection**: Identifies `.env`, credentials, private keys
- **False Positive Filtering**: Smart detection of dynamic variables vs real secrets

### 🐳 Docker Security
- **Base Image Analysis**: Detects outdated/EOL images
- **Security Vulnerabilities**: Root user detection, hardcoded secrets
- **Best Practices**: Multi-stage builds, layer optimization
- **Docker Compose**: Configuration validation and security checks

### ✨ Best Practices Evaluation
- **Testing**: Detects test directories and frameworks
- **CI/CD**: Identifies GitHub Actions, GitLab CI, Jenkins
- **.gitignore**: Validates essential patterns
- **Documentation**: Checks for README, LICENSE, CONTRIBUTING

### 📊 Comprehensive Reporting
- **Interactive HTML**: Modern, responsive design with filtering
- **Markdown**: GitHub-friendly documentation format
- **Unified Security Score**: Weighted scoring system (0-100)
- **Letter Grades**: A+ to F rating system

### 🌍 Dual Mode Support
- **GitHub Repositories**: Clone and analyze remote repos
- **Local Projects**: Analyze directories without GitHub

## Demo

### Visual Output Example

```bash
$ python3 src/main.py github.com/owner/repo

🔍 Analyzing GitHub: owner/repo

✓ GitHub token detected
✓ Cloned to /tmp/gh_analyzer_abc123/repo
⏳ Analyzing structure...
✓ Structure analyzed: 1,247 files
⏳ Searching for dependencies...
✓ Found Python dependencies: 15 packages
⏳ Running security scan...
✓ Scan complete: 3 alerts
⏳ Analyzing Docker configuration...
✓ Docker analysis complete: 2 issues found
⏳ Generating reports...

✅ Analysis complete!

📊 **owner/repo**
⭐ 12,458 stars | 🍴 2,341 forks
📂 1,247 files
🐳 1 Dockerfile(s), 1 compose file(s)

🟡 MEDIUM (2)
  • .env.example:5 - Incomplete .gitignore
  • requirements.txt - django 3.2 → 4.2

🔵 LOW (1)
  • No test directory found

📄 Reports generated:
  📝 Markdown: output/repo-2025-11-08.md
  🌐 HTML: output/repo-2025-11-08.html

💡 Open the HTML file in your browser for an interactive view!
```

### Sample Security Score

```
🎯 Security Score: A- (85/100)

Excellent! Very few security issues detected.

| Component       | Score | Weight |
|-----------------|-------|--------|
| Security        | 92/100| 50%    |
| Docker          | 85/100| 30%    |
| Best Practices  | 70/100| 20%    |
```

## Installation

### Prerequisites
- **Python 3.8+**
- **Git** (for cloning repositories)
- **Optional**: GitHub Personal Access Token (for higher API rate limits)

### Quick Install (Recommended)

```bash
# Clone the repository
git clone https://github.com/TuroTheReal/repo-analyzer.git
cd repo-analyzer

# Install with virtual environment (automatic)
make install

# Test installation
make test
```

### Manual Installation

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### System Installation (Not Recommended)

```bash
# Only if you know what you're doing
make dev-install
```

## Usage

### Analyze GitHub Repository

```bash
# Using Makefile (recommended)
make analyze URL=github.com/torvalds/linux

# Direct Python
source venv/bin/activate
python src/main.py github.com/facebook/react
```

### Analyze Local Project

```bash
# Absolute path
make analyze URL=/home/user/my-project

# Relative path
make analyze URL=./my-local-repo

# Home directory
make analyze URL=~/projects/webapp
```

### With GitHub Token (Higher Rate Limits)

```bash
# Set environment variable
export GITHUB_TOKEN="ghp_your_token_here"

# Then analyze
make analyze URL=github.com/owner/repo
```

### Advanced Options

```bash
# Clean temporary files
make clean

# Clean everything (including venv and reports)
make clean-all

# Quick examples
make linux    # Analyze Linux kernel
make react    # Analyze React
make django   # Analyze Django
```

## Analysis Components

### Security Scanner (`security.py`)

**Detection Capabilities:**
- 50+ secret patterns (API keys, tokens, passwords)
- Entropy-based detection for random strings
- Dynamic variable filtering (skips `${VAR}`, `$PASSWORD`, etc.)
- False positive reduction with multiple heuristics

**Severity Levels:**
- 🔴 **Critical**: Exposed secrets requiring immediate action
- 🟠 **High**: Sensitive files, authentication issues
- 🟡 **Medium**: Outdated dependencies, configuration issues
- 🔵 **Low**: Missing .gitignore patterns, minor issues

### Docker Scanner (`docker_scanner.py`)

**Checks Performed:**
- Base image analysis (latest tags, EOL versions)
- Security issues (root user, sudo usage, curl|bash)
- Layer optimization (RUN command consolidation)
- Multi-stage build detection
- docker-compose validation

### Structure Analyzer (`analyzer.py`)

**Capabilities:**
- File type distribution
- Directory depth analysis
- Important file detection (README, LICENSE, etc.)
- Test directory detection
- CI/CD configuration detection
- Dependency file parsing (Python, Node.js)

### Score Calculator (`score_calculator.py`)

**Weighted Scoring System:**
- **Security (50%)**: Based on vulnerability severity
- **Docker (30%)**: Docker configuration quality
- **Best Practices (20%)**: Tests, CI/CD, .gitignore, secrets

**Grading Scale:**
- A+ (95-100): Excellent security posture
- A (90-94): Very good, minor improvements
- B (75-89): Good, some issues to address
- C (60-74): Average, several issues
- D (50-59): Below average, important issues
- F (<50): Critical security problems

## Report Examples

### HTML Report Features

- 📊 **Interactive Dashboard**: Security score, statistics, charts
- 🎨 **Modern Design**: Dark theme, responsive layout
- 🔍 **Filter System**: Filter alerts by severity
- 📈 **Visualizations**: Language distribution, file types (Chart.js)
- 🎯 **Actionable Recommendations**: Specific fixes for each issue

### Markdown Report Features

- 📝 **GitHub-Friendly**: Renders perfectly on GitHub
- 📋 **Structured Content**: Table of contents, sections
- ✅ **Checklists**: Visual indicators for passed/failed checks
- 🔗 **Links**: Direct links to GitHub profiles, documentation

### Sample Report Structure

```markdown
# Analysis of owner/repo

## 🎯 Security Score: B+ (88/100)

## 📊 Metadata
- ⭐ Stars: 12,458
- 🍴 Forks: 2,341
- 📂 Files: 1,247

## 🔒 Security Alerts (3)
### 🟡 Medium (2)
- Incomplete .gitignore
- Outdated dependency: django 3.2 → 4.2

### 🔵 Low (1)
- No test directory found

## 💡 Recommendations
1. Add automated testing
2. Update dependencies
3. Fix .gitignore configuration
```

## Technical Architecture

### Project Structure

```
repo-analyzer/
├── src/
│   ├── main.py              # Entry point, mode detection
│   ├── analyzer.py          # Structure analysis
│   ├── security.py          # Security scanner
│   ├── docker_scanner.py    # Docker analysis
│   ├── score_calculator.py  # Scoring system
│   ├── reporter.py          # Report orchestrator
│   ├── html_reporter.py     # HTML generation
│   └── github_api.py        # GitHub API client
├── output/                  # Generated reports
├── requirements.txt         # Python dependencies
├── Makefile                 # Build automation
└── README.md
```

### Core Components

#### 1. **Main Controller** (`main.py`)
```python
# Auto-detects input type
if is_github_url(input):
    analyze_github_repo(input)
elif is_local_path(input):
    analyze_local_repo(input)
```

#### 2. **Security Engine** (`security.py`)
```python
# Multi-layer detection
1. Pattern matching (regex)
2. Entropy analysis (Shannon)
3. Dynamic variable filtering
4. False positive reduction
```

#### 3. **Report Generator** (`html_reporter.py`)
```python
# Modern interactive HTML
- Chart.js for visualizations
- Responsive CSS Grid layout
- JavaScript filtering system
- Dark theme design
```

### Data Flow

```
Input (URL or Path)
    ↓
[Mode Detection]
    ↓
[Clone/Validate] ─────→ [Structure Analysis]
    ↓                           ↓
[Security Scan]            [Dependencies]
    ↓                           ↓
[Docker Scan]              [File Types]
    ↓                           ↓
[Score Calculation] ←───────────┘
    ↓
[Report Generation]
    ↓
HTML + Markdown Output
```

### Design Patterns Used

- **Strategy Pattern**: Different analyzers (Security, Docker, Structure)
- **Factory Pattern**: Report generation (HTML, Markdown)
- **Template Method**: Common analysis workflow
- **Singleton**: Shared configuration and scoring

## Key Concepts Learned

### Security Analysis
- **Pattern Recognition**: Regular expressions for secret detection
- **Entropy Calculation**: Shannon entropy for randomness detection
- **False Positive Filtering**: Heuristics for dynamic variables
- **Severity Assessment**: Risk-based classification system

### API Integration
- **GitHub REST API**: Repository metadata, contributors, languages
- **Rate Limiting**: Token-based authentication for higher limits
- **Error Handling**: Graceful degradation for API failures
- **Data Parsing**: JSON processing and data transformation

### Docker Security
- **Image Security**: Base image vulnerabilities and best practices
- **Layer Optimization**: Reducing image size and attack surface
- **Configuration Analysis**: Dockerfile and docker-compose parsing
- **Best Practice Enforcement**: Security checklist validation

### Report Generation
- **HTML Templating**: Dynamic content generation
- **Data Visualization**: Chart.js integration for insights
- **Responsive Design**: CSS Grid and Flexbox layouts
- **Markdown Formatting**: GitHub-flavored markdown

## Skills Developed

### Programming & Software Engineering
- **Python 3**: Advanced OOP, file I/O, regex, data structures
- **Git Integration**: Repository cloning, history analysis
- **API Design**: Clean interfaces, separation of concerns
- **Error Handling**: Robust exception management

### Security
- **Secret Detection**: Pattern matching, entropy analysis
- **Vulnerability Assessment**: Risk classification, severity scoring
- **Secure Coding**: Input validation, safe file operations
- **Security Automation**: Automated scanning and reporting

### DevOps & Automation
- **CI/CD Analysis**: Pipeline configuration detection
- **Docker**: Container security best practices
- **Build Automation**: Makefile for cross-platform support
- **Virtual Environments**: Dependency isolation

### Documentation & Communication
- **Technical Writing**: Clear, professional documentation
- **Report Generation**: Multi-format output (HTML, Markdown)
- **Data Visualization**: Charts and metrics presentation
- **User Experience**: Intuitive CLI and reports

## Testing & Validation

### Test Cases Passed

```bash
# GitHub repositories
✅ Public repos (torvalds/linux, facebook/react)
✅ Large repos (1000+ files, 200+ contributors)
✅ Various languages (Python, JavaScript, Go, Rust)
✅ With/without GitHub token

# Local projects
✅ Absolute paths (/home/user/project)
✅ Relative paths (./project, ../other-project)
✅ Home directory (~/.config, ~/projects/app)
✅ Edge cases (empty dirs, single file)

# Security detection
✅ AWS keys (AKIA..., secret access keys)
✅ GitHub tokens (ghp_..., github_pat_...)
✅ Database URIs (mongodb://, postgres://)
✅ API keys (Stripe, SendGrid, Twilio)
✅ False positives (${VAR}, $PASSWORD, dummy values)

# Docker analysis
✅ Various base images (alpine, ubuntu, python)
✅ Multi-stage builds
✅ Security issues (root user, hardcoded secrets)
✅ docker-compose configurations
```

### Quality Assurance

```bash
# Code Quality
pylint src/*.py              # Linting
black src/                   # Code formatting
mypy src/                    # Type checking (optional)

# Performance
time make analyze URL=...    # Execution time
du -sh output/               # Report size
```

### Stress Testing

```bash
# Large repositories
✅ Linux kernel (70,000+ files) - 45s
✅ TensorFlow (15,000+ files) - 22s
✅ React (1,500+ files) - 8s

# Many files
✅ 10,000+ files: Completes successfully
✅ Deep directories (20+ levels): Handles correctly
✅ Binary files: Skips appropriately
```

## Configuration

### Environment Variables

```bash
# GitHub API token (recommended)
export GITHUB_TOKEN="ghp_your_token_here"

# Custom output directory
export ANALYZER_OUTPUT="./custom_reports"
```

### .gitignore Patterns (Built-in)

The analyzer checks for these essential patterns:
- `.env` (environment variables)
- `*.log` (log files)
- `node_modules/` (Node.js)
- `__pycache__/`, `*.pyc` (Python)
- `.vscode/`, `.idea/` (IDE configs)

### Secret Patterns (50+)

Detects secrets from:
- AWS, Azure, GCP, DigitalOcean
- GitHub, GitLab, Bitbucket
- Slack, Discord, Telegram
- Stripe, PayPal, Square
- MongoDB, PostgreSQL, MySQL
- SendGrid, Twilio, Mailgun
- Firebase, Cloudinary
- And many more...

## Why This Project Matters

### Real-World Applications

This project demonstrates skills directly applicable to:

- **DevSecOps**: Automated security scanning in CI/CD pipelines
- **Security Engineering**: Vulnerability detection and risk assessment
- **Platform Engineering**: Repository health monitoring at scale
- **Compliance**: Automated auditing for security standards (SOC2, ISO 27001)

### Transferable Skills

- Writing production-grade security tools
- Integrating multiple APIs and services
- Generating professional reports for stakeholders
- Balancing false positives vs security coverage
- Cross-platform compatibility and automation

### Industry Relevance

Similar tools used in production:
- **GitGuardian**: Secret detection in repositories
- **Snyk**: Vulnerability scanning for dependencies
- **SonarQube**: Code quality and security analysis
- **Dependabot**: Automated dependency updates

## Contributing

Contributions are welcome! Here's how you can help:

### Areas for Improvement
- Add more secret patterns
- Support additional languages (Go, Rust, Java dependencies)
- Enhanced Docker analysis (vulnerability databases)
- PDF report generation
- API endpoint for programmatic access

### How to Contribute

```bash
# Fork the repository
git clone https://github.com/YourUsername/repo-analyzer.git

# Create a feature branch
git checkout -b feature/amazing-feature

# Make your changes and test
make test

# Commit with clear messages
git commit -m "Add: Support for Ruby dependencies"

# Push and create Pull Request
git push origin feature/amazing-feature
```

## Next Feature

- [ ] CI/CD integration (GitHub Actions workflow)
- [ ] Kubernetes Scanners
- [ ] Terraform Scanners
- [ ] Cloud Config Scanners
- [ ] Ansible Scanners
- [ ] JSON export format
- [ ] API mode (REST endpoint)
- [ ] Plugin system for extensibility
- [ ] Database storage for historical analysis
- [ ] Comparison reports (track changes over time)
- [ ] Web dashboard
- [ ] Custom rule definitions

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact

- **GitHub**: [@TuroTheReal](https://github.com/TuroTheReal)
- **Email**: arthurbernard.dev@gmail.com
- **LinkedIn**: [Arthur Bernard](https://www.linkedin.com/in/arthurbernard92/)

---

<p align="center">
  <b>⭐ Star this repo if you find it useful!</b>
</p>

<p align="center">
  Made with ❤️ by <a href="https://github.com/TuroTheReal">Arthur Bernard</a>
</p>