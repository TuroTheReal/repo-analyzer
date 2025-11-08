# Makefile pour GitHub Repository Analyzer
# Compatible Linux, macOS, Windows (Git Bash/WSL)

.PHONY: help install venv analyze clean test linux react django dev-install

# Couleurs
BLUE := \033[0;34m
GREEN := \033[0;32m
YELLOW := \033[1;33m
RED := \033[0;31m
NC := \033[0m

# Détection de l'OS
UNAME_S := $(shell uname -s 2>/dev/null || echo Windows)
ifeq ($(UNAME_S),Linux)
    OS := Linux
    VENV_BIN := venv/bin
    PYTHON := python3
    PIP := $(VENV_BIN)/pip
    ACTIVATE := . $(VENV_BIN)/activate
endif
ifeq ($(UNAME_S),Darwin)
    OS := macOS
    VENV_BIN := venv/bin
    PYTHON := python3
    PIP := $(VENV_BIN)/pip
    ACTIVATE := . $(VENV_BIN)/activate
endif
ifeq ($(UNAME_S),Windows)
    OS := Windows
    VENV_BIN := venv/Scripts
    PYTHON := python
    PIP := $(VENV_BIN)/pip
    ACTIVATE := $(VENV_BIN)/activate
endif

help: ## Afficher l'aide
	@echo "$(BLUE)╔═══════════════════════════════════════════╗$(NC)"
	@echo "$(BLUE)║  GitHub Repository Analyzer              ║$(NC)"
	@echo "$(BLUE)║  OS détecté: $(OS)                        $(NC)"
	@echo "$(BLUE)╚═══════════════════════════════════════════╝$(NC)"
	@echo ""
	@echo "$(GREEN)Commandes disponibles:$(NC)"
	@echo "  $(YELLOW)make install$(NC)          - Installer avec venv (recommandé)"
	@echo "  $(YELLOW)make dev-install$(NC)      - Installation système (--break-system-packages)"
	@echo "  $(YELLOW)make analyze URL=...$(NC) - Analyser un repository"
	@echo "  $(YELLOW)make clean$(NC)            - Nettoyer les fichiers temporaires"
	@echo "  $(YELLOW)make test$(NC)             - Tester l'installation"
	@echo ""
	@echo "$(GREEN)Exemples:$(NC)"
	@echo "  make analyze URL=https://github.com/torvalds/linux"
	@echo "  make analyze URL=github.com/facebook/react"
	@echo "  make analyze URL=/home/arthur/my-project  $(BLUE)(local)$(NC)"
	@echo ""

venv: ## Créer l'environnement virtuel
	@if [ ! -d "venv" ]; then \
		echo "$(YELLOW)🔧 Création du virtual environment...$(NC)"; \
		$(PYTHON) -m venv venv; \
		echo "$(GREEN)✅ Virtual environment créé$(NC)"; \
	else \
		echo "$(BLUE)ℹ️  Virtual environment existe déjà$(NC)"; \
	fi

install: venv ## Installer les dépendances (avec venv - RECOMMANDÉ)
	@echo "$(YELLOW)📦 Installation des dépendances dans le venv...$(NC)"
	@$(ACTIVATE) && $(PIP) install --upgrade pip
	@$(ACTIVATE) && $(PIP) install -r requirements.txt
	@echo "$(GREEN)✅ Installation terminée$(NC)"
	@echo ""
	@echo "$(BLUE)💡 Pour utiliser:$(NC)"
	@echo "  $(YELLOW)make analyze URL=<url>$(NC)"
	@echo ""

dev-install: ## Installation système (déconseillé, mais parfois nécessaire)
	@echo "$(YELLOW)⚠️  Installation système (--break-system-packages)...$(NC)"
	@echo "$(RED)⚠️  Cette méthode peut casser votre environnement Python système$(NC)"
	@read -p "Êtes-vous sûr ? (y/N): " confirm && [ "$$confirm" = "y" ] || exit 1
	@$(PYTHON) -m pip install --break-system-packages -r requirements.txt
	@echo "$(GREEN)✅ Installation terminée$(NC)"

analyze: ## Analyser un repository (usage: make analyze URL=github.com/user/repo ou URL=/path/to/local)
ifndef URL
	@echo "$(RED)❌ Erreur: URL manquante$(NC)"
	@echo "$(YELLOW)Usage: make analyze URL=<github_url_ou_chemin_local>$(NC)"
	@echo ""
	@echo "$(GREEN)Exemples:$(NC)"
	@echo "  make analyze URL=github.com/torvalds/linux"
	@echo "  make analyze URL=/home/arthur/my-project"
	@exit 1
endif
	@if [ ! -d "venv" ]; then \
		echo "$(RED)❌ Virtual environment non trouvé$(NC)"; \
		echo "$(YELLOW)Exécutez d'abord: make install$(NC)"; \
		exit 1; \
	fi
	@echo "$(GREEN)🚀 Analyse de $(URL)...$(NC)"
	@$(ACTIVATE) && python src/main.py $(URL)
	@echo ""
	@echo "$(GREEN)✅ Analyse terminée !$(NC)"
	@echo "$(BLUE)📁 Rapports dans le dossier output/$(NC)"

clean: ## Nettoyer les fichiers temporaires
	@echo "$(YELLOW)🧹 Nettoyage...$(NC)"
	@rm -rf __pycache__ src/__pycache__
	@rm -rf .pytest_cache
	@rm -rf *.pyc src/*.pyc
	@find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	@echo "$(GREEN)✅ Nettoyage terminé$(NC)"

fclean: clean ## Nettoyer tout (incluant venv et output)
	@echo "$(YELLOW)🧹 Nettoyage complet...$(NC)"
	@rm -rf venv
	@rm -rf output
	@echo "$(GREEN)✅ Nettoyage complet terminé$(NC)"

test: ## Tester l'installation
	@echo "$(YELLOW)🧪 Test de l'installation...$(NC)"
	@if [ ! -d "venv" ]; then \
		echo "$(RED)❌ Virtual environment non trouvé. Exécutez: make install$(NC)"; \
		exit 1; \
	fi
	@$(ACTIVATE) && python -c "import requests, git, rich; print('$(GREEN)✅ Toutes les dépendances sont installées$(NC)')" || \
		(echo "$(RED)❌ Dépendances manquantes. Exécutez: make install$(NC)" && exit 1)
	@test -f src/main.py || (echo "$(RED)❌ src/main.py introuvable$(NC)" && exit 1)
	@echo "$(GREEN)✅ Installation OK$(NC)"

# Exemples rapides
linux: ## Exemple: Analyser le repo Linux
	@make analyze URL=https://github.com/torvalds/linux

react: ## Exemple: Analyser le repo React
	@make analyze URL=https://github.com/facebook/react

django: ## Exemple: Analyser le repo Django
	@make analyze URL=https://github.com/django/django

local-example: ## Exemple: Analyser un projet local
	@make analyze URL=./

# Alias pour Windows (au cas où)
install-windows: install
analyze-windows: analyze
