# Makefile pour GitHub Repository Analyzer

.PHONY: help install analyze clean test

# Couleurs
BLUE := \033[0;34m
GREEN := \033[0;32m
YELLOW := \033[1;33m
RED := \033[0;31m
NC := \033[0m # No Color

help: ## Afficher l'aide
	@echo "$(BLUE)╔═══════════════════════════════════════════╗$(NC)"
	@echo "$(BLUE)║  GitHub Repository Analyzer              ║$(NC)"
	@echo "$(BLUE)╚═══════════════════════════════════════════╝$(NC)"
	@echo ""
	@echo "$(GREEN)Commandes disponibles:$(NC)"
	@echo "  $(YELLOW)make install$(NC)          - Installer les dépendances"
	@echo "  $(YELLOW)make analyze URL=...$(NC) - Analyser un repository"
	@echo "  $(YELLOW)make clean$(NC)            - Nettoyer les fichiers temporaires"
	@echo "  $(YELLOW)make test$(NC)             - Tester l'installation"
	@echo ""
	@echo "$(GREEN)Exemples:$(NC)"
	@echo "  make analyze URL=https://github.com/torvalds/linux"
	@echo "  make analyze URL=github.com/facebook/react"
	@echo ""

install: ## Installer les dépendances
	@echo "$(YELLOW)📦 Installation des dépendances...$(NC)"
	pip3 install -r requirements.txt
	@echo "$(GREEN)✅ Installation terminée$(NC)"

analyze: ## Analyser un repository (usage: make analyze URL=github.com/user/repo)
ifndef URL
	@echo "$(RED)❌ Erreur: URL manquante$(NC)"
	@echo "$(YELLOW)Usage: make analyze URL=<github_url>$(NC)"
	@exit 1
endif
	@echo "$(GREEN)🚀 Analyse de $(URL)...$(NC)"
	@python3 src/main.py $(URL)
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

test: ## Tester l'installation
	@echo "$(YELLOW)🧪 Test de l'installation...$(NC)"
	@python3 -c "import requests, git, rich; print('✅ Toutes les dépendances sont installées')" || \
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
