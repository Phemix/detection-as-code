PYTHON := python3
SCRIPTS := scripts
RULES_DIR := rules

.DEFAULT_GOAL := help
.PHONY: help install validate validate-strict validate-changed validate-staged compile compile-splunk inventory lint new-rule install-hooks clean

help:
	@echo ""
	@echo "  Detection-as-Code Pipeline"
	@echo "  ────────────────────────────────────────────"
	@echo "  make install           Install dependencies"
	@echo "  make install-hooks     Install git pre-commit hook"
	@echo ""
	@echo "  Validation:"
	@echo "  make validate          Validate ALL rules"
	@echo "  make validate-strict   Validate ALL rules (fail on warnings)"
	@echo "  make validate-changed  Validate only unstaged changed rules"
	@echo "  make validate-staged   Validate only staged (git add) rules"
	@echo ""
	@echo "  Pipeline:"
	@echo "  make compile           Compile all rules to Splunk SPL"
	@echo "  make inventory         Generate RULES.md + rules_manifest.json"
	@echo "  make lint              YAML lint all rule files"
	@echo "  make new-rule          Scaffold a new rule (interactive)"
	@echo "  make clean             Remove compiled output"
	@echo ""

install:
	pip3 install pyyaml yamllint

install-hooks:
	@cp scripts/pre-commit .git/hooks/pre-commit
	@chmod +x .git/hooks/pre-commit
	@echo "Pre-commit hook installed."

validate:
	@$(PYTHON) $(SCRIPTS)/validate.py

validate-strict:
	@$(PYTHON) $(SCRIPTS)/validate.py --strict

validate-changed:
	@echo "Validating unstaged changed rules..."
	@git diff --name-only -- '$(RULES_DIR)' | \
	grep '\.yml$$' | \
	while read file; do \
		if [ -f "$$file" ]; then \
			echo "  checking: $$file"; \
			$(PYTHON) $(SCRIPTS)/validate.py --file "$$file" || exit 1; \
		fi; \
	done
	@echo "Done."

validate-staged:
	@echo "Validating staged rules..."
	@git diff --cached --name-only -- '$(RULES_DIR)/**/*.yml' '$(RULES_DIR)/**/**/*.yml' | \
	grep '\.yml$$' | \
	while read file; do \
		if [ -f "$$file" ]; then \
			echo "  checking: $$file"; \
			$(PYTHON) $(SCRIPTS)/validate.py --file "$$file" || exit 1; \
		fi; \
	done
	@echo "Done."

compile: compile-splunk

compile-splunk:
	@$(PYTHON) $(SCRIPTS)/compile.py --backend splunk

inventory:
	@$(PYTHON) $(SCRIPTS)/inventory.py --output RULES.md
	@$(PYTHON) $(SCRIPTS)/inventory.py --json --output rules_manifest.json
	@echo "Written: RULES.md and rules_manifest.json"

lint:
	@find $(RULES_DIR) -name "*.yml" -exec yamllint -d relaxed {} +

new-rule:
	@$(PYTHON) $(SCRIPTS)/new_rule.py

clean:
	@rm -rf compiled/splunk
	@echo "Cleaned"
