PYTHON := python3
SCRIPTS := scripts
RULES_DIR := rules

.DEFAULT_GOAL := help
.PHONY: help install validate validate-strict validate-changed validate-staged compile compile-splunk inventory lint new-rule install-hooks test promote configure-alerts clean

help:
	@echo ""
	@echo "  Detection-as-Code Pipeline"
	@echo "  ────────────────────────────────────────────"
	@echo "  make install              Install dependencies"
	@echo "  make install-hooks        Install git pre-commit hook"
	@echo ""
	@echo "  Validation:"
	@echo "  make validate             Validate ALL rules"
	@echo "  make validate-strict      Validate ALL rules (fail on warnings)"
	@echo "  make validate-changed     Validate only unstaged changed rules"
	@echo "  make validate-staged      Validate only staged (git add) rules"
	@echo ""
	@echo "  Testing:"
	@echo "  make test                 Run all rule test cases"
	@echo "  make test RULE=DET-00001  Run test cases for a single rule"
	@echo ""
	@echo "  Pipeline:"
	@echo "  make compile              Compile all rules to Splunk SPL"
	@echo "  make inventory            Generate RULES.md + rules_manifest.json"
	@echo "  make lint                 YAML lint all rule files"
	@echo "  make new-rule             Scaffold a new rule (interactive)"
	@echo ""
	@echo "  Deployment:"
	@echo "  make configure-alerts     Wire alert actions on deployed Splunk rules"
	@echo ""
	@echo "  Promotion:"
	@echo "  make promote FILE=rules/.../rule.yml   Promote rule to next status"
	@echo "  make promote FILE=rules/.../rule.yml TO=stable   Promote to specific status"
	@echo ""
	@echo "  make clean                Remove compiled output"
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
	@git diff --name-only -- '$(RULES_DIR)/**/*.yml' | \
	grep '\.yml$$' | \
	while IFS= read -r file; do \
		if [ -f "$$file" ]; then \
			echo "  checking: $$file"; \
			$(PYTHON) $(SCRIPTS)/validate.py --file "$$file" || exit 1; \
		fi; \
	done
	@echo "Done."

validate-staged:
	@echo "Validating staged rules..."
	@STAGED=$$(git diff --cached --name-only -- '$(RULES_DIR)/**/*.yml' | grep '\.yml$$'); \
	if [ -z "$$STAGED" ]; then \
		echo "  No staged rule files found. Run 'git add' first."; \
		exit 0; \
	fi; \
	echo "$$STAGED" | while IFS= read -r file; do \
		if [ -f "$$file" ]; then \
			echo "  checking: $$file"; \
			$(PYTHON) $(SCRIPTS)/validate.py --file "$$file" || exit 1; \
		fi; \
	done
	@echo "Done."

test:
ifdef RULE
	@$(PYTHON) $(SCRIPTS)/test_rules.py --rule $(RULE)
else
	@$(PYTHON) $(SCRIPTS)/test_rules.py
endif

compile: compile-splunk


#compile-splunk:
#	@$(PYTHON) $(SCRIPTS)/compile.py --backend splunk


inventory:
	@$(PYTHON) $(SCRIPTS)/inventory.py --output RULES.md
	@$(PYTHON) $(SCRIPTS)/inventory.py --json --output rules_manifest.json
	@echo "Written: RULES.md and rules_manifest.json"

lint:
	@find $(RULES_DIR) -name "*.yml" | xargs yamllint -d relaxed

new-rule:
	@$(PYTHON) $(SCRIPTS)/new_rule.py

configure-alerts:
	@$(PYTHON) $(SCRIPTS)/configure_alerts.py \
		--host localhost \
		--port 8089 \
		--user admin \
		--password $(SPLUNK_PASSWORD)

promote:
ifndef FILE
	@echo "Usage: make promote FILE=rules/tactic/rule.yml"
	@echo "       make promote FILE=rules/tactic/rule.yml TO=stable"
	@exit 1
endif
ifdef TO
	@$(PYTHON) $(SCRIPTS)/promote.py --file $(FILE) --to $(TO)
else
	@$(PYTHON) $(SCRIPTS)/promote.py --file $(FILE)
endif

compile-splunk:
	@$(PYTHON) $(SCRIPTS)/compile.py --backend splunk

compile-sentinel:
	@$(PYTHON) $(SCRIPTS)/compile.py --backend sentinel

compile-all:
	@$(PYTHON) $(SCRIPTS)/compile.py --backend all

coverage:
	@$(PYTHON) $(SCRIPTS)/coverage.py

coverage-html:
	@$(PYTHON) $(SCRIPTS)/coverage.py --html-only

coverage-markdown:
	@$(PYTHON) $(SCRIPTS)/coverage.py --markdown-only

score:
	@$(PYTHON) $(SCRIPTS)/score.py

score-verbose:
	@$(PYTHON) $(SCRIPTS)/score.py --verbose

score-strict:
	@$(PYTHON) $(SCRIPTS)/score.py --fail

notify-test:
	@$(PYTHON) $(SCRIPTS)/notify.py --event pipeline --status success --branch main --dry-run

notify-deploy:
	@$(PYTHON) $(SCRIPTS)/notify.py --event deploy --status success --rules $(RULES) --branch main

check-staleness:
	@$(PYTHON) $(SCRIPTS)/check_staleness.py

check-staleness-strict:
	@$(PYTHON) $(SCRIPTS)/check_staleness.py --fail

clean:
	@rm -rf compiled/splunk
	@echo "Cleaned"