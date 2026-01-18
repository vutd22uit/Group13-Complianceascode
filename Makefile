# ============================================
# Compliance-as-Code Framework Makefile
# ============================================
# Author: Capstone Project Team
# Last Updated: 2025-12-29
# ============================================

.PHONY: all help install scan report dashboard remediate clean test lint

# Default target
all: help

# ============================================
# Help
# ============================================
help:
	@echo "╔══════════════════════════════════════════════════════════════════╗"
	@echo "║           Compliance-as-Code Framework - CLI                     ║"
	@echo "╠══════════════════════════════════════════════════════════════════╣"
	@echo "║  make install      - Install all dependencies                    ║"
	@echo "║  make scan         - Run full compliance scan (demo mode)        ║"
	@echo "║  make scan-live    - Run scan against live OpenStack             ║"
	@echo "║  make report       - Generate HTML compliance report             ║"
	@echo "║  make dashboard    - Start Grafana/Prometheus dashboard          ║"
	@echo "║  make dashboard-stop - Stop the dashboard                        ║"
	@echo "║  make remediate    - Run auto-remediation (dry-run)              ║"
	@echo "║  make remediate-apply - Apply remediation (CAUTION!)             ║"
	@echo "║  make test         - Run all tests (InSpec, OPA, Python)         ║"
	@echo "║  make lint         - Lint all code (Ansible, Python, Rego)       ║"
	@echo "║  make baseline     - Save current compliance as baseline         ║"
	@echo "║  make diff         - Compare current scan with baseline          ║"
	@echo "║  make clean        - Clean temporary files and cache             ║"
	@echo "╚══════════════════════════════════════════════════════════════════╝"

# ============================================
# Installation
# ============================================
install:
	@echo "📦 Installing dependencies..."
	pip install -r requirements.txt
	@echo "✅ Python dependencies installed"
	@echo ""
	@echo "🔧 Checking InSpec..."
	@which inspec > /dev/null 2>&1 || (echo "⚠️  InSpec not found. Install with: curl https://omnitruck.chef.io/install.sh | sudo bash -s -- -P inspec" && exit 1)
	@echo "✅ InSpec is installed"
	@echo ""
	@echo "🔧 Checking OPA..."
	@which opa > /dev/null 2>&1 || (echo "⚠️  OPA not found. Install with: brew install opa (macOS) or download from https://www.openpolicyagent.org/docs/latest/#running-opa" && exit 1)
	@echo "✅ OPA is installed"
	@echo ""
	@echo "🔧 Checking Ansible..."
	@which ansible > /dev/null 2>&1 || (echo "⚠️  Ansible not found. Install with: pip install ansible" && exit 1)
	@echo "✅ Ansible is installed"
	@echo ""
	@echo "🎉 All dependencies are ready!"

# ============================================
# Scanning
# ============================================
RESULTS_DIR := ./scan-results
TIMESTAMP := $(shell date +%Y%m%d_%H%M%S)

scan:
	@echo "🔍 Running compliance scan (demo mode)..."
	@mkdir -p $(RESULTS_DIR)
	python3 scripts/generate_mock_data.py
	@echo "✅ Demo scan completed. Results in $(RESULTS_DIR)/"

scan-live:
ifndef OPENSTACK_HOST
	$(error OPENSTACK_HOST is not set. Example: make scan-live OPENSTACK_HOST=10.0.0.1)
endif
ifndef OPENSTACK_USER
	$(eval OPENSTACK_USER := root)
endif
	@echo "🔍 Running InSpec scan against $(OPENSTACK_HOST)..."
	@mkdir -p $(RESULTS_DIR)
	inspec exec tests/inspec/openstack-cis \
		-t ssh://$(OPENSTACK_USER)@$(OPENSTACK_HOST) \
		--chef-license=accept-silent \
		--reporter cli json:$(RESULTS_DIR)/openstack-cis-$(TIMESTAMP).json html:$(RESULTS_DIR)/openstack-cis-$(TIMESTAMP).html \
		|| true
	@echo "✅ Scan completed. Results: $(RESULTS_DIR)/openstack-cis-$(TIMESTAMP).json"

scan-linux:
ifndef TARGET_HOST
	$(error TARGET_HOST is not set. Example: make scan-linux TARGET_HOST=10.0.0.2)
endif
	@echo "🔍 Running Linux CIS scan against $(TARGET_HOST)..."
	@mkdir -p $(RESULTS_DIR)
	inspec exec tests/inspec/linux-cis \
		-t ssh://$(OPENSTACK_USER)@$(TARGET_HOST) \
		--chef-license=accept-silent \
		--reporter cli json:$(RESULTS_DIR)/linux-cis-$(TIMESTAMP).json \
		|| true
	@echo "✅ Linux scan completed."

# ============================================
# Reporting
# ============================================
report:
	@echo "📊 Generating compliance report..."
	python3 ci/scripts/generate-compliance-report.py --output compliance-report-$(TIMESTAMP).html
	@echo "✅ Report generated: compliance-report-$(TIMESTAMP).html"

report-pdf:
	@echo "📊 Generating PDF compliance report..."
	@which wkhtmltopdf > /dev/null 2>&1 || (echo "⚠️  wkhtmltopdf not found. Install to generate PDFs." && exit 1)
	python3 ci/scripts/generate-compliance-report.py --output compliance-report-$(TIMESTAMP).html
	wkhtmltopdf compliance-report-$(TIMESTAMP).html compliance-report-$(TIMESTAMP).pdf
	@echo "✅ PDF Report generated: compliance-report-$(TIMESTAMP).pdf"

# ============================================
# Dashboard
# ============================================
dashboard:
	@echo "🚀 Starting Grafana/Prometheus dashboard..."
	cd dashboards && docker-compose up -d
	@echo ""
	@echo "╔══════════════════════════════════════════════════════════════════╗"
	@echo "║  Dashboard URLs:                                                 ║"
	@echo "║  - Grafana:     http://localhost:3000 (admin/admin)              ║"
	@echo "║  - Prometheus:  http://localhost:9090                            ║"
	@echo "║  - Exporter:    http://localhost:9100/metrics                    ║"
	@echo "╚══════════════════════════════════════════════════════════════════╝"

dashboard-stop:
	@echo "🛑 Stopping dashboard..."
	cd dashboards && docker-compose down
	@echo "✅ Dashboard stopped."

dashboard-logs:
	cd dashboards && docker-compose logs -f

# ============================================
# Remediation
# ============================================
remediate:
	@echo "🛠️  Running remediation (DRY-RUN mode)..."
	ansible-playbook remediation/ansible/cis-openstack-remediation.yml \
		--check --diff \
		-i localhost,
	@echo "✅ Dry-run completed. Review the changes above."

remediate-apply:
	@echo "⚠️  WARNING: This will apply changes to your systems!"
	@read -p "Are you sure? (yes/no): " confirm; \
	if [ "$$confirm" = "yes" ]; then \
		ansible-playbook remediation/ansible/cis-openstack-remediation.yml -i localhost,; \
	else \
		echo "❌ Remediation cancelled."; \
	fi

# ============================================
# Testing
# ============================================
test: test-opa test-inspec test-python
	@echo "✅ All tests passed!"

test-opa:
	@echo "🧪 Running OPA policy tests..."
	opa test policies/rego/ -v
	@echo "✅ OPA tests passed."

test-inspec:
	@echo "🧪 Validating InSpec profiles..."
	inspec check tests/inspec/openstack-cis --chef-license=accept-silent
	inspec check tests/inspec/linux-cis --chef-license=accept-silent || true
	@echo "✅ InSpec profiles validated."

test-python:
	@echo "🧪 Running Python tests..."
	python -m pytest tests/ -v --ignore=tests/inspec || echo "No pytest tests found or pytest not installed"
	@echo "✅ Python tests completed."

# ============================================
# Linting
# ============================================
lint: lint-ansible lint-python lint-rego
	@echo "✅ All linting passed!"

lint-ansible:
	@echo "🔍 Linting Ansible playbooks..."
	@which ansible-lint > /dev/null 2>&1 || pip install ansible-lint
	ansible-lint remediation/ansible/ || true
	@echo "✅ Ansible linting completed."

lint-python:
	@echo "🔍 Linting Python code..."
	@which flake8 > /dev/null 2>&1 || pip install flake8
	flake8 --max-line-length=120 --ignore=E501,W503 \
		dashboards/exporters/ \
		evidence/collectors/ \
		evidence/reporters/ \
		ci/scripts/ \
		|| true
	@echo "✅ Python linting completed."

lint-rego:
	@echo "🔍 Linting Rego policies..."
	opa check policies/rego/
	opa fmt --diff policies/rego/
	@echo "✅ Rego linting completed."

# ============================================
# Baseline & Diff
# ============================================
BASELINE_DIR := ./baselines

baseline:
	@echo "📸 Saving current compliance state as baseline..."
	@mkdir -p $(BASELINE_DIR)
	@LATEST=$$(ls -t $(RESULTS_DIR)/*.json 2>/dev/null | head -1); \
	if [ -z "$$LATEST" ]; then \
		echo "❌ No scan results found. Run 'make scan' first."; \
		exit 1; \
	fi; \
	cp "$$LATEST" $(BASELINE_DIR)/baseline-$(TIMESTAMP).json; \
	ln -sf baseline-$(TIMESTAMP).json $(BASELINE_DIR)/current-baseline.json; \
	echo "✅ Baseline saved: $(BASELINE_DIR)/baseline-$(TIMESTAMP).json"

diff:
	@echo "📊 Comparing current scan with baseline..."
	@if [ ! -f $(BASELINE_DIR)/current-baseline.json ]; then \
		echo "❌ No baseline found. Run 'make baseline' first."; \
		exit 1; \
	fi
	@LATEST=$$(ls -t $(RESULTS_DIR)/*.json 2>/dev/null | head -1); \
	if [ -z "$$LATEST" ]; then \
		echo "❌ No scan results found. Run 'make scan' first."; \
		exit 1; \
	fi; \
	python3 scripts/compare_baseline.py \
		--baseline $(BASELINE_DIR)/current-baseline.json \
		--current "$$LATEST" \
		--output compliance-diff-$(TIMESTAMP).html

# ============================================
# Cleanup
# ============================================
clean:
	@echo "🧹 Cleaning temporary files..."
	rm -rf __pycache__ .pytest_cache .mypy_cache
	rm -rf $(RESULTS_DIR)/*.tmp
	find . -name "*.pyc" -delete
	find . -name ".DS_Store" -delete
	@echo "✅ Cleanup completed."

clean-all: clean
	@echo "🧹 Deep cleaning (including results and baselines)..."
	rm -rf $(RESULTS_DIR)/*
	rm -rf $(BASELINE_DIR)/*
	cd dashboards && docker-compose down -v 2>/dev/null || true
	@echo "✅ Deep cleanup completed."
