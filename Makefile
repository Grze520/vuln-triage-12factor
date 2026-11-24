IMAGE_NAME := vuln-triage-12factor
IMAGE_TAG := 1.0.0

.PHONY: all secrets sast sca iac build scan-image clean

all: secrets sast sca iac build scan-image
	@echo "===> [SUCCESS] All 6 DevSecOps Quality Gates passed!"

secrets:
	@echo "===> [1/6] Secret Scanning (Gitleaks)..."
	gitleaks detect --source . --no-git --config .gitleaks.toml -v

sast:
	@echo "===> [2/6] Static Application Security Testing (Bandit)..."
	bandit -r app.py admin_seed.py -ll

sca:
	@echo "===> [3/6] Software Composition Analysis (pip-audit)..."
	pip-audit -r requirements.txt

iac:
	@echo "===> [4/6] Dockerfile Misconfiguration Scan (Trivy Config)..."
	trivy config --severity HIGH,CRITICAL --exit-code 1 Dockerfile

build:
	@echo "===> [5/6] Building Hardened Non-Root Container..."
	docker build -t $(IMAGE_NAME):$(IMAGE_TAG) .

scan-image:
	@echo "===> [6/6] Container Image Vulnerability Scan (Trivy Image)..."
	trivy image --severity HIGH,CRITICAL --exit-code 1 $(IMAGE_NAME):$(IMAGE_TAG)

clean:
	docker rm -f api redis 2>/dev/null || true
	docker network rm backend_net 2>/dev/null || true
