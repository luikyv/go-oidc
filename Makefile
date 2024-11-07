CS_VERSION = v5.1.22

test:
	@go test ./pkg/... ./internal/...

test-coverage:
	@go test -coverprofile=coverage.out ./pkg/... ./internal/...
	@go tool cover -html="coverage.out" -o coverage.html
	@echo "Total Coverage: `go tool cover -func=coverage.out | grep total | grep -Eo '[0-9]+\.[0-9]+'` %"

test-benchmark:
	@go test -bench=. -benchmem ./pkg/... ./internal/...

# Before running this, install pkgsite with:
# go install golang.org/x/pkgsite/cmd/pkgsite@latest
docs:
	@echo "Docs available at http://localhost:6060/github.com/luikyv/go-oidc"
	@pkgsite -http=:6060

run-cs:
	@if [ ! -d "conformance-suite" ]; then \
	  echo "Cloning conformance-suite repository..."; \
	  git clone --branch "release-$(CS_VERSION)" --single-branch --depth=1 https://gitlab.com/openid/conformance-suite.git; \
	  docker compose -f ./conformance-suite/builder-compose.yml run builder; \
	fi
	@docker compose up
