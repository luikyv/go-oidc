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
	@if [ ! -d "conformance/suite" ]; then \
	  echo "Cloning conformance-suite repository..."; \
	  git clone --branch "release-$(CS_VERSION)" --single-branch --depth=1 https://gitlab.com/openid/conformance-suite.git conformance/suite; \
	  docker compose -f ./conformance/suite/builder-compose.yml run builder; \
	fi
	@docker compose up

cs-oidc-tests:
	@python3 conformance/suite/scripts/run-test-plan.py \
		oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=dynamic_client] ./conformance/oidc_config.json \
		--expected-failures-file ./conformance/oidc_expected_failures.json \
		--export-dir ./conformance

cs-fapi2-tests:
	@python3 conformance/suite/scripts/run-test-plan.py \
		fapi2-message-signing-id1-test-plan[sender_constrain=dpop][client_auth_type=private_key_jwt][openid=openid_connect][fapi_request_method=unsigned][fapi_profile=plain_fapi][fapi_response_mode=plain_response] ./conformance/fapi2_config.json \
		fapi2-security-profile-id2-test-plan[sender_constrain=dpop][client_auth_type=private_key_jwt][openid=openid_connect][fapi_profile=plain_fapi] ./conformance/fapi2_config.json \
		fapi2-security-profile-id2-test-plan[sender_constrain=mtls][client_auth_type=mtls][openid=openid_connect][fapi_profile=plain_fapi] ./conformance/fapi2_mtls_config.json \
		--export-dir ./conformance

cs-fapiciba-tests:
	@python3 conformance/suite/scripts/run-test-plan.py \
		fapi-ciba-id1-test-plan[client_auth_type=private_key_jwt][ciba_mode=poll][fapi_profile=plain_fapi][client_registration=dynamic_client] ./conformance/fapi_ciba_config.json \
		fapi-ciba-id1-test-plan[client_auth_type=private_key_jwt][ciba_mode=ping][fapi_profile=plain_fapi][client_registration=dynamic_client] ./conformance/fapi_ciba_config.json \
		--export-dir ./conformance
