CS_VERSION = v5.1.39

setup-dev:
	@make setup-cs
	@go install golang.org/x/pkgsite/cmd/pkgsite@latest
	@python3 -m pip install httpx

setup-cs:
	@if [ ! -d "conformance-suite" ]; then \
	  echo "Cloning conformance-suite repository..."; \
	  git clone --branch "release-$(CS_VERSION)" --single-branch --depth=1 https://gitlab.com/openid/conformance-suite.git; \
	  docker compose -f ./conformance-suite/builder-compose.yml run builder; \
	fi

	@if [ ! -d "conformance-suite/venv" ]; then \
	  python3 -m venv conformance-suite/venv; \
	  . ./conformance-suite/venv/bin/activate; \
	  python3 -m pip install -r conformance-suite/scripts/requirements.txt; \
	fi

test:
	@go test ./pkg/... ./internal/...

test-coverage:
	@go test -coverprofile=coverage.out ./pkg/... ./internal/...
	@go tool cover -html="coverage.out" -o coverage.html
	@echo "Total Coverage: `go tool cover -func=coverage.out | grep total | grep -Eo '[0-9]+\.[0-9]+'` %"

lint:
	@golangci-lint run ./pkg/... ./internal/...

test-benchmark:
	@go test -bench=. -benchmem ./pkg/... ./internal/...

docs:
	@echo "Docs available at http://localhost:6060/github.com/luikyv/go-oidc"
	@pkgsite -http=:6060

keys:
	@openssl req -x509 -newkey rsa:2048 -keyout examples/keys/server.key -out examples/keys/server.crt -days 365 -nodes \
		-subj "/CN=op"
	@openssl req -x509 -newkey rsa:2048 -keyout examples/keys/client_one.key -out examples/keys/client_one.crt -days 365 -nodes \
		-subj "/CN=client_one"
	@openssl req -x509 -newkey rsa:2048 -keyout examples/keys/client_two.key -out examples/keys/client_two.crt -days 365 -nodes \
		-subj "/CN=client_two"

run-cs:
	@docker compose up

cs-oidc-tests:
	@conformance-suite/venv/bin/python3 conformance-suite/scripts/run-test-plan.py \
		oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=dynamic_client] ./examples/oidc/config.json \
		oidcc-dynamic-certification-test-plan[response_type=code] ./examples/oidc/config.json \
		oidcc-dynamic-certification-test-plan[response_type=id_token] ./examples/oidc/config.json \
		oidcc-dynamic-certification-test-plan[response_type=id_token\ token] ./examples/oidc/config.json \
		oidcc-dynamic-certification-test-plan[response_type=code\ id_token] ./examples/oidc/config.json \
		oidcc-dynamic-certification-test-plan[response_type=code\ token] ./examples/oidc/config.json \
		oidcc-dynamic-certification-test-plan[response_type=code\ id_token\ token] ./examples/oidc/config.json \
		oidcc-formpost-basic-certification-test-plan[server_metadata=discovery][client_registration=dynamic_client] ./examples/oidc/config.json \
		oidcc-formpost-hybrid-certification-test-plan[server_metadata=discovery][client_registration=dynamic_client] ./examples/oidc/config.json \
		oidcc-formpost-implicit-certification-test-plan[server_metadata=discovery][client_registration=dynamic_client] ./examples/oidc/config.json \
		oidcc-rp-initiated-logout-certification-test-plan[response_type=code\ id_token][client_registration=dynamic_client] ./examples/oidc/config.json \
		--expected-failures-file ./examples/oidc/failures.json \
		--export-dir ./examples/oidc \
		--verbose

cs-fapi1-op-mtls-tests:
	@conformance-suite/venv/bin/python3 conformance-suite/scripts/run-test-plan.py \
		fapi1-advanced-final-test-plan[client_auth_type=mtls][fapi_auth_request_method=by_value][fapi_profile=plain_fapi][fapi_response_mode=plain_response] ./examples/fapi1_op_mtls/config.json \
		--export-dir ./examples/fapi1_op_mtls \
		--verbose

cs-fapi1-op-mtls-par-tests:
	@conformance-suite/venv/bin/python3 conformance-suite/scripts/run-test-plan.py \
		fapi1-advanced-final-test-plan[client_auth_type=mtls][fapi_auth_request_method=pushed][fapi_profile=plain_fapi][fapi_response_mode=plain_response] ./examples/fapi1_op_mtls_par/config.json \
		--export-dir ./examples/fapi1_op_mtls_par \
		--verbose

cs-fapi1-op-private-key-tests:
	@conformance-suite/venv/bin/python3 conformance-suite/scripts/run-test-plan.py \
		fapi1-advanced-final-test-plan[client_auth_type=private_key_jwt][fapi_auth_request_method=by_value][fapi_profile=plain_fapi][fapi_response_mode=plain_response] ./examples/fapi1_op_private_key/config.json \
		--export-dir ./examples/fapi1_op_private_key \
		--verbose

cs-fapi1-op-private-key-par-tests:
	@conformance-suite/venv/bin/python3 conformance-suite/scripts/run-test-plan.py \
		fapi1-advanced-final-test-plan[client_auth_type=private_key_jwt][fapi_auth_request_method=pushed][fapi_profile=plain_fapi][fapi_response_mode=plain_response] ./examples/fapi1_op_private_key_par/config.json \
		--export-dir ./examples/fapi1_op_private_key_par \
		--verbose

cs-fapi1-op-mtls-jarm-tests:
	@conformance-suite/venv/bin/python3 conformance-suite/scripts/run-test-plan.py \
		fapi1-advanced-final-test-plan[client_auth_type=mtls][fapi_auth_request_method=by_value][fapi_profile=plain_fapi][fapi_response_mode=jarm] ./examples/fapi1_op_mtls_jarm/config.json \
		--export-dir ./examples/fapi1_op_mtls_jarm \
		--verbose

cs-fapi1-op-mtls-par-jarm-tests:
	@conformance-suite/venv/bin/python3 conformance-suite/scripts/run-test-plan.py \
		fapi1-advanced-final-test-plan[client_auth_type=mtls][fapi_auth_request_method=pushed][fapi_profile=plain_fapi][fapi_response_mode=jarm] ./examples/fapi1_op_mtls_par_jarm/config.json \
		--export-dir ./examples/fapi1_op_mtls_par_jarm \
		--verbose

cs-fapi1-op-private-key-jarm-tests:
	@conformance-suite/venv/bin/python3 conformance-suite/scripts/run-test-plan.py \
		fapi1-advanced-final-test-plan[client_auth_type=private_key_jwt][fapi_auth_request_method=by_value][fapi_profile=plain_fapi][fapi_response_mode=jarm] ./examples/fapi1_op_private_key_jarm/config.json \
		--export-dir ./examples/fapi1_op_private_key_jarm \
		--verbose

cs-fapi1-op-private-key-par-jarm-tests:
	@conformance-suite/venv/bin/python3 conformance-suite/scripts/run-test-plan.py \
		fapi1-advanced-final-test-plan[client_auth_type=private_key_jwt][fapi_auth_request_method=pushed][fapi_profile=plain_fapi][fapi_response_mode=jarm] ./examples/fapi1_op_private_key_par_jarm/config.json \
		--export-dir ./examples/fapi1_op_private_key_par_jarm \
		--verbose

cs-fapi2-sp-op-mtls-mtls-tests:
	@conformance-suite/venv/bin/python3 conformance-suite/scripts/run-test-plan.py \
		fapi2-security-profile-final-test-plan[client_auth_type=mtls][sender_constrain=mtls][openid=openid_connect][fapi_profile=plain_fapi] ./examples/fapi2_sp_op_mtls_mtls/config.json \
		--export-dir ./examples/fapi2_sp_op_mtls_mtls \
		--verbose

cs-fapi2-sp-op-mtls-dpop-tests:
	@conformance-suite/venv/bin/python3 conformance-suite/scripts/run-test-plan.py \
		fapi2-security-profile-final-test-plan[client_auth_type=mtls][sender_constrain=dpop][openid=openid_connect][fapi_profile=plain_fapi] ./examples/fapi2_sp_op_mtls_dpop/config.json \
		--export-dir ./examples/fapi2_sp_op_mtls_dpop \
		--verbose

cs-fapi2-sp-op-private-key-mtls-tests:
	@conformance-suite/venv/bin/python3 conformance-suite/scripts/run-test-plan.py \
		fapi2-security-profile-final-test-plan[client_auth_type=private_key_jwt][sender_constrain=mtls][openid=openid_connect][fapi_profile=plain_fapi] ./examples/fapi2_sp_op_private_key_mtls/config.json \
		--export-dir ./examples/fapi2_sp_op_private_key_mtls \
		--verbose

cs-fapi2-sp-op-private-key-dpop-tests:
	@conformance-suite/venv/bin/python3 conformance-suite/scripts/run-test-plan.py \
		fapi2-security-profile-final-test-plan[client_auth_type=private_key_jwt][sender_constrain=dpop][openid=openid_connect][fapi_profile=plain_fapi] ./examples/fapi2_sp_op_private_key_dpop/config.json \
		--export-dir ./examples/fapi2_sp_op_private_key_dpop \
		--verbose

cs-fapi2-ms-op-jar-tests:
	@conformance-suite/venv/bin/python3 conformance-suite/scripts/run-test-plan.py \
		fapi2-message-signing-final-test-plan[client_auth_type=private_key_jwt][sender_constrain=mtls][authorization_request_type=simple][openid=openid_connect][fapi_request_method=signed_non_repudiation][fapi_profile=plain_fapi][fapi_response_mode=plain_response] ./examples/fapi2_ms_op_jar/config.json \
		--export-dir ./examples/fapi2_ms_op_jar \
		--verbose

cs-fapi2-ms-op-jarm-tests:
	@conformance-suite/venv/bin/python3 conformance-suite/scripts/run-test-plan.py \
			fapi2-message-signing-final-test-plan[client_auth_type=private_key_jwt][sender_constrain=mtls][authorization_request_type=simple][openid=openid_connect][fapi_request_method=unsigned][fapi_profile=plain_fapi][fapi_response_mode=jarm] ./examples/fapi2_ms_op_jarm/config.json \
		--export-dir ./examples/fapi2_ms_op_jarm \
		--verbose

cs-fapi1-tests:
	@conformance-suite/venv/bin/python3 conformance-suite/scripts/run-test-plan.py \
		fapi1-advanced-final-test-plan[client_auth_type=private_key_jwt][fapi_auth_request_method=by_value][fapi_profile=plain_fapi][fapi_response_mode=jarm] ./examples/fapi1/config.json \
		fapi1-advanced-final-test-plan[client_auth_type=mtls][fapi_auth_request_method=by_value][fapi_profile=plain_fapi][fapi_response_mode=jarm] ./examples/fapi1/mtls_config.json \
		fapi1-advanced-final-test-plan[client_auth_type=private_key_jwt][fapi_auth_request_method=pushed][fapi_profile=plain_fapi][fapi_response_mode=jarm] ./examples/fapi1/config.json \
		fapi1-advanced-final-test-plan[client_auth_type=private_key_jwt][fapi_auth_request_method=by_value][fapi_profile=plain_fapi][fapi_response_mode=plain_response] ./examples/fapi1/config.json \
		--export-dir ./examples/fapi1 \
		--verbose

cs-fapiciba-tests:
	@conformance-suite/venv/bin/python3 conformance-suite/scripts/run-test-plan.py \
		fapi-ciba-id1-test-plan[client_auth_type=private_key_jwt][ciba_mode=poll][fapi_profile=plain_fapi][client_registration=dynamic_client] ./examples/fapiciba/config.json \
		fapi-ciba-id1-test-plan[client_auth_type=private_key_jwt][ciba_mode=ping][fapi_profile=plain_fapi][client_registration=dynamic_client] ./examples/fapiciba/config.json \
		--export-dir ./examples/fapiciba \
		--verbose

cs-ssf-tests:
	@conformance-suite/venv/bin/python3 conformance-suite/scripts/run-test-plan.py \
		openid-ssf-transmitter-test-plan[client_auth_type=client_secret_post][ssf_server_metadata=discovery][server_metadata=discovery][ssf_auth_mode=dynamic][ssf_delivery_mode=push][ssf_profile=default][client_registration=static_client] ./examples/ssf/config.json \
		openid-ssf-transmitter-test-plan[client_auth_type=client_secret_post][ssf_server_metadata=discovery][server_metadata=discovery][ssf_auth_mode=dynamic][ssf_delivery_mode=poll][ssf_profile=default][client_registration=static_client] ./examples/ssf/config.json \
		--export-dir ./examples/ssf \
		--verbose
