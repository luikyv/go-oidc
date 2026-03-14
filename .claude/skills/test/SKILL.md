---
name: test
description: >
  Create or fix Go tests for the go-oidc project. Ensures tests validate
  both the implemented behavior and the correct behavior per the relevant
  OIDC/OAuth specifications. Use when writing, reviewing, or fixing tests.
---

# Test Skill

You are writing tests for **go-oidc**, a Go OpenID Connect Provider library. Tests must validate both the implementation's behavior and correctness per the relevant OIDC/OAuth specifications.

## Workflow

1. **Parse `$ARGUMENTS`**: Determine if it is a file path, function name, or behavior description.
2. **Find the code under test**: Use Glob/Grep to locate the relevant source files and read them.
3. **Identify applicable specs**: Consult the spec reference table below. If unsure about the correct behavior, fetch the spec (use WebFetch on the RFC/spec URL) to verify what the standard requires.
4. **Write or fix tests**: Follow the project conventions below exactly. Cover both happy paths AND error conditions mandated by the spec.
5. **Run tests**: Execute `go test ./<package>/... -run <TestName> -v` to verify. Fix failures iteratively.
6. **Lint**: Run `make lint` and fix any issues.

## Spec-Compliance Mandate

Before writing any test, identify which specification sections govern the behavior under test. Then:

- **Test what the spec requires**, not just what the code currently does. If the code is wrong per spec, note it.
- **Test error conditions** the spec mandates (e.g., RFC 6749 §5.2 error responses, required error codes).
- **Test boundary conditions** from the spec (e.g., token lifetimes, required claims, required parameters).
- Add a brief comment at the top of each test or test group referencing the spec section, e.g.:
  ```go
  // TestGenerateGrant_AuthzCodeGrant_PKCERequired tests that the token endpoint
  // rejects authorization code requests without a code_verifier when PKCE is
  // required (RFC 7636 §4.6).
  ```

## Project Test Conventions

### Structure: Arrange-Act-Assert with Comments

Every test MUST use these exact comment markers:

```go
func TestFunctionName_Scenario(t *testing.T) {
    // Given.
    ctx := oidctest.NewContext(t)
    client, secret := oidctest.NewClient(t)
    // ... setup ...

    // When.
    result, err := FunctionUnderTest(ctx, args)

    // Then.
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    // ... assertions ...
}
```

### Naming Convention

`Test<FunctionName>_<Scenario>` where `<Scenario>` is a concise description of the case:

```
TestGenerateGrant_UnsupportedGrantType
TestGenerateGrant_ClientNotFound
TestAuthenticated_SecretPostAuthn_InvalidSecret
TestExtractID_OpaqueToken
```

### Context and Client Setup

```go
ctx := oidctest.NewContext(t)
client, secret := oidctest.NewClient(t)

// Save client to context's in-memory store.
if err := ctx.SaveClient(client); err != nil {
    t.Fatalf("error setting up: %v", err)
}
```

Configure the context directly for the scenario being tested:

```go
ctx.Request = httptest.NewRequest(http.MethodPost, "/token", nil)
ctx.Request.PostForm = map[string][]string{
    "grant_type": {"authorization_code"},
    "code":       {"test_code"},
}
```

### Assertions — Pure Go + go-cmp

Do NOT use testify. Use native Go checks and `google/go-cmp`:

```go
// Simple checks.
if err != nil {
    t.Fatalf("unexpected error: %v", err)
}

// Struct/map comparison.
if diff := cmp.Diff(got, want, cmpopts.EquateEmpty()); diff != "" {
    t.Error(diff)
}

// Approximate comparison (for timestamps).
if diff := cmp.Diff(claims, wantClaims, cmpopts.EquateApprox(0, 1)); diff != "" {
    t.Error(diff)
}

// Ignore specific map entries.
if diff := cmp.Diff(claims, wantClaims,
    cmpopts.IgnoreMapEntries(func(k string, _ any) bool {
        return k == "jti"
    }),
); diff != "" {
    t.Error(diff)
}
```

### Error Assertions

```go
// Expect a specific OIDC error code.
var oidcErr goidc.Error
if !errors.As(err, &oidcErr) {
    t.Fatal("invalid error type")
}
if oidcErr.Code != goidc.ErrorCodeInvalidRequest {
    t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidRequest)
}
```

### Helper Functions

Always mark helpers with `t.Helper()`:

```go
func setUpScenario(t *testing.T) (oidc.Context, *goidc.Client) {
    t.Helper()
    ctx := oidctest.NewContext(t)
    client, _ := oidctest.NewClient(t)
    // ... configure ...
    return ctx, client
}
```

### Table-Driven Tests

Use when multiple scenarios test the same function with different inputs:

```go
testCases := []struct {
    name    string
    input   string
    want    bool
}{
    {"valid input", "value", true},
    {"empty input", "", false},
}

for _, tc := range testCases {
    t.Run(tc.name, func(t *testing.T) {
        got := FunctionUnderTest(tc.input)
        if got != tc.want {
            t.Errorf("FunctionUnderTest(%q) = %v, want %v", tc.input, got, tc.want)
        }
    })
}
```
