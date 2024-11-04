package token

import "testing"

func BenchmarkHandleCreate_AuthzCodeGrant(b *testing.B) {
	ctx, _, _ := setUpAuthzCodeGrant(b)
	for i := 0; i < b.N; i++ {
		handleCreate(ctx)
	}
}

func BenchmarkHandleCreate_RefreshTokenGrant(b *testing.B) {
	ctx, _, _ := setUpRefreshTokenGrant(b)
	for i := 0; i < b.N; i++ {
		handleCreate(ctx)
	}
}

func BenchmarkHandleCreate_ClientCredentialsGrant(b *testing.B) {
	ctx, _ := setUpClientCredentialsGrant(b)
	for i := 0; i < b.N; i++ {
		handleCreate(ctx)
	}
}

func BenchmarkHandleCreate_JWTBearerGrant(b *testing.B) {
	ctx, _ := setUpClientCredentialsGrant(b)
	for i := 0; i < b.N; i++ {
		handleCreate(ctx)
	}
}
