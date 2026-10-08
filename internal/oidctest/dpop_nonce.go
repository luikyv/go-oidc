package oidctest

import (
	"context"
	"fmt"
	"sync"

	"github.com/luikyv/go-oidc/pkg/goidc"
)

type DPoPNonceManager struct {
	mu          sync.Mutex
	valid       map[dpopNonceKey]struct{}
	issueValues []string
	issueCalls  int
	nextValues  []string
	nextCalls   int
}

type dpopNonceKey struct {
	scope goidc.DPoPNonceScope
	nonce string
}

func NewDPoPNonceManager(issueValues ...string) *DPoPNonceManager {
	return &DPoPNonceManager{
		valid:       make(map[dpopNonceKey]struct{}),
		issueValues: issueValues,
	}
}

func (m *DPoPNonceManager) Add(scope goidc.DPoPNonceScope, nonce string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.valid[dpopNonceKey{scope: scope, nonce: nonce}] = struct{}{}
}

func (m *DPoPNonceManager) RotateWith(nonces ...string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextValues = nonces
}

func (m *DPoPNonceManager) IssueNonce(_ context.Context, scope goidc.DPoPNonceScope) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.issueCalls++

	nonce := fmt.Sprintf("fresh_nonce_%d", m.issueCalls)
	if m.issueCalls <= len(m.issueValues) {
		nonce = m.issueValues[m.issueCalls-1]
	}
	m.valid[dpopNonceKey{scope: scope, nonce: nonce}] = struct{}{}
	return nonce, nil
}

func (m *DPoPNonceManager) ValidateNonce(_ context.Context, scope goidc.DPoPNonceScope, nonce string) (goidc.DPoPNonceValidation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := dpopNonceKey{scope: scope, nonce: nonce}
	if _, ok := m.valid[key]; !ok {
		return goidc.DPoPNonceValidation{}, goidc.ErrNotFound
	}
	if m.nextCalls < len(m.nextValues) {
		next := m.nextValues[m.nextCalls]
		m.nextCalls++
		m.valid[dpopNonceKey{scope: scope, nonce: next}] = struct{}{}
		return goidc.DPoPNonceValidation{NextNonce: next}, nil
	}
	return goidc.DPoPNonceValidation{}, nil
}
