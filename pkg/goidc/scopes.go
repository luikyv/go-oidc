package goidc

import "strings"

var (
	ScopeOpenID         = NewScope("openid")
	ScopeProfile        = NewScope("profile")
	ScopeEmail          = NewScope("email")
	ScopeAddress        = NewScope("address")
	ScopeOffilineAccess = NewScope("offline_access")
)

type Scopes []Scope

func (scopes Scopes) GetIDs() []string {
	scopesIDs := []string{}
	for _, scope := range scopes {
		scopesIDs = append(scopesIDs, scope.String())
	}
	return scopesIDs
}

func (scopes Scopes) GetSubSet(ids []string) Scopes {
	scopesSubSet := []Scope{}
	for _, id := range ids {
		scope, ok := scopes.getScope(id)
		if ok {
			scopesSubSet = append(scopesSubSet, scope)
		}
	}

	return scopesSubSet
}

func (scopes Scopes) ContainsOpenID() bool {
	_, ok := scopes.getScope(ScopeOpenID.ID)
	return ok
}

func (scopes Scopes) Contains(requestedScope string) bool {
	for _, s := range scopes {
		if s.Matches(requestedScope) {
			return true
		}
	}

	return false
}

func (scopes Scopes) String() string {
	scopesAsStrings := []string{}
	for _, scope := range scopes {
		scopesAsStrings = append(scopesAsStrings, scope.ID)
	}
	return strings.Join(scopesAsStrings, " ")
}

func (scopes Scopes) getScope(id string) (Scope, bool) {
	for _, s := range scopes {
		if s.ID == id {
			return s, true
		}
	}

	return Scope{}, false
}

type Scope struct {
	// ID is the string representation of the scope.
	// Its value will be exported as is.
	ID string
	// Matches validates if a requested scope is valid.
	Matches ScopeMatchingFunc
}

type ScopeMatchingFunc func(requestedScope string) bool

// NewScope creates a scope where the validation logic is simple string comparison.
func NewScope(scope string) Scope {
	return Scope{
		ID: scope,
		Matches: func(requestedScope string) bool {
			return scope == requestedScope
		},
	}
}

/*
NewDynamicScope creates a scope with custom logic that will be used to validate the scopes requested by the client.

	dynamicScope := NewDynamicScope(
		"payment",
		func(requestedScope string) bool {
			return strings.HasPrefix(requestedScope, "payment")
		},
	)

	// This results in true.
	dynamicScope.Matches("payment:30")
*/
func NewDynamicScope(
	scope string,
	matchingFunc ScopeMatchingFunc,
) Scope {
	return Scope{
		ID:      scope,
		Matches: matchingFunc,
	}
}

func (scope Scope) String() string {
	return scope.ID
}
