package goidc

type AuthnSession struct {
	ID                          string                `json:"id" bson:"_id"`
	CallbackID                  string                `json:"callback_id" bson:"callback_id"`
	PolicyID                    string                `json:"policy_id" bson:"policy_id"`
	ExpiresAtTimestamp          int                   `json:"expires_at" bson:"expires_at"`
	CreatedAtTimestamp          int                   `json:"created_at" bson:"created_at"`
	Subject                     string                `json:"sub" bson:"sub"`
	ClientID                    string                `json:"client_id" bson:"client_id"`
	GrantedScopes               string                `json:"granted_scopes" bson:"granted_scopes"`
	GrantedAuthorizationDetails []AuthorizationDetail `json:"granted_authorization_details,omitempty" bson:"granted_authorization_details,omitempty"`
	AuthorizationCode           string                `json:"authorization_code,omitempty" bson:"authorization_code,omitempty"`
	AuthorizationCodeIssuedAt   int                   `json:"authorization_code_issued_at,omitempty" bson:"authorization_code_issued_at,omitempty"`
	// Custom parameters sent by PAR or JAR.
	ProtectedParameters map[string]any `json:"protected_params,omitempty" bson:"protected_params,omitempty"`
	// Allow the developer to store information in memory and, hence, between steps.
	Store                    map[string]any `json:"store,omitempty" bson:"store,omitempty"`
	AdditionalTokenClaims    map[string]any `json:"additional_token_claims,omitempty" bson:"additional_token_claims,omitempty"`
	AdditionalIDTokenClaims  map[string]any `json:"additional_id_token_claims,omitempty" bson:"additional_id_token_claims,omitempty"`
	AdditionalUserInfoClaims map[string]any `json:"additional_user_info_claims,omitempty" bson:"additional_user_info_claims,omitempty"`
	AuthorizationParameters  `bson:"inline"`
	Error                    OAuthError `json:"-" bson:"-"`
}

func (session AuthnSession) GetClaims() (ClaimsObject, bool) {
	if session.Claims == nil {
		return ClaimsObject{}, false
	}
	return *session.Claims, true
}

func (session AuthnSession) GetAuthorizationDetails() ([]AuthorizationDetail, bool) {
	if session.AuthorizationDetails == nil {
		return nil, false
	}
	return session.AuthorizationDetails, true
}

func (session AuthnSession) GetMaxAuthenticationAgeSecs() (int, bool) {
	if session.MaxAuthenticationAgeSecs == nil {
		return 0, false
	}

	return *session.MaxAuthenticationAgeSecs, true
}

func (session AuthnSession) GetACRValues() ([]AuthenticationContextReference, bool) {
	if session.ACRValues == "" {
		return nil, false
	}
	acrValues := []AuthenticationContextReference{}
	for _, acrValue := range SplitStringWithSpaces(session.ACRValues) {
		acrValues = append(acrValues, AuthenticationContextReference(acrValue))
	}
	return acrValues, true
}

// Update the session with the parameters from an authorization request
// The parameters already present in the session have priority.
func (session *AuthnSession) UpdateParams(params AuthorizationParameters) {
	session.AuthorizationParameters = session.AuthorizationParameters.Merge(params)
}

func (session *AuthnSession) SetUserID(userID string) {
	session.Subject = userID
}

func (session *AuthnSession) SaveParameter(key string, value any) {
	if session.Store == nil {
		session.Store = make(map[string]any)
	}
	session.Store[key] = value
}

func (session AuthnSession) GetParameter(key string) (any, bool) {
	value, ok := session.Store[key]
	return value, ok
}

func (session *AuthnSession) AddTokenClaim(claim string, value any) {
	if session.AdditionalTokenClaims == nil {
		session.AdditionalTokenClaims = make(map[string]any)
	}
	session.AdditionalTokenClaims[claim] = value
}

func (session *AuthnSession) AddIDTokenClaim(claim string, value any) {
	if session.AdditionalIDTokenClaims == nil {
		session.AdditionalIDTokenClaims = make(map[string]any)
	}
	session.AdditionalIDTokenClaims[claim] = value
}

func (session *AuthnSession) AddUserInfoClaim(claim string, value any) {
	if session.AdditionalUserInfoClaims == nil {
		session.AdditionalUserInfoClaims = make(map[string]any)
	}
	session.AdditionalUserInfoClaims[claim] = value
}

func (session AuthnSession) IsPushedRequestExpired(parLifetimeSecs int) bool {
	return GetTimestampNow() > session.ExpiresAtTimestamp
}

func (session AuthnSession) IsAuthorizationCodeExpired() bool {
	return GetTimestampNow() > session.ExpiresAtTimestamp
}

func (session AuthnSession) IsExpired() bool {
	return GetTimestampNow() > session.ExpiresAtTimestamp
}

func (session *AuthnSession) Push(parLifetimeSecs int) (requestURI string) {
	session.RequestURI = GenerateRequestURI()
	session.ExpiresAtTimestamp = GetTimestampNow() + parLifetimeSecs
	return session.RequestURI
}

func (session *AuthnSession) Start(policyID string, sessionLifetimeSecs int) {
	if session.Nonce != "" {
		session.AddIDTokenClaim(NonceClaim, session.Nonce)
	}
	session.PolicyID = policyID
	session.CallbackID = GenerateCallbackID()
	// FIXME: To think about:Treating the request_uri as one-time use will cause problems when the user refreshes the page.
	session.RequestURI = ""
	session.ExpiresAtTimestamp = GetTimestampNow() + sessionLifetimeSecs
}

func (session *AuthnSession) InitAuthorizationCode() string {
	session.AuthorizationCode = GenerateAuthorizationCode()
	session.AuthorizationCodeIssuedAt = GetTimestampNow()
	session.ExpiresAtTimestamp = session.AuthorizationCodeIssuedAt + AuthorizationCodeLifetimeSecs
	return session.AuthorizationCode
}

func (session *AuthnSession) GrantScopes(scopes string) {
	session.GrantedScopes = scopes
}

// Set the authorization details the client will have permissions to use.
// This will only have effect if support for authorization details was enabled.
func (session *AuthnSession) GrantAuthorizationDetails(authDetails []AuthorizationDetail) {
	session.GrantedAuthorizationDetails = authDetails
}

func (session AuthnSession) GetAdditionalIDTokenClaims() map[string]any {
	return session.AdditionalIDTokenClaims
}

func (session AuthnSession) GetAdditionalUserInfoClaims() map[string]any {
	return session.AdditionalUserInfoClaims
}

// Get custom protected parameters sent during PAR or JAR.
func (session AuthnSession) GetProtectedParameter(key string) (any, bool) {
	value, ok := session.ProtectedParameters[key]
	return value, ok
}

func (session *AuthnSession) SetRedirectError(errorCode ErrorCode, errorDescription string) {
	session.Error = session.NewRedirectError(errorCode, errorDescription)
}
