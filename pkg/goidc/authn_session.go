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
	// ProtectedParameters contains custom parameters sent by PAR or JAR.
	ProtectedParameters map[string]any `json:"protected_params,omitempty" bson:"protected_params,omitempty"`
	// Store allows developers to store information between user interactions.
	Store                    map[string]any `json:"store,omitempty" bson:"store,omitempty"`
	AdditionalTokenClaims    map[string]any `json:"additional_token_claims,omitempty" bson:"additional_token_claims,omitempty"`
	AdditionalIDTokenClaims  map[string]any `json:"additional_id_token_claims,omitempty" bson:"additional_id_token_claims,omitempty"`
	AdditionalUserInfoClaims map[string]any `json:"additional_user_info_claims,omitempty" bson:"additional_user_info_claims,omitempty"`
	AuthorizationParameters  `bson:"inline"`
	Error                    OAuthError `json:"-" bson:"-"`
}

// UpdateParams updates the session with the parameters from an authorization request.
// The parameters already present in the session have priority.
func (s *AuthnSession) UpdateParams(params AuthorizationParameters) {
	s.AuthorizationParameters = s.AuthorizationParameters.Merge(params)
}

func (s *AuthnSession) SetUserID(userID string) {
	s.Subject = userID
}

func (s *AuthnSession) StoreParameter(key string, value any) {
	if s.Store == nil {
		s.Store = make(map[string]any)
	}
	s.Store[key] = value
}

func (s *AuthnSession) Parameter(key string) any {
	return s.Store[key]
}

func (s *AuthnSession) SetClaimToken(claim string, value any) {
	if s.AdditionalTokenClaims == nil {
		s.AdditionalTokenClaims = make(map[string]any)
	}
	s.AdditionalTokenClaims[claim] = value
}

func (s *AuthnSession) SetACRClaimIDToken(acr AuthenticationContextReference) {
	s.SetClaimIDToken(ClaimAuthenticationContextReference, acr)
}

func (s *AuthnSession) SetAuthTimeClaimIDToken(authTime int) {
	s.SetClaimIDToken(ClaimAuthenticationTime, authTime)
}

func (s *AuthnSession) SetAMRClaimIDToken(amrs ...AuthenticationMethodReference) {
	s.SetClaimIDToken(ClaimAuthenticationMethodReferences, amrs)
}

func (s *AuthnSession) SetClaimIDToken(claim string, value any) {
	if s.AdditionalIDTokenClaims == nil {
		s.AdditionalIDTokenClaims = make(map[string]any)
	}
	s.AdditionalIDTokenClaims[claim] = value
}

func (s *AuthnSession) SetACRClaimUserInfo(acr AuthenticationContextReference) {
	s.SetClaimUserInfo(ClaimAuthenticationContextReference, acr)
}

func (s *AuthnSession) SetAuthTimeClaimUserInfo(authTime int) {
	s.SetClaimUserInfo(ClaimAuthenticationTime, authTime)
}

func (s *AuthnSession) SetAMRClaimUserInfo(amrs ...AuthenticationMethodReference) {
	s.SetClaimUserInfo(ClaimAuthenticationMethodReferences, amrs)
}

func (s *AuthnSession) SetClaimUserInfo(claim string, value any) {
	if s.AdditionalUserInfoClaims == nil {
		s.AdditionalUserInfoClaims = make(map[string]any)
	}
	s.AdditionalUserInfoClaims[claim] = value
}

func (s *AuthnSession) IsExpired() bool {
	return TimestampNow() > s.ExpiresAtTimestamp
}

// Push creates a session that can be referenced by a request URI.
func (s *AuthnSession) Push(lifetimeSecs int) (requestURI string, err error) {
	requestURI, err = RequestURI()
	if err != nil {
		return "", err
	}

	s.RequestURI = requestURI
	s.ExpiresAtTimestamp = TimestampNow() + lifetimeSecs
	return requestURI, nil
}

// Start prepares the session to be used while the authentication flow defined by policyID happens.
func (s *AuthnSession) Start(policyID string, lifetimeSecs int) OAuthError {
	if s.Nonce != "" {
		s.SetClaimIDToken(ClaimNonce, s.Nonce)
	}
	s.PolicyID = policyID
	callbackID, err := CallbackID()
	if err != nil {
		return s.NewRedirectError(ErrorCodeInternalError, err.Error())
	}
	s.CallbackID = callbackID
	// FIXME: To think about:Treating the request_uri as one-time use will cause problems when the user refreshes the page.
	s.RequestURI = ""
	s.ExpiresAtTimestamp = TimestampNow() + lifetimeSecs
	return nil
}

func (s *AuthnSession) InitAuthorizationCode() OAuthError {
	code, err := AuthorizationCode()
	if err != nil {
		return s.NewRedirectError(ErrorCodeInternalError, err.Error())
	}
	s.AuthorizationCode = code
	s.ExpiresAtTimestamp = TimestampNow() + AuthorizationCodeLifetimeSecs
	return nil
}

func (s *AuthnSession) GrantScopes(scopes string) {
	s.GrantedScopes = scopes
}

// GrantAuthorizationDetails sets the authorization details the client will have permissions to use.
// This will only have effect if support for authorization details was enabled.
func (s *AuthnSession) GrantAuthorizationDetails(authDetails []AuthorizationDetail) {
	s.GrantedAuthorizationDetails = authDetails
}

func (s *AuthnSession) SetRedirectError(errorCode ErrorCode, errorDescription string) {
	s.Error = s.NewRedirectError(errorCode, errorDescription)
}
