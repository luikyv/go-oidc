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

func (session *AuthnSession) Parameter(key string) (any, bool) {
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

func (session *AuthnSession) IsExpired() bool {
	return TimestampNow() > session.ExpiresAtTimestamp
}

// Push creates a session that can be referenced by a request URI.
func (session *AuthnSession) Push(parLifetimeSecs int) (requestURI string, err error) {
	requestURI, err = RequestURI()
	if err != nil {
		return "", err
	}

	session.RequestURI = requestURI
	session.ExpiresAtTimestamp = TimestampNow() + parLifetimeSecs
	return requestURI, nil
}

// Start prepares the session to be used while the authentication flow defined by policyID happens.
func (session *AuthnSession) Start(policyID string, sessionLifetimeSecs int) OAuthError {
	if session.Nonce != "" {
		session.AddIDTokenClaim(ClaimNonce, session.Nonce)
	}
	session.PolicyID = policyID
	callbackID, err := CallbackID()
	if err != nil {
		return session.NewRedirectError(ErrorCodeInternalError, err.Error())
	}
	session.CallbackID = callbackID
	// FIXME: To think about:Treating the request_uri as one-time use will cause problems when the user refreshes the page.
	session.RequestURI = ""
	session.ExpiresAtTimestamp = TimestampNow() + sessionLifetimeSecs
	return nil
}

func (session *AuthnSession) InitAuthorizationCode() OAuthError {
	code, err := AuthorizationCode()
	if err != nil {
		return session.NewRedirectError(ErrorCodeInternalError, err.Error())
	}
	session.AuthorizationCode = code
	session.ExpiresAtTimestamp = TimestampNow() + AuthorizationCodeLifetimeSecs
	return nil
}

func (session *AuthnSession) GrantScopes(scopes string) {
	session.GrantedScopes = scopes
}

// GrantAuthorizationDetails sets the authorization details the client will have permissions to use.
// This will only have effect if support for authorization details was enabled.
func (session *AuthnSession) GrantAuthorizationDetails(authDetails []AuthorizationDetail) {
	session.GrantedAuthorizationDetails = authDetails
}

func (session *AuthnSession) SetRedirectError(errorCode ErrorCode, errorDescription string) {
	session.Error = session.NewRedirectError(errorCode, errorDescription)
}
