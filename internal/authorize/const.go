package authorize

const (
	callbackIDLength              int    = 30
	parRequestURIPrefix           string = "urn:ietf:params:oauth:request_uri:"
	parRequestURILength           int    = 30
	cibaAuthReqIDLength           int    = 50
	authorizationCodeLength       int    = 30
	authorizationCodeLifetimeSecs int    = 60 // TODO: Make it a config.
	// formPostResponseTemplate is a HTML document intended to be used as the
	// response mode "form_post".
	// The parameters that are usually sent to the client via redirect will be
	// sent by posting a form to the client's redirect URI.
	// TODO: Check if there's something missing.
	formPostResponseTemplate string = `
	<html>
	<body onload="javascript:document.forms[0].submit()">
	  <form id="auth-response" method="post" action="{{ .redirect_uri }}">
	  	{{ if .iss }}
	    <input type="hidden" name="iss" value="{{ .iss }}"/>
		{{ end }}
	    {{ if .code }}
	    <input type="hidden" name="code" value="{{ .code }}"/>
		{{ end }}
	    {{ if .state }}
		<input type="hidden" name="state" value="{{ .state }}"/>
		{{ end }}
	    {{ if .access_token }}
		<input type="hidden" name="access_token" value="{{ .access_token }}"/>
		{{ end }}
	    {{ if .token_type }}
		<input type="hidden" name="token_type" value="{{ .token_type }}"/>
		{{ end }}
	    {{ if .id_token }}
		<input type="hidden" name="id_token" value="{{ .id_token }}"/>
		{{ end }}
	    {{ if .response }}
		<input type="hidden" name="response" value="{{ .response }}"/>
		{{ end }}
	    {{ if .error }}
		<input type="hidden" name="error" value="{{ .error }}"/>
		{{ end }}
	    {{ if .error_description }}
		<input type="hidden" name="error_description" value="{{ .error_description }}"/>
		{{ end }}
	  </form>
	</body>
	</html>
`
)
