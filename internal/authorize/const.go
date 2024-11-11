package authorize

const (
	callbackIDLength              int    = 20
	parRequestURIPrefix           string = "urn:ietf:params:oauth:request_uri:"
	parRequestURILength           int    = 20
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
		<form id="form" method="post" action="{{ .redirect_uri }}">
			<input type="hidden" name="code" value="{{ .code }}"/>
			<input type="hidden" name="state" value="{{ .state }}"/>
			<input type="hidden" name="access_token" value="{{ .access_token }}"/>
			<input type="hidden" name="token_type" value="{{ .token_type }}"/>
			<input type="hidden" name="id_token" value="{{ .id_token }}"/>
			<input type="hidden" name="response" value="{{ .response }}"/>
			<input type="hidden" name="error" value="{{ .error }}"/>
			<input type="hidden" name="error_description" value="{{ .error_description }}"/>
		</form>
	</body>

	<script>
		var form = document.getElementByID('form');
		form.addEventListener('formdata', function(event) {
			let formData = event.formData;
			for (let [name, value] of Array.from(formData.entries())) {
				if (value === '') formData.delete(name);
			}
		});
	</script>

	</html>
`
)
