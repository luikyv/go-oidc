# goidc
A customizable OpenID Provider made in Go.

## To Evaluate
* Remove complexity and store all tokens? Most of them will be already stored.
* Add more tests.
* Implement storage with MongoDB.
* Add coverage report and quality checks.
* Implement the revocation endpoint.
* Should I add the default encryption algorithm instead of requiring the dev to pass it?
* Implement the resource parameter.
* Implement a client credentials policy.
* Test the authorization details.
* Should I use "starts with" to validate scopes?
* Symmetric encryption for JAR?
* Support pairwise subject type.
* Add logs and log warnings.
* Create a package.
* Allow the dev to set an error template for /authorize.
* Client jwks is required for JAR.