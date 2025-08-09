package keys

import "embed"

//go:embed *.crt
//go:embed *.key
//go:embed *.jwks
var FS embed.FS
