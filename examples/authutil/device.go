package authutil

import (
	"fmt"
	"html/template"
	"net/http"

	"github.com/luikyv/go-oidc/examples/ui"
)

type userCodePage struct {
	BaseURL  string
	Endpoint string
}

func UserCodeHandler(w http.ResponseWriter, r *http.Request) error {
	tmpl := template.Must(template.ParseFS(ui.FS, "usercode.html"))
	err := tmpl.ExecuteTemplate(w, "usercode.html", userCodePage{
		BaseURL:  Issuer,
		Endpoint: "device",
	})
	if err != nil {
		// should be catched by RenderErrorFunc
		return fmt.Errorf("failed render user code page: %w", err)
	}
	return nil
}
