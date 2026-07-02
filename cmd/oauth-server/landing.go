package main

import (
	"html/template"
	"net/http"
	"strings"

	"github.com/akhenakh/quackjwt/permissions"
)

var landingTmpl = template.Must(template.New("landing").Parse(landingHTML))

const landingHTML = `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>QuackJWT OAuth Server</title>
<style>
  body { font-family: system-ui,sans-serif; max-width:720px; margin:2em auto; padding:0 1em; color:#1a1a1a; }
  code { background:#f0f0f0; padding:.15em .35em; border-radius:4px; font-size:.95em; }
  pre { background:#1e1e1e; color:#d4d4d4; padding:1em; border-radius:6px; overflow-x:auto; font-size:.9em; }
  .error { color:#c00; }
  h1 { font-size:1.4em; }
</style>
</head>
<body>
<h1>QuackJWT OAuth Server</h1>
{{if .Error}}
<p class="error">{{.Error}}</p>
{{end}}
{{if .User}}
<p>Connected as <strong>{{.User}}</strong>.</p>
<p>Use this token in DuckDB:</p>
<pre>INSTALL quack; LOAD quack;
ATTACH 'quack:{{.Host}}' AS remote (
    TOKEN '{{.TruncatedToken}}',
    DISABLE_SSL false
);</pre>
{{else}}
<p>Include your JWT in the <code>Authorization: Bearer &lt;token&gt;</code> header to authenticate.</p>
{{end}}
</body>
</html>`

type landingData struct {
	User           string
	TruncatedToken string
	Host           string
	Error          string
}

func landingHandler(pm *permissions.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := strings.Cut(r.Host, ":")
		data := landingData{Host: host}

		auth := r.Header.Get("Authorization")
		if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
			_ = landingTmpl.Execute(w, data)
			return
		}

		token := strings.TrimPrefix(auth, "Bearer ")
		token = strings.TrimSpace(token)
		user, err := pm.VerifyToken(token)
		if err != nil {
			data.Error = "Invalid token: " + err.Error()
			w.WriteHeader(http.StatusUnauthorized)
			_ = landingTmpl.Execute(w, data)
			return
		}

		data.User = user
		data.TruncatedToken = truncateToken(token)
		_ = landingTmpl.Execute(w, data)
	}
}

func truncateToken(t string) string {
	if b, _, ok := strings.Cut(t, "."); ok {
		return b + ".…"
	}
	if len(t) > 40 {
		return t[:40] + "…"
	}
	return t
}
