package main

import (
	"fmt"
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
  .code-block { position:relative; }
  .code-block pre { background:#1e1e1e; color:#d4d4d4; padding:1em; padding-right:3em; border-radius:6px; overflow-x:auto; font-size:.9em; }
  .copy-btn { position:absolute; top:.5em; right:.5em; background:none; border:1px solid #555; border-radius:4px; color:#999; cursor:pointer; padding:3px 6px; font-size:.85em; line-height:1; }
  .copy-btn:hover { color:#fff; border-color:#999; }
  .copy-btn.copied { color:#4caf50; border-color:#4caf50; }
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
<div class="code-block">
<pre id="install-cmd">INSTALL quack; LOAD quack;
ATTACH 'quack:{{.Address}}' AS remote (
    TOKEN '{{.Token}}',
    DISABLE_SSL false
);</pre>
<button class="copy-btn" onclick="copyInstallCmd()" title="Copy to clipboard">&#x2398;</button>
</div>
{{else}}
<p>Include your JWT in the <code>Authorization: Bearer &lt;token&gt;</code> header to authenticate.</p>
{{end}}
<script>
function copyInstallCmd() {
  const text = document.getElementById('install-cmd').innerText;
  navigator.clipboard.writeText(text).then(() => {
    const btn = document.querySelector('.copy-btn');
    btn.classList.add('copied');
    btn.innerHTML = '&#10003;';
    setTimeout(() => {
      btn.classList.remove('copied');
      btn.innerHTML = '&#x2398;';
    }, 2000);
  });
}
</script>
</body>
</html>`

type landingData struct {
	User    string
	Token   string
	Address string
	Error   string
}

func landingHandler(pm *permissions.Manager, cookieName string, externalPort int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := strings.Cut(r.Host, ":")
		address := host
		if externalPort > 0 {
			address = fmt.Sprintf("%s:%d", host, externalPort)
		}
		data := landingData{Address: address}

		var token string
		if c, err := r.Cookie(cookieName); err == nil {
			token = c.Value
		}
		if token == "" {
			if a := r.Header.Get("Authorization"); strings.HasPrefix(a, "Bearer ") {
				token = strings.TrimSpace(strings.TrimPrefix(a, "Bearer "))
			}
		}
		if token == "" {
			_ = landingTmpl.Execute(w, data)
			return
		}

		user, err := pm.VerifyToken(token)
		if err != nil {
			data.Error = "Invalid token: " + err.Error()
			w.WriteHeader(http.StatusUnauthorized)
			_ = landingTmpl.Execute(w, data)
			return
		}

		data.User = user
		data.Token = token
		_ = landingTmpl.Execute(w, data)
	}
}
