package rewrite

import (
	"net/http"
	"net/url"
	"strings"
)

type prefixSwap struct {
	next http.Handler
	from string
	to   string
}

func (p *prefixSwap) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	incoming := req.URL.EscapedPath()
	if strings.HasPrefix(incoming, p.from) {
		req.URL.RawPath = p.to + strings.TrimPrefix(incoming, p.from)
		var err error
		req.URL.Path, err = url.PathUnescape(req.URL.RawPath)
		if err != nil {
			http.Error(w, "bad path", http.StatusBadRequest)
			return
		}
	}
	p.next.ServeHTTP(w, req)
}
