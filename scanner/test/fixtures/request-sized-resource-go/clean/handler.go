package api

import (
	"net/http"
	"strconv"
	"strings"
)

const maxFill = 1 << 16

func Fill(w http.ResponseWriter, r *http.Request) {
	n, err := strconv.Atoi(r.URL.Query().Get("n"))
	if err != nil || n > maxFill {
		http.Error(w, "bad n", http.StatusBadRequest)
		return
	}
	buf := make([]byte, n)
	w.Write(buf)
	w.Write([]byte(strings.Repeat("x", n)))
}

func Concat(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	parts := r.Form["part"]
	var b strings.Builder
	for _, p := range parts {
		b.WriteString(p)
	}
	w.Write([]byte(b.String()))
}
