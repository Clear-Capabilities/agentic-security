package api

import (
	"net/http"
	"strconv"
	"strings"
)

func Fill(w http.ResponseWriter, r *http.Request) {
	n, err := strconv.Atoi(r.URL.Query().Get("n"))
	if err != nil {
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
	out := ""
	for _, p := range parts {
		out += p
	}
	w.Write([]byte(out))
}
