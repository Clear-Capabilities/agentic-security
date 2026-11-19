package main

import (
	"html"
	"net/http"
)

func hello(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("<p>Hello " + html.EscapeString(r.URL.Query().Get("name")) + "</p>"))
}