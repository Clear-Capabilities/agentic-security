package main

import (
	"fmt"
	"html/template"
	"net/http"
)

func hello(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	fmt.Fprintf(w, "<h1>Hello %s</h1>", template.HTMLEscapeString(name))
}

func plain(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "Hello %s\n", name)
}

func main() {
	http.HandleFunc("/hello", hello)
	http.HandleFunc("/plain", plain)
	http.ListenAndServe(":8080", nil)
}
