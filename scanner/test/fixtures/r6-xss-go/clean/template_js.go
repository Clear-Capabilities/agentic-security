package main

import (
	"html/template"
	"net/http"
)

var page = template.Must(template.New("p").Parse("<script>var cfg = {{.}};</script>"))

func cfg(w http.ResponseWriter, r *http.Request) {
	theme := r.FormValue("theme")
	page.Execute(w, template.JSEscapeString(theme))
}

func main() {
	http.HandleFunc("/cfg", cfg)
	http.ListenAndServe(":8080", nil)
}
