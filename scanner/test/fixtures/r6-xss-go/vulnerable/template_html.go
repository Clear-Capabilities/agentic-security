package main

import (
	"html/template"
	"net/http"
)

var page = template.Must(template.New("p").Parse("<div>{{.}}</div>"))

func show(w http.ResponseWriter, r *http.Request) {
	bio := r.URL.Query().Get("bio")
	page.Execute(w, template.HTML(bio))
}

func main() {
	http.HandleFunc("/show", show)
	http.ListenAndServe(":8080", nil)
}
