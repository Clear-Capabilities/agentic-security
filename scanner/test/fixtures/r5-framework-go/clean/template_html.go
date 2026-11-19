package main

import (
	"html/template"
	"net/http"
)

func page(w http.ResponseWriter, r *http.Request) {
	tpl.Execute(w, r.FormValue("bio"))
}
