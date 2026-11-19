package main

import (
	"html"
	"net/http"
)

func banner(w http.ResponseWriter, r *http.Request) {
	msg := r.FormValue("msg")
	w.Write([]byte("<div class=\"banner\">" + html.EscapeString(msg) + "</div>"))
}

func main() {
	http.HandleFunc("/banner", banner)
	http.ListenAndServe(":8080", nil)
}
