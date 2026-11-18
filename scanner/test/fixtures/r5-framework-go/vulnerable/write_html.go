package main

import "net/http"

func hello(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("<p>Hello " + r.URL.Query().Get("name") + "</p>"))
}