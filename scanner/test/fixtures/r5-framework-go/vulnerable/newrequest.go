package main

import "net/http"

func fetch(w http.ResponseWriter, r *http.Request) {
	req, _ := http.NewRequest("GET", r.URL.Query().Get("url"), nil)
	http.DefaultClient.Do(req)
}