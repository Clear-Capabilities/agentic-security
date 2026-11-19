package main

import "net/http"

func fetch(w http.ResponseWriter, r *http.Request) {
	req, _ := http.NewRequest("GET", "https://api.internal.test/status", nil)
	req.Header.Set("X-Trace", "1")
	http.DefaultClient.Do(req)
}