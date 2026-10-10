package main

import (
	"net/http"
	"os/exec"
)

func handler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")

	// The diagnostic below shells out so the operator
	// can see the raw ping output in the response.
	//
	// It was added for the support team.

	out, _ := exec.Command("sh", "-c", "ping -c 1 "+host).Output()
	w.Write(out)
}
