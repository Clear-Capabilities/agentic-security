package main

import (
	"net/http"
	"os/exec"
)

func handler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")

	// The diagnostic below runs ping directly, with no shell,
	// so the host is a single argument.
	//
	// It was added for the support team.

	out, _ := exec.Command("ping", "-c", "1", host).Output()
	w.Write(out)
}
