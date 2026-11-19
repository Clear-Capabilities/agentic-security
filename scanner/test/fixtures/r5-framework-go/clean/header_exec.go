package main

import (
	"net/http"
	"os/exec"
)

func run(w http.ResponseWriter, r *http.Request) {
	ref := r.Header.Get("X-Ref")
	exec.Command("git", "log", ref).Run()
}