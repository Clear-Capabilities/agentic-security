package main

import (
	"net/http"
	"os/exec"
)

func run(w http.ResponseWriter, r *http.Request) {
	tool := r.Header.Get("X-Tool")
	exec.Command(tool, "--version").Run()
}