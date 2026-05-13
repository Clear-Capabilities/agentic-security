package main

import (
	"net/http"
	"os/exec"
	"text/template"
)

func badProxy(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	resp, _ := http.Get(target)
	defer resp.Body.Close()
}

func badNewReq(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	req, _ := http.NewRequest("GET", target, nil)
	http.DefaultClient.Do(req)
}

func badExec(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("cmd")
	exec.Command("sh", "-c", cmd).Run()
}

func badTemplate(w http.ResponseWriter, r *http.Request) {
	t := template.Must(template.New("p").Parse("<h1>{{.Title}}</h1>"))
	t.Execute(w, map[string]string{"Title": r.URL.Query().Get("t")})
}
