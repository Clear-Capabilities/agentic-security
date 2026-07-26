package main

import "os"

func identity(payload string) string {
	return payload
}

func emit() {
	msg := identity("status: ok")
	f, _ := os.Create("/tmp/out.log")
	f.Write([]byte(msg))
	f.Close()
}
