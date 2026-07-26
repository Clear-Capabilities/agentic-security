package main

import "os"

func identity(payload string) string {
	return payload
}

func emit() {
	path := identity("/tmp/out.log")
	os.Open(path)
}
