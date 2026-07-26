package main

import "os"

func emit(payload string) {
	f, _ := os.Create("/tmp/out.log")
	f.Write([]byte(payload))
	f.Close()
}
