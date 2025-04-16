package main

import (
    "fmt"
    "log"
    "net/http"
    "os"
)

func infoHandler(w http.ResponseWriter, r *http.Request) {
    uid := os.Getuid()
    gid := os.Getgid()
    fmt.Fprintf(w, "Running as UID: %d, GID: %d\n", uid, gid)
}

func main() {
    http.HandleFunc("/info", infoHandler)

    log.Println("Starting HTTP server on :8080")
    log.Fatal(http.ListenAndServe(":8080", nil))
}
