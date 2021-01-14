package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
)

func main() {
	// secret.txtからurlを取得
	b, err := ioutil.ReadFile("secret.txt")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	url := string(b)

	// slackのwebhookよしなに
	data := `{"text":"Hello from golang(use secret.txt)"}`
	req, _ := http.NewRequest(
		"POST",
		url,
		bytes.NewBuffer([]byte(data)),
	)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, _ := client.Do(req)
	body, _ := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()

	fmt.Println(string(body))
}
