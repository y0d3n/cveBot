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
	errCheck(err)
	url := string(b)

	// slackのwebhookよしなに
	data := `{"text":"Hello from golang(use secret.txt)"}`
	req, err := http.NewRequest(
		"POST",
		url,
		bytes.NewBuffer([]byte(data)),
	)
	errCheck(err)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	errCheck(err)
	body, err := ioutil.ReadAll(resp.Body)
	errCheck(err)
	defer resp.Body.Close()

	fmt.Println(string(body))
}

func errCheck(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
