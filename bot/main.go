package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"

	_ "github.com/go-sql-driver/mysql"
)

func main() {
	var msg, description string
	sendSlack := initSlack()
	cves, err := getCves()
	if err != nil {
		sendSlack(fmt.Sprint(err))
		log.Fatal(err)
	}

	// dbに接続
	db, err := sql.Open("mysql", "docker:docker@tcp(localhost:3306)/cves")
	if err != nil {
		sendSlack(fmt.Sprint(err))
		log.Fatal(err)
	}
	defer db.Close()

	for _, v := range cves.Result.CVEItems {
		isnotified, err := isNotified(db, v.Cve.CVEDataMeta.ID, v.LastModifiedDate)
		if err != nil {
			sendSlack(fmt.Sprint(err))
		}
		if isnotified {
			// 通知するメッセージ作成
			if v.LastModifiedDate == v.PublishedDate {
				msg = ":new:"
			} else {
				msg = ":update:"
			}
			description = strings.Replace(v.Cve.Description.DescriptionData[0].Value, "\"", "\\\"", -1)
			msg += fmt.Sprint(" <"+v.Cve.References.ReferenceData[0].URL+"|"+v.Cve.CVEDataMeta.ID+">", "[", v.Impact.BaseMetricV3.ImpactScore, "]", description)

			sendSlack(msg)
			err = update(db, v.Cve.CVEDataMeta.ID, v.LastModifiedDate)
			if err != nil {
				sendSlack(fmt.Sprint(err))
			}
		}
	}
}

// nvdからjsonとってきてよしなに
func getCves() (*Cves, error) {
	var nvdURL string
	nvdURL = "https://services.nvd.nist.gov/rest/json/cves/1.0"
	cves := new(Cves)
	resp, err := http.Get(nvdURL)
	if err != nil {
		return cves, err
	}
	defer resp.Body.Close()
	byteArray, _ := ioutil.ReadAll(resp.Body)
	jsonBytes := ([]byte)(byteArray)
	if err := json.Unmarshal(jsonBytes, cves); err != nil {
		return cves, err
	}
	fmt.Println(cves.Result.CVEDataTimestamp)
	return cves, nil
}

// slackのwebhookよしなに
func initSlack() func(string) {
	var slackURL string
	slackURL = os.Getenv("cveBotUrl")

	return func(msg string) {
		data := `{"text":"` + msg + `"}`
		req, err := http.NewRequest(
			"POST",
			slackURL,
			bytes.NewBuffer([]byte(data)),
		)
		if err != nil {
			log.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			log.Fatal(err)
		}
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Fatal(err)
		}
		defer resp.Body.Close()
		fmt.Println(string(body))
	}
}

// idとdateを元に、通知済みかチェック
func isNotified(db *sql.DB, id string, date string) (bool, error) {
	var mod string
	rows, err := db.Query("select modDate from notified where id = ?;", id)
	if err != nil {
		return false, err
	}

	for rows.Next() {
		err := rows.Scan(&mod)
		if err != nil {
			return false, err
		}
	}
	fmt.Println(id, mod)

	return mod != date, nil
}

// idをもとにdelete(重複削除)して、新しいレコードをinsert
// (updateでは新しいcveを追加できないのでdeleteとinsertに分けた)
func update(db *sql.DB, id string, date string) error {
	dlt, err := db.Prepare("DELETE FROM notified WHERE id=?")
	if err != nil {
		return err
	}
	if _, err := dlt.Exec(id); err != nil {
		return err
	}
	ins, err := db.Prepare("INSERT INTO notified VALUES(?, ?)")
	if err != nil {
		return err
	}
	if _, err := ins.Exec(id, date); err != nil {
		return err
	}
	return nil
}
