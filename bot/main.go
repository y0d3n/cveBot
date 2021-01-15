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

	_ "github.com/go-sql-driver/mysql"
)

// Cves はjson用
type Cves struct {
	ResultsPerPage int `json:"resultsPerPage"`
	StartIndex     int `json:"startIndex"`
	TotalResults   int `json:"totalResults"`
	Result         struct {
		CVEDataType      string `json:"CVE_data_type"`
		CVEDataFormat    string `json:"CVE_data_format"`
		CVEDataVersion   string `json:"CVE_data_version"`
		CVEDataTimestamp string `json:"CVE_data_timestamp"`
		CVEItems         []struct {
			Cve struct {
				DataType    string `json:"data_type"`
				DataFormat  string `json:"data_format"`
				DataVersion string `json:"data_version"`
				CVEDataMeta struct {
					ID       string `json:"ID"`
					ASSIGNER string `json:"ASSIGNER"`
				} `json:"CVE_data_meta"`
				Problemtype struct {
					ProblemtypeData []struct {
						Description []struct {
							Lang  string `json:"lang"`
							Value string `json:"value"`
						} `json:"description"`
					} `json:"problemtype_data"`
				} `json:"problemtype"`
				References struct {
					ReferenceData []struct {
						URL       string   `json:"url"`
						Name      string   `json:"name"`
						Refsource string   `json:"refsource"`
						Tags      []string `json:"tags,omitempty"`
					} `json:"reference_data"`
				} `json:"references"`
				Description struct {
					DescriptionData []struct {
						Lang  string `json:"lang"`
						Value string `json:"value"`
					} `json:"description_data"`
				} `json:"description"`
			} `json:"cve"`
			Configurations struct {
				CVEDataVersion string `json:"CVE_data_version"`
				Nodes          []struct {
					Operator string `json:"operator"`
					CpeMatch []struct {
						Vulnerable            bool   `json:"vulnerable"`
						Cpe23URI              string `json:"cpe23Uri"`
						VersionStartIncluding string `json:"versionStartIncluding"`
						VersionEndIncluding   string `json:"versionEndIncluding"`
					} `json:"cpe_match"`
				} `json:"nodes"`
			} `json:"configurations,omitempty"`
			Impact struct {
				BaseMetricV3 struct {
					CvssV3 struct {
						Version               string  `json:"version"`
						VectorString          string  `json:"vectorString"`
						AttackVector          string  `json:"attackVector"`
						AttackComplexity      string  `json:"attackComplexity"`
						PrivilegesRequired    string  `json:"privilegesRequired"`
						UserInteraction       string  `json:"userInteraction"`
						Scope                 string  `json:"scope"`
						ConfidentialityImpact string  `json:"confidentialityImpact"`
						IntegrityImpact       string  `json:"integrityImpact"`
						AvailabilityImpact    string  `json:"availabilityImpact"`
						BaseScore             float64 `json:"baseScore"`
						BaseSeverity          string  `json:"baseSeverity"`
					} `json:"cvssV3"`
					ExploitabilityScore float64 `json:"exploitabilityScore"`
					ImpactScore         float64 `json:"impactScore"`
				} `json:"baseMetricV3"`
				BaseMetricV2 struct {
					CvssV2 struct {
						Version               string  `json:"version"`
						VectorString          string  `json:"vectorString"`
						AccessVector          string  `json:"accessVector"`
						AccessComplexity      string  `json:"accessComplexity"`
						Authentication        string  `json:"authentication"`
						ConfidentialityImpact string  `json:"confidentialityImpact"`
						IntegrityImpact       string  `json:"integrityImpact"`
						AvailabilityImpact    string  `json:"availabilityImpact"`
						BaseScore             float64 `json:"baseScore"`
					} `json:"cvssV2"`
					Severity                string  `json:"severity"`
					ExploitabilityScore     float64 `json:"exploitabilityScore"`
					ImpactScore             float64 `json:"impactScore"`
					AcInsufInfo             bool    `json:"acInsufInfo"`
					ObtainAllPrivilege      bool    `json:"obtainAllPrivilege"`
					ObtainUserPrivilege     bool    `json:"obtainUserPrivilege"`
					ObtainOtherPrivilege    bool    `json:"obtainOtherPrivilege"`
					UserInteractionRequired bool    `json:"userInteractionRequired"`
				} `json:"baseMetricV2"`
			} `json:"impact,omitempty"`
			PublishedDate    string `json:"publishedDate"`
			LastModifiedDate string `json:"lastModifiedDate"`
		} `json:"CVE_Items"`
	} `json:"result"`
}

// Database はcveが通知済みかチェックする用
type Database struct {
	ID   string
	Flag int
}

func main() {
	// nvdからjsonとってきてよしなに
	nvdURL := "https://services.nvd.nist.gov/rest/json/cves/1.0"
	resp, err := http.Get(nvdURL)
	if err != nil {
		log.Fatal(err)
	}

	defer resp.Body.Close()
	byteArray, _ := ioutil.ReadAll(resp.Body)

	jsonBytes := ([]byte)(byteArray)
	cves := new(Cves)

	if err := json.Unmarshal(jsonBytes, cves); err != nil {
		log.Fatal(err)
	}

	// envからslack botのurlを取得
	slackURL := os.Getenv("cveBotUrl")

	msg := ""
	for _, v := range cves.Result.CVEItems {
		if dbCheck(v.Cve.CVEDataMeta.ID) {
			msg = fmt.Sprint("<"+v.Cve.References.ReferenceData[0].URL+"|"+v.Cve.CVEDataMeta.ID+">", "[", v.Impact.BaseMetricV3.ImpactScore, "]", v.Cve.Description.DescriptionData[0].Value)
			// slackのwebhookよしなに
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
			resp, err = client.Do(req)
			if err != nil {
				log.Fatal(err)
			}
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				log.Fatal(err)
			}
			defer resp.Body.Close()

			fmt.Println(string(body))
			setFlag(v.Cve.CVEDataMeta.ID)
		}
	}
}

func dbCheck(id string) bool {
	db, err := sql.Open("mysql", "docker:docker@tcp(localhost:3306)/docker")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	var flag string
	rows, err := db.Query("select flag from docker where id = ?;", id)
	if err != nil {
		log.Fatal("a", err)
	}

	for rows.Next() {
		err := rows.Scan(&flag)
		if err != nil {
			panic(err)
		}
	}
	fmt.Println(id, flag)

	return flag == "0"
}

func setFlag(id string) {
	db, err := sql.Open("mysql", "docker:docker@tcp(localhost:3306)/docker")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	ins, err := db.Prepare("insert into docker values ('?', 1)")
	if err != nil {
		log.Fatal(err)
	}
	ins.Exec(id)
}
