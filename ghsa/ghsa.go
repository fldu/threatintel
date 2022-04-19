package ghsa

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/fldu/threatintel/utils"
)

func GetGHSAData(c utils.Config) ([]GHSAData, error) {
	url := "https://api.github.com/graphql"

	if err := utils.ValidateDateFormat(c.DayBegin); err != nil {
		return []GHSAData{}, err
	}

	rawPayload := map[string]string{
		"query": `
		{
			securityAdvisories(
				orderBy: {field: PUBLISHED_AT, direction: DESC}
				publishedSince: "` + c.DayBegin + `T00:00:00Z"
				first: 100
			) {
				nodes {
				summary
				description
				ghsaId
				publishedAt
				cvss {
					score
				}
				severity
				permalink
				}
			}
		}
		`,
	} // GitHub API authorizes only 100 SA to be retrieved. But it is very unlikely that more than 100 SA will be made per day, so if more than 24 hours are needed, you have to iterate.
	payload, _ := json.Marshal(rawPayload)
	client := http.Client{
		Timeout: time.Second * 10,
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(payload))
	if err != nil {
		return []GHSAData{}, errors.New("error while creating HTTP client: " + err.Error())
	}
	req.Header.Set("Authorization", "Bearer "+c.GithubToken)
	r, err := client.Do(req)
	if err != nil {
		return []GHSAData{}, errors.New("error while fetching GHSA: " + err.Error())
	}
	respBytes, err := ioutil.ReadAll(r.Body)
	resp := string(respBytes)
	switch {
	case err != nil:
		return []GHSAData{}, errors.New("error while fetching GHSA: " + err.Error())
	case r.StatusCode != 200:
		return []GHSAData{}, errors.New("unexpected error while fetching GHSA: " + resp)
	case r.StatusCode == 200:
		var rawGHSAData GHSADataRaw
		var output []GHSAData
		if err := json.Unmarshal(respBytes, &rawGHSAData); err != nil {
			return []GHSAData{}, errors.New("JSON error while fetching GHSA: " + err.Error())
		}
		for _, i := range rawGHSAData.Data.SecurityAdvisories.Nodes {
			output = append(output, GHSAData{
				Summary:     i.Summary,
				Description: i.Description,
				GHSAID:      i.GhsaID,
				PublishedAt: i.PublishedAt,
				Score:       i.Cvss.Score,
				CVSSScore:   i.Cvss.VectorString,
				Severity:    i.Severity,
				Permalink:   i.Permalink,
			})
		}
		return output, nil
	default:
		return []GHSAData{}, errors.New("uncaught error while fetching GHSA data")
	}
}
