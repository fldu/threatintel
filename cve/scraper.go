package cve

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/fldu/threatintel/utils"
)

func getNISTPage(c utils.Config, page int, wg *sync.WaitGroup, outChan chan<- NistData) {
	/*
		This function is the scraper on its own. It's retrieving the data from NIST website
	*/
	defer wg.Done()

	var data NistDataRaw
	startIndex := strconv.Itoa(page * 2000)
	url := "https://services.nvd.nist.gov/rest/json/cves/1.0/?pubStartDate=" + c.DayBegin + "T00:00:00:000%20UTC&pubEndDate=" + c.DayEnd + "T23:59:59:000%20UTC&resultsPerPage=2000&cvssV3Severity=" + c.Severity + "&startIndex=" + startIndex

	client := http.Client{
		Timeout: time.Second * 10,
	}
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	r, err := client.Do(req)
	if err != nil {
		return
	}
	defer r.Body.Close()

	body, _ := ioutil.ReadAll(r.Body)
	err = json.Unmarshal(body, &data)
	if err != nil {
		return
	}
	for _, cveData := range data.Result.CVEItems {
		outChan <- NistData{
			CVEid:              cveData.Cve.CVEDataMeta.ID,
			Description:        cveData.Cve.Description.DescriptionData[0].Value,
			ReferenceUrl:       cveData.Cve.References.ReferenceData[0].URL,
			ReferenceSource:    cveData.Cve.References.ReferenceData[0].Refsource,
			AttackVector:       cveData.Impact.BaseMetricV3.CvssV3.AttackVector,
			AttackComplexity:   cveData.Impact.BaseMetricV3.CvssV3.AttackComplexity,
			PrivilegeRequired:  cveData.Impact.BaseMetricV3.CvssV3.PrivilegesRequired,
			UserInteraction:    cveData.Impact.BaseMetricV3.CvssV3.UserInteraction,
			IntegrityImpact:    cveData.Impact.BaseMetricV3.CvssV3.IntegrityImpact,
			AvailabilityImpact: cveData.Impact.BaseMetricV3.CvssV3.AvailabilityImpact,
			BaseScore:          cveData.Impact.BaseMetricV3.CvssV3.BaseScore,
		}
	}
}

func calculateNistLastPage(c utils.Config) (int, error) {
	/*
		NIST API is only allowing maximum 2000 results per page. Idea is to make a first query with one result
		in order to get the total of results, and then be able to properly parallelize the retrieval of
		informations
	*/
	var data NistDataRaw
	url := "https://services.nvd.nist.gov/rest/json/cves/1.0/?modStartDate=" + c.DayBegin + "T00:00:00:000%20UTC&modEndDate=" + c.DayEnd + "T00:00:00:000%20UTC&resultsPerPage=1&cvssV3Severity=" + c.Severity

	client := http.Client{
		Timeout: 10 * time.Second,
	}
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	r, err := client.Do(req)
	if err != nil {
		return 0, errors.New("problem while contacting NIST servers: " + err.Error())
	}
	defer r.Body.Close()

	b, _ := ioutil.ReadAll(r.Body)
	err = json.Unmarshal(b, &data)
	if err != nil {
		return 0, errors.New("problem while parsing NIST data: " + err.Error())
	}
	if data.TotalResults%2000 > 0 && data.TotalResults >= 2000 {
		return data.TotalResults/2000 + 1, nil
	}
	return data.TotalResults / 2000, nil
}
