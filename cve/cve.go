package cve

import (
	"errors"
	"regexp"
	"sync"

	"github.com/fldu/threatintel/utils"
)

func GetNISTData(c utils.Config) ([]NistData, error) {
	/*
		This function is a wrapper for getNISTPage function and allows us to use goroutines
		and therefore download data much faster in case of a huge dump
	*/
	var output Nist
	var wg sync.WaitGroup
	outChan := make(chan NistData)

	// Here we test that we have a date of beginning and a date of end which are compliant
	rDate := regexp.MustCompile(`\d{4}-\d{2}-\d{2}`)
	if !rDate.MatchString(c.DayBegin) || !rDate.MatchString(c.DayEnd) {
		return []NistData{}, errors.New("dates should be in format YYYY-MM-DD")
	}

	// Here we test that the severity is valid
	rSeverity := regexp.MustCompile(`LOW|MEDIUM|HIGH|CRITICAL`)
	if !rSeverity.MatchString(c.Severity) {
		return []NistData{}, errors.New("severity is not valid, it should be LOW or MEDIUM or HIGH or CRITICAL")
	}

	lastPage, err := calculateNistLastPage(c)
	if err != nil {
		return []NistData{}, errors.New(err.Error())
	}
	for i := 0; i <= lastPage; i++ {
		wg.Add(1)
		go getNISTPage(c, i, &wg, outChan)
	}
	go func() {
		for i := range outChan {
			output.mu.Lock()
			output.Data = append(output.Data, i)
			output.mu.Unlock()
		}
	}()
	wg.Wait()
	close(outChan)
	return output.Data, nil
}
