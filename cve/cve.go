package cve

import (
	"errors"
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

	if err := utils.ValidateDateFormat(c.DayBegin); err != nil {
		return []NistData{}, err
	}

	if err := utils.ValidateDateFormat(c.DayEnd); err != nil {
		return []NistData{}, err
	}

	if err := utils.ValidateSeverityFormat(c.Severity); err != nil {
		return []NistData{}, err
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
