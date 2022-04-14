package cve

import (
	"strconv"
	"testing"

	"github.com/fldu/threatintel/utils"
)

func TestGetNISTDataValid(t *testing.T) {
	c := utils.Config{
		DayBegin: "2020-10-10",
		DayEnd:   "2020-12-20",
		Severity: "LOW",
	}
	output, err := GetNISTData(c)
	if err != nil {
		t.Error(err.Error())
	}
	if len(output) != 124 {
		t.Error("something is wrong, expected result is 124, result is: " + strconv.Itoa(len(output))) // There is exactly 124 LOW vulnerabilities for this timeframe
	}
}

func TestGetNISTDataWrongDate(t *testing.T) {
	c := utils.Config{
		DayBegin: "hello",
		DayEnd:   "2020-12-20",
		Severity: "LOW",
	}
	_, err := GetNISTData(c)
	if err == nil {
		t.Error("date sanitization broken")
	}
}

func TestGetNISTDataIncoherentDate(t *testing.T) {
	c := utils.Config{
		DayBegin: "2021-12-20",
		DayEnd:   "2020-12-20",
		Severity: "LOW",
	}
	output, _ := GetNISTData(c)
	if len(output) > 0 {
		t.Error("there is an issue at NIST level, incoherent dates are returning something")
	}
}

func TestGetNISTDataWrongSeverity(t *testing.T) {
	c := utils.Config{
		DayBegin: "2020-10-10",
		DayEnd:   "2020-12-20",
		Severity: "test",
	}
	_, err := GetNISTData(c)
	if err == nil {
		t.Error("severity sanitization broken")
	}
}
