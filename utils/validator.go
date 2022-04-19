package utils

import (
	"errors"
	"regexp"
)

func ValidateDateFormat(date string) error {
	/*
		This function is validating the date format for this application
	*/
	rDate := regexp.MustCompile(`\d{4}-\d{2}-\d{2}`)
	if !rDate.MatchString(date) {
		return errors.New("dates should be in format YYYY-MM-DD")
	}
	return nil
}

func ValidateSeverityFormat(severity string) error {
	/*
		This function is validating that the severity is either LOW, MEDIUM, HIGH or CRITICAL
	*/
	rSeverity := regexp.MustCompile(`LOW|MEDIUM|HIGH|CRITICAL`)
	if !rSeverity.MatchString(severity) {
		return errors.New("severity is not valid, it should be LOW or MEDIUM or HIGH or CRITICAL")
	}
	return nil
}
