package main

import (
	"errors"
	"testing"
)

type parsePortArgsReturn struct {
	results []int
	failed error
}

type parsePortsArgTest struct {
	arg1 string
	expected parsePortArgsReturn
}

var parsePortArgTests = []parsePortsArgTest{
	{"443", parsePortArgsReturn{[]int{443}, nil}},
	{"443,8443", parsePortArgsReturn{[]int{443}, nil}},
	{"443:445", parsePortArgsReturn{[]int{443,444,445}, nil}},
	{"443:445,8443", parsePortArgsReturn{[]int{443,444,445,8443}, nil}},
	//{"70000", parsePortArgsReturn{[]int{}, errors.New("no valid ports parsed")}},
}

func compareIntSlices(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i:= range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestParsePortsArg(t *testing.T) {
	for _, test := range parsePortArgTests {
		output, err := parsePortsArg(test.arg1)
		if test.expected.failed != nil && errors.Is(err,test.expected.failed) {
			t.Errorf("Error %q not equal to expected %q", err, test.expected.failed)
		}
		if !compareIntSlices(output, test.expected.results) {
			t.Errorf("Output %q not equal to expected %q", output, test.expected.results)
		}
	}
}