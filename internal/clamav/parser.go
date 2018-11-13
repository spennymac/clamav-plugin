package clamav

import (
	"strings"
	"time"

	"github.com/worlvlhole/maladapt/pkg/plugin"
)

//Parser parses clamscan output
type Parser struct{}

const (
	found string = "FOUND"
	ok    string = "OK"
)

//NewParser creates a parser that knows
//how to parse output from clamscan
func NewParser() *Parser {
	return &Parser{}
}

//Parse checks the provided data for clamscan output
func (p Parser) Parse(output []byte) (res plugins.Result) {
	res.Time = time.Now()
	res.Type = plugins.VirusScan

	scanResult := plugins.VirusScanResult{
		Positives:  0,
		TotalScans: 1,
	}

	context := map[string]string{}
	strOutput := string(output)
	lines := strings.Split(strOutput, "\n")
	for _, line := range lines {
		pair := strings.Split(line, ":")

		if len(pair) == 2 {
			if strings.Contains(pair[1], found) {
				scanResult.Positives = scanResult.Positives + 1
				context[found] = strings.TrimSpace(strings.TrimRight(pair[1], found))
				continue
			}

			if strings.Contains(pair[1], ok) {
				continue
			}

			context[pair[0]] = strings.TrimSpace(pair[1])
		}
	}
	scanResult.Context = context
	res.Details = scanResult

	return res
}
