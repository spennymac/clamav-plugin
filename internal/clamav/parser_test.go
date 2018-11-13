package clamav

import (
	"testing"
	"time"

	"github.com/worlvlhole/maladapt/pkg/plugin"
)

type testData struct {
	input  string
	result plugins.Result
}

var TestTable = []testData{
	{`LibClamAV Warning: Cannot dlopen libclamunrar_iface: file not found - unrar support unavailable
/quarantine_zone/f91fd0505c91af2156892429a0746b93dd3e9322784cc6c947a99ba4629662573: Eicar-Test-Signature FOUND
clamav_1            | 2018/09/27 14:31:32 [INFO]
----------- SCAN SUMMARY -----------
Known viruses: 6661373
Engine version: 0.100.1
Scanned directories: 0
Scanned files: 1
Infected files: 1
Data scanned: 0.00 MB
Data read: 0.00 MB (ratio 0.00:1)
Time: 15.779 sec (0 m 15 s)`,
		plugins.Result{
			Time: time.Now(),
			Type: plugins.VirusScan,
			Details: plugins.VirusScanResult{
				Positives:  1,
				TotalScans: 1,
				Context: map[string]string{
					"FOUND":               "Eicar-Test-Signature",
					"Known viruses":       "6661373",
					"Engine version":      "0.100.1",
					"Scanned directories": "0",
					"Scanned files":       "1",
					"Infected files":      "1",
					"Data scanned":        "0.00 MB",
					"Data read":           "0.00 MB (ratio 0.00:1)",
					"Time":                "15.779 sec (0 m 15 s)",
				},
			},
		},
	},
	{`/quarantine_zone/2c0ca0f9922e478ba853d93b5826529bd05af33a062037702: OK
 ----------- SCAN SUMMARY -----------
 Known viruses: 6661373
 Engine version: 0.100.1
 Scanned directories: 0
 Scanned files: 1
 Infected files: 0
 Data scanned: 0.00 MB
 Data read: 100.00 MB (ratio 0.00:1)
 Time: 15.756 sec (0 m 15 s)`,
		plugins.Result{
			Time: time.Now(),
			Type: plugins.VirusScan,
			Details: plugins.VirusScanResult{
				Positives:  0,
				TotalScans: 1,
				Context: map[string]string{
					"Known viruses":       "6661373",
					"Engine version":      "0.100.1",
					"Scanned directories": "0",
					"Scanned files":       "1",
					"Infected files":      "1",
					"Data scanned":        "0.00 MB",
					"Data read":           "100 MB (ratio 0.00:1)",
					"Time":                "15.756 sec (0 m 15 s)",
				},
			},
		},
	},
}

func TestParser(t *testing.T) {

	parser := NewParser()

	for _, obj := range TestTable {
		result := parser.Parse([]byte(obj.input))

		if result.Type != obj.result.Type {
			t.Fatalf("Expected %s, Parsed %s", obj.result.Type, result.Type)
		}

		parserResults := result.Details.(plugins.VirusScanResult)
		expectedResults := obj.result.Details.(plugins.VirusScanResult)

		if parserResults.TotalScans != expectedResults.TotalScans {
			t.Fatalf("Expected %d scans, Parsed %d", expectedResults.TotalScans, parserResults.TotalScans)
		}

		if parserResults.Positives != expectedResults.Positives {
			t.Fatalf("Expected %d positives, Parsed %d", expectedResults.Positives, parserResults.Positives)
		}

		parserContext := parserResults.Context.(map[string]string)
		expectedContext := parserResults.Context.(map[string]string)

		if len(parserContext) != len(expectedContext) {
			t.Fatalf("Expected %d context results, Parsed %d", len(expectedContext), len(parserContext))
		}

		for k, v := range expectedContext {
			parsed, ok := parserContext[k]
			if !ok {
				t.Fatalf("%s not present in context", k)
			}

			if v != parsed {
				t.Fatalf("Expected %s, Parsed %s", k, parsed)
			}
		}
	}
}
