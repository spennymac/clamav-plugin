package plugins

import (
	"time"

	"github.com/worlvlhole/maladapt/pkg/ipc"
)

// Plugin interface to be implemented by all plugin modules
type Plugin interface {
	Scan(scan ipc.Scan) (Result, error)
}

const (
	//VirusScan result type
	VirusScan string = "VirusScan"
)

//VirusScanResult represents the output of scanning
//a file by a virus scanner
type VirusScanResult struct {
	Positives  int         `json:"positives"`         //number of infected scans
	TotalScans int         `json:"totalScans"`        //total number of scans performed
	Context    interface{} `json:"context,omitempty"` //additional virus scanner specific details
}

//Result represents an individual plugins
//results for scanning a file
type Result struct {
	Time    time.Time   `json:"time"`    //time the scan began
	Type    string      `json:"type"`    //type of scan perfomed
	Details interface{} `json:"details"` //Type specific scan details
}
