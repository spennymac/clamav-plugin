package main

import (
	"github.com/ncw/rclone/fs"
	"github.com/spf13/viper"

	"github.com/worlvlhole/maladapt/pkg/quarantine"
	"github.com/worlvlhole/maladapt/pkg/ipc"
	"github.com/worlvlhole/maladapt/pkg/plugin"
	"github.com/worlvlhole/maladapt/pkg/plugin/avscan"
	
	"github.com/worlvlhole/clamav/internal/clamav"
)

type clam struct {
	scanner *avscan.Scanner
}

func newClam(cfg *viper.Viper) (*clam, error) {
	avCfg := avscan.NewConfigurationFromViper(cfg)
	if err := avCfg.Validate(); err != nil {
		return nil, err
	}

	theFs, err := fs.NewFs(avCfg.QuarantineConfig.Path)
	if err != nil {
		return nil, err
	}

	//Parser
	parser := clamav.NewParser()

	//Verifier
	verifier := clamav.NewVerifier()

	//Quarantiner
	quarantine := quarantine.NewQuarantine(avCfg.QuarantineConfig, theFs)

	//Scanner
	scanner := avscan.NewScanner(
		avCfg.ProgramName,
		avCfg.ProgramPath,
		avCfg.ProgramArgs,
		avCfg.LocalQuarantineZone,
		avCfg.ScanTimeout,
		parser,
		verifier,
		quarantine,
	)

	return &clam{scanner: scanner}, nil
}

func (c *clam) Scan(scan ipc.Scan) (plugins.Result, error) {
	return c.scanner.Scan(scan)
}

//NewPlugin creates the plugin to be used by the plugin module
func NewPlugin() (plugins.Plugin, error) {
	plugin, err := newClam(viper.GetViper())

	if err != nil {
		return nil, err
	}

	return plugin, nil
}
