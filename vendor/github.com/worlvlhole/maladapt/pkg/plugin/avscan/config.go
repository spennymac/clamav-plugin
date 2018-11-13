package avscan

import (
	"errors"
	"os"
	"time"

	"github.com/ncw/rclone/fs/fspath"
	"github.com/spf13/viper"

	"github.com/worlvlhole/maladapt/pkg/quarantine"
)

//Configuration defines the items needed to launch the clamav plugin
type Configuration struct {
	ProgramName         string
	ProgramPath         string
	ProgramArgs         []string
	LocalQuarantineZone string
	ScanTimeout         time.Duration
	QuarantineConfig    quarantine.Configuration
}

// Validate implements the Validate interface.
func (c *Configuration) Validate() error {
	if c.ProgramName == "" {
		return errors.New("Program name is empty")
	}

	if c.ProgramPath == "" {
		return errors.New("Program path is empty")
	}

	if c.LocalQuarantineZone == "" {
		return errors.New("LocalQuarantineZone name is empty")
	}

	if c.ScanTimeout == time.Second*0 {
		return errors.New("ScanTimeout is 0")
	}

	configName, _ := fspath.Parse(c.LocalQuarantineZone)
	if configName == "" {
		if err := os.MkdirAll(c.LocalQuarantineZone, 0777); err != nil {
			return err
		}
	}

	return c.QuarantineConfig.Validate()
}

// NewConfigurationFromViper creates a Configuration from the values
// provided by the viper instance
func NewConfigurationFromViper(cfg *viper.Viper) Configuration {
	return NewConfiguration(
		cfg.GetString("avscan.program_name"),
		cfg.GetString("avscan.program_path"),
		cfg.GetStringSlice("avscan.program_args"),
		cfg.GetString("avscan.local_quarantine_zone"),
		cfg.GetDuration("avscan.scan_timeout"),
		quarantine.NewConfigurationFromViper(cfg),
	)
}

// NewConfiguration creates a new Configuration from the provided values
func NewConfiguration(
	programName string,
	programPath string,
	programArgs []string,
	localQuarantineZone string,
	scanTimeout time.Duration,
	quarantineConfig quarantine.Configuration,
) Configuration {
	return Configuration{
		ProgramName:         programName,
		ProgramPath:         programPath,
		ProgramArgs:         programArgs,
		LocalQuarantineZone: localQuarantineZone,
		ScanTimeout:         scanTimeout,
		QuarantineConfig:    quarantineConfig,
	}
}
