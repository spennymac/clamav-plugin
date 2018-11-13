package quarantine

import (
	"errors"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

//Configuration defines the items needed to construct the quarantine
type Configuration struct {
	Path string
	Type string
}

// NewConfigurationFromViper creates a Configuration from the values
// provided by the viper instance
func NewConfigurationFromViper(cfg *viper.Viper) Configuration {
	return NewConfiguration(
		cfg.GetString("quarantine.path"),
		cfg.GetString("quarantine.type"),
	)
}

// NewConfiguration creates a new Configuration from the provided values
func NewConfiguration(path, qType string) Configuration {
	log.WithFields(log.Fields{"func": "NewConfiguration", "path": path, "type": qType}).Info()
	return Configuration{
		Path: path,
		Type: qType,
	}
}

// Validate implements the Validate interface.
func (c *Configuration) Validate() error {
	if c.Path == "" {
		return errors.New("quarantine path not set")
	}

	if c.Type == "" {
		return errors.New("quarantine type not set")
	}

	return nil
}
