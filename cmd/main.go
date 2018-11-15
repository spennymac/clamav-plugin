package main

import (
	"strings"
	"log/syslog"
	"github.com/ncw/rclone/fs"
	"github.com/spf13/viper"
	log "github.com/sirupsen/logrus"
	lSyslog "github.com/sirupsen/logrus/hooks/syslog"
	"github.com/hashicorp/go-plugin"

	_ "github.com/ncw/rclone/backend/local"
	_ "github.com/ncw/rclone/backend/swift"

	"github.com/worlvlhole/maladapt/pkg/quarantine"
	"github.com/worlvlhole/maladapt/pkg/plugin"
	"github.com/worlvlhole/maladapt/pkg/plugin/avscan"
	
	"github.com/worlvlhole/clamav-plugin/internal/clamav"
)

const (
	envPrefix     = "MAL"
)

func main() {	
	log.SetFormatter(&log.JSONFormatter{})
	hook, err := lSyslog.NewSyslogHook("", "", syslog.LOG_DEBUG, "virustotal")
	if err != nil {
		log.Error("could not setup syslog logger")
	} else {
		log.AddHook(hook)
	}

	log.Info("Starting clamav plugin")
	replacer := strings.NewReplacer(".", "_")
	viper.SetEnvKeyReplacer(replacer)
	viper.SetEnvPrefix(envPrefix)
	viper.AutomaticEnv()

	avCfg := avscan.NewConfigurationFromViper(viper.GetViper())
	if err := avCfg.Validate(); err != nil {
		log.Fatal(err)
	}

	theFs, err := fs.NewFs(avCfg.QuarantineConfig.Path)
	if err != nil {
		log.Fatal(err)
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

	pluginMap := map[string]plugin.Plugin{
		"av_scanner": &plugins.AVScannerGRPCPlugin{Impl: scanner},
	}

	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: plugins.HandshakeConfig,
		Plugins: pluginMap,
		GRPCServer: plugin.DefaultGRPCServer,
	})


}