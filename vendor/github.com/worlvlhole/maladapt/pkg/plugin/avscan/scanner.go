package avscan

import (
	"context"
	"errors"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/worlvlhole/maladapt/pkg/ipc"
	"github.com/worlvlhole/maladapt/pkg/plugin"
	"github.com/worlvlhole/maladapt/pkg/quarantine"
)

//Parser interface wraps the basic Parse method.
type Parser interface {
	Parse([]byte) plugins.Result
}

//Verifier interface wraps the basic Verify method.
type Verifier interface {
	Verify(error) error
}

//Scanner represents a virus scanner executable
type Scanner struct {
	Executable          string                //name of executable
	ProgramArgs         []string              //args for executable
	LocalQuarantineZone string                //location to store file contents
	scanTimeout         time.Duration         //time to wait before giving up on scan
	parser              Parser                //scanner output parse
	verifier            Verifier              //scanner output verifier
	quarantine          quarantine.Quarantine //quarantine object
}

//NewScanner creates a scanner from the provided params
func NewScanner(programName, programPath string, prorgamArgs []string,
	localQuarantineZone string,
	scanTimeout time.Duration,
	parser Parser,
	verifier Verifier,
	quarantine quarantine.Quarantine,
) *Scanner {
	return &Scanner{
		Executable:          path.Join(programPath, programName),
		ProgramArgs:         prorgamArgs,
		parser:              parser,
		verifier:            verifier,
		quarantine:          quarantine,
		LocalQuarantineZone: localQuarantineZone,
		scanTimeout:         scanTimeout,
	}
}

//Scan implements the Plugin interface to received Scan messages.
// The file in the messages is downloaded to the LocalQuarantineZone
// and the executable is invoked to scan it.
func (s Scanner) Scan(scan ipc.Scan) (plugins.Result, error) {
	logger := log.WithFields(log.Fields{"func": "Scan"})

	//Unquarantine
	reader, err := s.quarantine.OpenFile(context.Background(), scan.Filename)
	defer func() {
		if reader != nil {
			if err := reader.Close(); err != nil {
				logger.Error(err)
			}
		}
	}()
	if err != nil {
		logger.Error(err)
		return plugins.Result{}, err
	}

	//Create temp file
	file, err := ioutil.TempFile(s.LocalQuarantineZone, scan.Filename)
	defer func() {
		if err := file.Close(); err != nil {
			logger.Error(err)
		}

		if file != nil {
			//Delete File
			if err := os.Remove(file.Name()); err != nil {
				logger.Error(err)
			}
		}
	}()
	if err != nil {
		logger.Error(err)
		return plugins.Result{}, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.scanTimeout)
	defer cancel()

	_, err = io.Copy(file, reader)
	if err != nil {
		logger.Error(err)
		return plugins.Result{}, err
	}

	logger.Warning("Initiating scan")
	res, err := s.scan(ctx, file.Name())
	if err != nil {
		logger.Error(err)
		return plugins.Result{}, err
	}
	logger.Warning("Scan complete")

	return res, nil
}

func (s Scanner) scan(ctx context.Context, file string) (plugins.Result, error) {
	logger := log.WithFields(log.Fields{"func": "Scan"})

	var scanCmd *exec.Cmd
	if ctx != nil {
		scanCmd = exec.CommandContext(ctx, s.Executable, append(s.ProgramArgs, file)...)
	} else {
		scanCmd = exec.Command(s.Executable, append(s.ProgramArgs, file)...)
	}

	output, err := scanCmd.CombinedOutput()
	if s.verifier.Verify(err) != nil {
		logger.Error(err)
		return s.parser.Parse(output), err
	}

	if ctx != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return s.parser.Parse(output), errors.New("scan timed out")
		}
	}

	return s.parser.Parse(output), nil
}
