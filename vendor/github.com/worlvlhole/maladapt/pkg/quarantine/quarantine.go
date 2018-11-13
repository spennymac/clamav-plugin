package quarantine

import (
	"bytes"
	"context"
	"io"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/ncw/rclone/fs"
	"github.com/ncw/rclone/fs/object"
	"go.opencensus.io/trace"
)

const (
	// Zip quarantine Writer/Reader
	Zip string = "zip"
)

// Quarantine reads and writes to the configured quarantine area
// via the configured mechanism
type Quarantine struct {
	config     Configuration
	fs         fs.Fs
	openReader func(r io.Reader) (io.ReadCloser, error)
	openWriter func(io.Writer) (io.WriteCloser, error)
}

// NewQuarantine creates a new Quarntine from the provided config
func NewQuarantine(config Configuration, fs fs.Fs) Quarantine {
	logger := log.WithFields(log.Fields{"func": "NewQuarantine"})
	q := Quarantine{config: config, fs: fs}

	switch q.config.Type {
	case Zip:
		q.openWriter = newZipWriter
		q.openReader = newZipReader
	default:
		logger.Fatal("invalid quarantine type provided")
	}

	return q
}

// Location returns the configured quarantine zone
func (q Quarantine) Location() string {
	return q.config.Path
}

// Exists returns if the given file exists
func (q Quarantine) Exists(filename string) bool {
	_, err := q.fs.NewObject(filename)
	if err != nil {
		if err == fs.ErrorObjectNotFound {
			return false
		}
		// We don't really know..
		return false
	}
	return true
}

// OpenFile returns a Reader of the configured type
func (q Quarantine) OpenFile(ctx context.Context, filename string) (io.ReadCloser, error) {
	logger := log.WithFields(log.Fields{"func": "OpenFile"})
	_, span := trace.StartSpan(ctx, "OpenFile")
	defer span.End()

	obj, err := q.fs.NewObject(filename)
	if err != nil {
		logger.Error(err)
		return nil, err
	}

	reader, err := obj.Open()
	if err != nil {
		logger.Error(err)
		return nil, err
	}

	return q.openReader(reader)
}

//Write writes the contents provided to a file in the quarantine location
//of the given filename
func (q Quarantine) Write(ctx context.Context, filename string, contents []byte) error {
	logger := log.WithFields(log.Fields{"func": "Write"})
	_, span := trace.StartSpan(ctx, "Write")
	defer span.End()

	logger.Info("Quarantining ", filename)
	buf := new(bytes.Buffer)
	writer, err := q.openWriter(buf)
	if err != nil {
		if cerr := writer.Close(); cerr != nil {
			logger.Error(cerr)
		}
		return err
	}

	_, err = writer.Write(contents)
	if err != nil {
		if cerr := writer.Close(); cerr != nil {
			logger.Error(cerr)
		}
		return err
	}

	// Writer needs to be close before the buf len can be used
	// if not close it may not reflect the whole file size
	if err := writer.Close(); err != nil {
		return err
	}

	obji := object.NewStaticObjectInfo(filename, time.Now(), int64(buf.Len()), true, nil, nil)
	_, err = q.fs.Put(buf, obji)
	if err != nil {
		return err
	}

	return nil
}
