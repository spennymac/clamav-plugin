package quarantine

import (
	"compress/gzip"
	"io"
)

func newZipWriter(w io.Writer) (io.WriteCloser, error) {
	//Create gzip writer
	gz, err := gzip.NewWriterLevel(w, gzip.BestSpeed)
	if err != nil {
		return nil, err
	}
	return gz, nil
}

func newZipReader(r io.Reader) (io.ReadCloser, error) {
	gzReader, err := gzip.NewReader(r)
	if err != nil {
		return nil, err
	}
	return gzReader, nil
}
