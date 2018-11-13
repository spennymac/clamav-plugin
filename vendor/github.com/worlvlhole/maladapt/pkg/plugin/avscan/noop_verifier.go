package avscan

//NoOpVerifier if verification isn't needed
type NoOpVerifier struct{}

//NewNoopVerifier creates a new NoopVerifier
func NewNoopVerifier() *NoOpVerifier {
	return &NoOpVerifier{}
}

//Verify returns the given error. This is useful
//if the scanner doesn't exit with any weird status codes
func (v NoOpVerifier) Verify(err error) error {
	return err
}
