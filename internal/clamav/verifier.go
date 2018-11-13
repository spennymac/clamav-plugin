package clamav

//clamav exits with this status code when malware is detected
var virusFoundExitCode = "exit status 1"

//Verifier verifies exit codes from clamav
type Verifier struct{}

//NewVerifier creates a clamav verifier
func NewVerifier() *Verifier {
	return &Verifier{}
}

//Verify ensures that the error received from shelling out
//to clamscan was indeed an error. Clamscan exits with status
//code 1 if the scan was positive, we don't want to acutally
//consider this an error
func (v Verifier) Verify(err error) error {
	if err == nil {
		return nil
	}

	switch err.Error() {
	case virusFoundExitCode:
		return nil
	default:
		return err
	}
}
