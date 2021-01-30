package errof

// ErrorCode is vuls error code
type ErrorCode string

// Error is vuls error
type Error struct {
	Code    ErrorCode
	Message string
}

func (e Error) Error() string {
	return e.Message
}

var (
	// ErrFailedToAccessGithubAPI is error of github alert's api access
	ErrFailedToAccessGithubAPI ErrorCode = "ErrFailedToAccessGithubAPI"

	// ErrFailedToAccessWpScan is error of wpscan.com api access
	ErrFailedToAccessWpScan ErrorCode = "ErrFailedToAccessWpScan"

	// ErrWpScanAPILimitExceeded is error of wpscan.com api limit exceeded
	ErrWpScanAPILimitExceeded ErrorCode = "ErrWpScanAPILimitExceeded"
)

// New :
func New(code ErrorCode, msg string) Error {
	return Error{
		Code:    code,
		Message: msg,
	}
}
