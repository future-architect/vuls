package errof

// ErrorCode is vuls error code
type ErrorCode string

// Error is vuls error
type Error struct {
	Code    ErrorCode `json:"code"`
	Message string    `json:"message"`
}

func (e Error) Error() string {
	return e.Message
}

var (
	// ErrIPUnreachable is error that ping is unreachable
	ErrIPUnreachable ErrorCode = "ErrIPUnreachable"

	// ErrSSHConfig is error of ssh config
	ErrSSHConfig ErrorCode = "ErrSSHConfig"

	// ErrUncategorized is an uncategorized error other than ErrIPUnreachable and ErrSSHConfig
	ErrUncategorized ErrorCode = "ErrUncategorized"

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
