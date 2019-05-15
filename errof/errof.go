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
)

// New :
func New(code ErrorCode, msg string) Error {
	return Error{
		Code:    code,
		Message: msg,
	}
}
