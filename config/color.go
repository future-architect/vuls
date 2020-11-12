package config

var (
	// Colors has ansi color list
	Colors = []string{
		"\033[32m", // green
		"\033[33m", // yellow
		"\033[36m", // cyan
		"\033[35m", // magenta
		"\033[31m", // red
		"\033[34m", // blue
	}
	// ResetColor is reset color
	ResetColor = "\033[0m"
)
