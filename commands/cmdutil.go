package commands

import (
	"fmt"

	"github.com/howeyc/gopass"
)

func getPasswd(prompt string) (string, error) {
	for {
		fmt.Print(prompt)
		pass, err := gopass.GetPasswdMasked()
		if err != nil {
			return "", fmt.Errorf("Failed to read password")
		}
		if 0 < len(pass) {
			return string(pass[:]), nil
		}
	}

}
