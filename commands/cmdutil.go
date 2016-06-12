package commands

import (
	"fmt"

	log "github.com/Sirupsen/logrus"
	"github.com/howeyc/gopass"
)

func getPassword(prompt string) (string, error) {
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

func askKeyPassword() (keyPassword string, err error) {
	prompt := "SSH key password: "

	if keyPassword, err = getPassword(prompt); err != nil {
		log.Error(err)
		return "", err
	}
	return
}

func askBecomePassword(becomeMethod string) (becomePassword string, err error) {
	var prompt string

	switch becomeMethod {
	case "su":
		prompt = "su password: "
		log.Warn("su is executed without password")
		log.Warn("If you can not exececute su without password, ssh will hang. Please stop this process by Ctrl-C")
		return "", nil
	case "sudo", "":
		prompt = "sudo password: "
	default:
		return "", fmt.Errorf("BecomeMethod: unsupported method %s", becomeMethod)
	}

	if becomePassword, err = getPassword(prompt); err != nil {
		log.Error(err)
		return "", err
	}
	return
}
