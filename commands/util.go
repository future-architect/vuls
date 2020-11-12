package commands

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/howeyc/gopass"
	homedir "github.com/mitchellh/go-homedir"
	"golang.org/x/xerrors"
)

func getPasswd(prompt string) (string, error) {
	for {
		fmt.Print(prompt)
		pass, err := gopass.GetPasswdMasked()
		if err != nil {
			return "", xerrors.New("Failed to read a password")
		}
		if 0 < len(pass) {
			return string(pass), nil
		}
	}

}

func mkdirDotVuls() error {
	home, err := homedir.Dir()
	if err != nil {
		return err
	}
	dotVuls := filepath.Join(home, ".vuls")
	if _, err := os.Stat(dotVuls); os.IsNotExist(err) {
		if err := os.Mkdir(dotVuls, 0700); err != nil {
			return err
		}
	}
	return nil
}
