package subcmds

import (
	"os"
	"path/filepath"

	homedir "github.com/mitchellh/go-homedir"
)

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
