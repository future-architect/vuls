package subcmds

import (
	"os"
	"path/filepath"
)

func mkdirDotVuls() error {
	home, err := os.UserHomeDir()
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
