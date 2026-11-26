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

// defaultTrivyCacheDir returns the default Trivy cache directory.
// This replaces trivy/pkg/cache.DefaultDir() to avoid importing the heavy
// cache package, which pulls in DB and OCI dependencies.
func defaultTrivyCacheDir() string {
	tmpDir, err := os.UserCacheDir()
	if err != nil {
		tmpDir = os.TempDir()
	}
	return filepath.Join(tmpDir, "trivy")
}
