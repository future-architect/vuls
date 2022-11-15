package util

import (
	"compress/bzip2"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/ulikunitz/xz"
	"golang.org/x/exp/maps"
)

func CacheDir() string {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		cacheDir = os.TempDir()
	}
	dir := filepath.Join(cacheDir, "vuls")
	return dir
}

func Unique[T comparable](s []T) []T {
	m := map[T]struct{}{}
	for _, v := range s {
		m[v] = struct{}{}
	}
	return maps.Keys(m)
}

func Read(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.Wrapf(err, "open %s", path)
	}
	defer f.Close()

	switch filepath.Ext(path) {
	case ".gz":
		gr, err := gzip.NewReader(f)
		if err != nil {
			return nil, errors.Wrap(err, "create gzip reader")
		}
		defer gr.Close()

		bs, err := io.ReadAll(gr)
		if err != nil {
			return nil, errors.Wrap(err, "read data")
		}
		return bs, nil
	case ".bz2":
		bs, err := io.ReadAll(bzip2.NewReader(f))
		if err != nil {
			return nil, errors.Wrap(err, "read data")
		}
		return bs, nil
	case ".xz":
		xr, err := xz.NewReader(f)
		if err != nil {
			return nil, errors.Wrap(err, "create xz reader")
		}

		bs, err := io.ReadAll(xr)
		if err != nil {
			return nil, errors.Wrap(err, "read data")
		}
		return bs, nil
	default:
		bs, err := io.ReadAll(f)
		if err != nil {
			return nil, errors.Wrap(err, "read data")
		}
		return bs, nil
	}
}
