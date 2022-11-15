package server

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/future-architect/vuls/pkg/cmd/version"
	"github.com/future-architect/vuls/pkg/config"
	"github.com/future-architect/vuls/pkg/detect"
	"github.com/future-architect/vuls/pkg/scan/os"
	"github.com/future-architect/vuls/pkg/scan/ospkg/apk"
	"github.com/future-architect/vuls/pkg/scan/ospkg/dpkg"
	"github.com/future-architect/vuls/pkg/scan/ospkg/rpm"
	"github.com/future-architect/vuls/pkg/scan/systeminfo"
	"github.com/future-architect/vuls/pkg/types"
)

type scanContents struct {
	Contents []struct {
		ContentType string `json:"type,omitempty"`
		Content     string `json:"content,omitempty"`
	} `json:"contents,omitempty"`
}

func Scan() echo.HandlerFunc {
	return func(c echo.Context) error {
		s := new(scanContents)
		if err := c.Bind(s); err != nil {
			return c.JSON(http.StatusBadRequest, "bad request")
		}

		h := types.Host{Name: uuid.NewString()}

		for _, cont := range s.Contents {
			switch cont.ContentType {
			case "os-release":
				family, release, err := os.ParseOSRelease(cont.Content)
				if err != nil {
					h.ScanError = err.Error()
					return c.JSON(http.StatusInternalServerError, h)
				}
				h.Family = family
				h.Release = release
			case "systeminfo":
				family, release, kbs, err := systeminfo.ParseSysteminfo(cont.Content)
				if err != nil {
					h.ScanError = err.Error()
					return c.JSON(http.StatusInternalServerError, h)
				}
				h.Family = family
				h.Release = release
				h.Packages.KB = kbs
			case "apk":
				pkgs, err := apk.ParseInstalledPackage(cont.Content)
				if err != nil {
					h.ScanError = err.Error()
					return c.JSON(http.StatusInternalServerError, h)
				}
				h.Packages.OSPkg = pkgs
			case "dpkg":
				pkgs, err := dpkg.ParseInstalledPackage(cont.Content)
				if err != nil {
					h.ScanError = err.Error()
					return c.JSON(http.StatusInternalServerError, h)
				}
				h.Packages.OSPkg = pkgs
			case "rpm":
				pkgs, err := rpm.ParseInstalledPackage(cont.Content)
				if err != nil {
					h.ScanError = err.Error()
					return c.JSON(http.StatusInternalServerError, h)
				}
				h.Packages.OSPkg = pkgs
			}
		}

		t := time.Now()
		h.ScannedAt = &t
		h.ScannedVersion = version.Version
		h.ScannedRevision = version.Revision
		return c.JSON(http.StatusOK, h)
	}
}

func Detect(dbpath string) echo.HandlerFunc {
	return func(c echo.Context) error {
		h := new(types.Host)
		if err := c.Bind(h); err != nil {
			return c.JSON(http.StatusBadRequest, "bad request")
		}

		if h.Config.Detect == nil {
			h.Config.Detect = &config.Detect{}
		}
		h.Config.Detect.Path = dbpath

		if err := detect.Detect(context.Background(), h); err != nil {
			h.DetectError = err.Error()
			return c.JSON(http.StatusInternalServerError, h)
		}

		return c.JSON(http.StatusOK, h)
	}
}
