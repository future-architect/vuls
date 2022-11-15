package create

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/MakeNowJust/heredoc"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/future-architect/vuls/pkg/cmd/db/create/vulnsrc"
	"github.com/future-architect/vuls/pkg/db"
	"github.com/future-architect/vuls/pkg/util"
)

type DBCreateOption struct {
	Path string
}

func NewCmdCreate() *cobra.Command {
	opts := &DBCreateOption{
		Path: "vuls.db",
	}

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create Vuls DB",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return create(args[0], opts.Path)
		},
		Example: heredoc.Doc(`
			$ vuls db create https://github.com/vulsio/vuls-data.git
			$ vuls db create /home/MaineK00n/.cache/vuls
		`),
	}

	cmd.Flags().StringVarP(&opts.Path, "path", "p", "vuls.db", "path to create Vuls DB")

	return cmd
}

func create(src, dbpath string) error {
	datapath := src
	if u, err := url.Parse(src); err == nil && u.Scheme != "" {
		cloneDir := filepath.Join(util.CacheDir(), "clone")
		if err := exec.Command("git", "clone", "--depth", "1", src, cloneDir).Run(); err != nil {
			return errors.Wrapf(err, "git clone --depth 1 %s %s", src, cloneDir)
		}
		datapath = cloneDir
	}
	if _, err := os.Stat(datapath); err != nil {
		return errors.Wrapf(err, "%s not found", datapath)
	}

	db, err := db.Open("boltdb", dbpath, false)
	if err != nil {
		return errors.Wrap(err, "open db")
	}
	defer db.Close()

	if err := filepath.WalkDir(datapath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		p := strings.TrimPrefix(strings.TrimPrefix(path, datapath), string(os.PathSeparator))
		srcType, p, found := strings.Cut(p, string(os.PathSeparator))
		if !found {
			return nil
		}
		advType, p, found := strings.Cut(p, string(os.PathSeparator))
		if !found {
			return errors.Errorf(`unexpected filepath. expected: "%s/["official", ...]/["vulnerability", "os", "library", "cpe"]/...", actual: "%s"`, datapath, path)
		}

		bs, err := util.Read(path)
		if err != nil {
			return errors.Wrapf(err, "read %s", path)
		}
		if len(bs) == 0 {
			return nil
		}

		switch advType {
		case "vulnerability":
			var src vulnsrc.Vulnerability
			if err := json.Unmarshal(bs, &src); err != nil {
				return errors.Wrapf(err, "unmarshal json. path: %s", path)
			}
			if err := db.PutVulnerability(srcType, fmt.Sprintf("vulnerability:%s", src.ID), vulnsrc.ToVulsVulnerability(src)); err != nil {
				return errors.Wrap(err, "put vulnerability")
			}
		case "os":
			advType, err := toAdvType(p)
			if err != nil {
				return errors.Wrap(err, "path to adv type")
			}
			bucket, err := toAdvBucket(p)
			if err != nil {
				return errors.Wrap(err, "path to adv bucket")
			}

			switch advType {
			case "redhat_oval":
				if strings.Contains(p, "repository_to_cpe.json") {
					var src vulnsrc.RepositoryToCPE
					if err := json.Unmarshal(bs, &src); err != nil {
						return errors.Wrapf(err, "unmarshal json. path: %s", path)
					}
					if err := db.PutRedHatRepoToCPE(srcType, bucket, vulnsrc.ToVulsRepositoryToCPE(src)); err != nil {
						return errors.Wrap(err, "put repository to cpe")
					}
					break
				}
				var src vulnsrc.DetectPackage
				if err := json.Unmarshal(bs, &src); err != nil {
					return errors.Wrapf(err, "unmarshal json. path: %s", path)
				}
				pkgs, err := vulnsrc.ToVulsPackage(src, advType)
				if err != nil {
					return errors.Wrap(err, "to vuls package")
				}
				if err := db.PutPackage(srcType, bucket, pkgs); err != nil {
					return errors.Wrap(err, "put package")
				}
			case "windows":
				if strings.Contains(p, "supercedence.json") {
					var supercedences []vulnsrc.Supercedence
					if err := json.Unmarshal(bs, &supercedences); err != nil {
						return errors.Wrapf(err, "unnmarshal json. path: %s", path)
					}
					if err := db.PutWindowsSupercedence(srcType, bucket, vulnsrc.ToVulsSupercedences(supercedences)); err != nil {
						return errors.Wrap(err, "put supercedence")
					}
					break
				}
				var src vulnsrc.DetectPackage
				if err := json.Unmarshal(bs, &src); err != nil {
					return errors.Wrapf(err, "unmarshal json. path: %s", path)
				}
				pkgs, err := vulnsrc.ToVulsPackage(src, advType)
				if err != nil {
					return errors.Wrap(err, "to vuls package")
				}
				if err := db.PutPackage(srcType, bucket, pkgs); err != nil {
					return errors.Wrap(err, "put package")
				}
			default:
				var src vulnsrc.DetectPackage
				if err := json.Unmarshal(bs, &src); err != nil {
					return errors.Wrapf(err, "unmarshal json. path: %s", path)
				}
				pkgs, err := vulnsrc.ToVulsPackage(src, advType)
				if err != nil {
					return errors.Wrap(err, "to vuls package")
				}
				if err := db.PutPackage(srcType, bucket, pkgs); err != nil {
					return errors.Wrap(err, "put package")
				}
			}
		case "library":
		case "cpe":
			var src vulnsrc.DetectCPE
			if err := json.Unmarshal(bs, &src); err != nil {
				return errors.Wrapf(err, "unmarshal json. path: %s", path)
			}

			advType, err := toAdvType(p)
			if err != nil {
				return errors.Wrap(err, "path to adv type")
			}
			cs, err := vulnsrc.ToVulsCPEConfiguration(src, advType)
			if err != nil {
				return errors.Wrap(err, "to vuls cpe configuration")
			}
			bucket, err := toAdvBucket(p)
			if err != nil {
				return errors.Wrap(err, "path to adv bucket")
			}

			if err := db.PutCPEConfiguration(srcType, bucket, cs); err != nil {
				return errors.Wrap(err, "put cpe configuration")
			}
		}

		return nil
	}); err != nil {
		return err
	}

	return nil
}

func toAdvType(path string) (string, error) {
	ss := strings.Split(path, string(os.PathSeparator))
	if len(ss) < 3 && ss[0] != "windows" {
		return "", errors.Errorf(`unexpected path. accepts: "[<os name>, <library name>, "nvd", "jvn"]/**/*.json*", received: "%s"`, path)
	}

	switch ss[0] {
	case "alma", "alpine", "amazon", "epel", "fedora", "oracle", "rocky":
		return fmt.Sprintf("%s:%s", ss[0], ss[1]), nil
	case "arch", "freebsd", "gentoo", "windows", "conan", "erlang", "nvd", "jvn":
		return ss[0], nil
	case "debian":
		switch ss[1] {
		case "oval":
			return "debian_oval", nil
		case "tracker":
			return "debian_security_tracker", nil
		default:
			return "", errors.Errorf(`unexpected debian advisory type. accepts: ["oval", "tracker"], received: "%s"`, ss[1])
		}
	case "redhat":
		switch ss[1] {
		case "api":
			return "redhat_security_api", nil
		case "oval":
			return "redhat_oval", nil
		default:
			return "", errors.Errorf(`unexpected redhat advisory type. accepts: ["api", "oval"], received: "%s"`, ss[1])
		}
	case "suse":
		switch ss[1] {
		case "cvrf":
			return "suse_cvrf", nil
		case "oval":
			return "suse_oval", nil
		default:
			return "", errors.Errorf(`unexpected suse advisory type. accepts: ["cvrf", "oval"], received: "%s"`, ss[1])
		}
	case "ubuntu":
		switch ss[1] {
		case "oval":
			return "ubuntu_oval", nil
		case "tracker":
			return "ubuntu_security_tracker", nil
		default:
			return "", errors.Errorf(`unexpected debian advisory type. accepts: ["oval", "tracker"], received: "%s"`, ss[1])
		}
	case "cargo":
		switch ss[1] {
		case "db":
			return "cargo_db", nil
		case "ghsa":
			return "cargo_ghsa", nil
		case "osv":
			return "cargo_osv", nil
		default:
			return "", errors.Errorf(`unexpected cargo advisory type. accepts: ["db", "ghsa", "osv"], received: "%s"`, ss[1])
		}
	case "composer":
		switch ss[1] {
		case "db":
			return "composer_db", nil
		case "ghsa":
			return "composer_ghsa", nil
		case "glsa":
			return "composer_glsa", nil
		default:
			return "", errors.Errorf(`unexpected composer advisory type. accepts: ["db", "ghsa", "glsa"], received: "%s"`, ss[1])
		}
	case "golang":
		switch ss[1] {
		case "db":
			return "golang_db", nil
		case "ghsa":
			return "golang_ghsa", nil
		case "glsa":
			return "golang_glsa", nil
		case "govulndb":
			return "golang_govulndb", nil
		case "osv":
			return "golang_osv", nil
		default:
			return "", errors.Errorf(`unexpected golang advisory type. accepts: ["db", "ghsa", "glsa", "govulndb", "osv"], received: "%s"`, ss[1])
		}
	case "maven":
		switch ss[1] {
		case "ghsa":
			return "maven_ghsa", nil
		case "glsa":
			return "maven_glsa", nil
		default:
			return "", errors.Errorf(`unexpected maven advisory type. accepts: ["ghsa", "glsa"], received: "%s"`, ss[1])
		}
	case "npm":
		switch ss[1] {
		case "db":
			return "npm_db", nil
		case "ghsa":
			return "npm_ghsa", nil
		case "glsa":
			return "npm_glsa", nil
		case "osv":
			return "npm_osv", nil
		default:
			return "", errors.Errorf(`unexpected npm advisory type. accepts: ["db", "ghsa", "glsa", "osv"], received: "%s"`, ss[1])
		}
	case "nuget":
		switch ss[1] {
		case "ghsa":
			return "nuget_ghsa", nil
		case "glsa":
			return "nuget_glsa", nil
		case "osv":
			return "nuget_osv", nil
		default:
			return "", errors.Errorf(`unexpected nuget advisory type. accepts: ["ghsa", "glsa", "osv"], received: "%s"`, ss[1])
		}
	case "pip":
		switch ss[1] {
		case "db":
			return "pip_db", nil
		case "ghsa":
			return "pip_ghsa", nil
		case "glsa":
			return "pip_glsa", nil
		case "osv":
			return "pip_osv", nil
		default:
			return "", errors.Errorf(`unexpected pip advisory type. accepts: ["db", "ghsa", "glsa", "osv"], received: "%s"`, ss[1])
		}
	case "rubygems":
		switch ss[1] {
		case "db":
			return "rubygems_db", nil
		case "ghsa":
			return "rubygems_ghsa", nil
		case "glsa":
			return "rubygems_glsa", nil
		case "osv":
			return "rubygems_osv", nil
		default:
			return "", errors.Errorf(`unexpected rubygems advisory type. accepts: ["db", "ghsa", "glsa", "osv"], received: "%s"`, ss[1])
		}
	default:
		return "", errors.Errorf(`unexpected os or library or cpe. accepts: ["alma", "alpine", "amazon", "arch", "debian", "epel", "fedora", "freebsd", "gentoo", "oracle", "redhat", "rocky", "suse", "ubuntu", "windows", "cargo", "composer", "conan", "erlang", "golang", "maven", "npm", "nuget", "pip", "rubygems", "nvd", "jvn"], received: "%s"`, ss[0])
	}
}

func toAdvBucket(path string) (string, error) {
	ss := strings.Split(path, string(os.PathSeparator))
	if len(ss) < 3 && ss[0] != "windows" {
		return "", errors.Errorf(`unexpected path. accepts: "[<os name>, <library name>, "nvd", "jvn"]/**/*.json*", received: "%s"`, path)
	}

	switch ss[0] {
	case "alma", "alpine", "amazon", "epel", "fedora", "oracle", "rocky":
		return fmt.Sprintf("%s:%s", ss[0], ss[1]), nil
	case "arch", "freebsd", "gentoo", "cargo", "composer", "conan", "erlang", "golang", "maven", "npm", "nuget", "pip", "rubygems":
		return ss[0], nil
	case "debian":
		switch ss[1] {
		case "oval", "tracker":
			return fmt.Sprintf("%s:%s", ss[0], ss[2]), nil
		default:
			return "", errors.Errorf(`unexpected debian advisory type. accepts: ["oval", "tracker"], received: "%s"`, ss[1])
		}
	case "redhat":
		switch ss[1] {
		case "api":
			return fmt.Sprintf("%s:%s", ss[0], ss[2]), nil
		case "oval":
			if len(ss) < 4 {
				return "", errors.Errorf(`unexpected path. accepts: "redhat/oval/<os version>/<stream>/yyyy/*.json*", received: "%s"`, path)
			}
			if strings.Contains(path, "repository_to_cpe.json") {
				return fmt.Sprintf("%s_cpe:%s", ss[0], ss[3]), nil
			}
			return fmt.Sprintf("%s:%s", ss[0], ss[3]), nil
		default:
			return "", errors.Errorf(`unexpected redhat advisory type. accepts: ["api", "oval"], received: "%s"`, ss[1])
		}
	case "suse":
		switch ss[1] {
		case "cvrf", "oval":
			if len(ss) < 4 {
				return "", errors.Errorf(`unexpected path. accepts: "suse/[cvrf, oval]/<os>/<version>/yyyy/*.json*", received: "%s"`, path)
			}
			return fmt.Sprintf("%s:%s", ss[2], ss[3]), nil
		default:
			return "", errors.Errorf(`unexpected suse advisory type. accepts: ["cvrf", "oval"], received: "%s"`, ss[1])
		}
	case "ubuntu":
		switch ss[1] {
		case "oval", "tracker":
			return fmt.Sprintf("%s:%s", ss[0], ss[2]), nil
		default:
			return "", errors.Errorf(`unexpected debian advisory type. accepts: ["oval", "tracker"], received: "%s"`, ss[1])
		}
	case "windows":
		if strings.Contains(path, "supercedence.json") {
			return "windows_supercedence", nil
		}
		return fmt.Sprintf("%s:%s", ss[0], ss[1]), nil
	case "nvd", "jvn":
		return "cpe", nil
	default:
		return "", errors.Errorf(`unexpected os or library or cpe. accepts: ["alma", "alpine", "amazon", "arch", "debian", "epel", "fedora", "freebsd", "gentoo", "oracle", "redhat", "rocky", "suse", "ubuntu", "windows", "cargo", "composer", "conan", "erlang", "golang", "maven", "npm", "nuget", "pip", "rubygems", "nvd", "jvn"], received: "%s"`, ss[0])
	}
}
