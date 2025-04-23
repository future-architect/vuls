package sbom

import (
	"fmt"
	"strings"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/package-url/packageurl-go"

	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/models"
)

func osPkgToPURL(osFamily, osVersion string, pkg models.Package) *packageurl.PackageURL {
	var pType string
	switch osFamily {
	case constant.Alma, constant.Amazon, constant.CentOS, constant.Fedora, constant.OpenSUSE, constant.OpenSUSELeap, constant.Oracle, constant.RedHat, constant.Rocky, constant.SUSEEnterpriseDesktop, constant.SUSEEnterpriseServer:
		pType = packageurl.TypeRPM
	case constant.Alpine:
		pType = packageurl.TypeApk
	case constant.Debian, constant.Raspbian, constant.Ubuntu:
		pType = packageurl.TypeDebian
	case constant.FreeBSD:
		pType = "pkg"
	case constant.Windows:
		pType = "win"
	case constant.ServerTypePseudo:
		pType = "pseudo"
	default:
		pType = "unknown"
	}

	version := pkg.Version
	if pkg.Release != "" {
		version = fmt.Sprintf("%s-%s", pkg.Version, pkg.Release)
	}

	var qualifiers packageurl.Qualifiers
	if osVersion != "" {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "distro",
			Value: osVersion,
		})
	}
	if pkg.Arch != "" {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "arch",
			Value: pkg.Arch,
		})
	}
	if pkg.Repository != "" {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "repo",
			Value: pkg.Repository,
		})
	}

	return packageurl.NewPackageURL(pType, osFamily, pkg.Name, version, qualifiers, "")
}

func libPkgToPURL(libScanner models.LibraryScanner, lib models.Library) *packageurl.PackageURL {
	if lib.PURL != "" {
		if purl, err := packageurl.FromString(lib.PURL); err == nil {
			return &purl
		}
	}
	pType := purlType(libScanner.Type)
	namespace, name, subpath := parsePkgName(pType, lib.Name)
	return packageurl.NewPackageURL(pType, namespace, name, lib.Version, packageurl.Qualifiers{{Key: "file_path", Value: libScanner.LockfilePath}}, subpath)
}

func ghPkgToPURL(m models.DependencyGraphManifest, dep models.Dependency) *packageurl.PackageURL {
	pType := ghEcosystemToPurlType(m.Ecosystem())
	namespace, name, subpath := parsePkgName(pType, dep.PackageName)
	return packageurl.NewPackageURL(pType, namespace, name, dep.Version(), packageurl.Qualifiers{{Key: "repo_url", Value: m.Repository}, {Key: "file_path", Value: m.Filename}}, subpath)
}

func wpPkgToPURL(wpPkg models.WpPackage) *packageurl.PackageURL {
	return packageurl.NewPackageURL(packageurl.TypeWORDPRESS, wpPkg.Type, wpPkg.Name, wpPkg.Version, packageurl.Qualifiers{{Key: "status", Value: wpPkg.Status}}, "")
}

func purlType(t ftypes.LangType) string {
	switch t {
	case ftypes.Jar, ftypes.Pom, ftypes.Gradle, ftypes.Sbt:
		return packageurl.TypeMaven
	case ftypes.Bundler, ftypes.GemSpec:
		return packageurl.TypeGem
	case ftypes.NuGet, ftypes.DotNetCore, ftypes.PackagesProps:
		return packageurl.TypeNuget
	case ftypes.Composer, ftypes.ComposerVendor:
		return packageurl.TypeComposer
	case ftypes.CondaPkg, ftypes.CondaEnv:
		return packageurl.TypeConda
	case ftypes.PythonPkg, ftypes.Pip, ftypes.Pipenv, ftypes.Poetry, ftypes.Uv:
		return packageurl.TypePyPi
	case ftypes.GoBinary, ftypes.GoModule:
		return packageurl.TypeGolang
	case ftypes.Npm, ftypes.NodePkg, ftypes.Yarn, ftypes.Pnpm:
		return packageurl.TypeNPM
	case ftypes.Cocoapods:
		return packageurl.TypeCocoapods
	case ftypes.Swift:
		return packageurl.TypeSwift
	case ftypes.Hex:
		return packageurl.TypeHex
	case ftypes.Conan:
		return packageurl.TypeConan
	case ftypes.Pub:
		return packageurl.TypePub
	case ftypes.RustBinary, ftypes.Cargo:
		return packageurl.TypeCargo
	case ftypes.Julia:
		return packageurl.TypeJulia
	default:
		return string(t)
	}
}

func ghEcosystemToPurlType(t string) string {
	switch t {
	case "cargo":
		return packageurl.TypeCargo
	case "composer":
		return packageurl.TypeComposer
	case "gomod":
		return packageurl.TypeGolang
	case "pom", "gradle":
		return packageurl.TypeMaven
	case "npm", "yarn", "pnpm":
		return packageurl.TypeNPM
	case "nuget":
		return packageurl.TypeNuget
	case "pipenv", "pip", "poetry":
		return packageurl.TypePyPi
	case "bundler", "gemspec":
		return packageurl.TypeGem
	case "swift":
		return packageurl.TypeSwift
	case "cocoapods":
		return packageurl.TypeCocoapods
	case "hex":
		return packageurl.TypeHex
	case "conan":
		return packageurl.TypeConan
	case "pub":
		return packageurl.TypePub
	default:
		return t
	}
}

func parsePkgName(t, n string) (string, string, string) {
	var subpath string
	switch t {
	case packageurl.TypeMaven, packageurl.TypeGradle:
		n = strings.ReplaceAll(n, ":", "/")
	case packageurl.TypePyPi:
		n = strings.ToLower(strings.ReplaceAll(n, "_", "-"))
	case packageurl.TypeGolang:
		n = strings.ToLower(n)
	case packageurl.TypeNPM:
		n = strings.ToLower(n)
	case packageurl.TypeCocoapods:
		n, subpath, _ = strings.Cut(n, "/")
	}

	index := strings.LastIndex(n, "/")
	if index != -1 {
		return n[:index], n[index+1:], subpath
	}

	return "", n, subpath
}
