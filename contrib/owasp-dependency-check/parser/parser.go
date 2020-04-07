package parser

import (
	"encoding/xml"
	"io/ioutil"
	"os"
	"strings"

	"github.com/knqyf263/go-cpe/naming"
	log "github.com/sirupsen/logrus"
	"golang.org/x/xerrors"
)

type analysis struct {
	Dependencies []dependency `xml:"dependencies>dependency"`
}

type dependency struct {
	Identifiers []vulnerabilityId `xml:"identifiers>vulnerabilityIds"`
}

type vulnerabilityId struct {
	Id string `xml:"id"`
}

func appendIfMissing(slice []string, str string) []string {
	for _, s := range slice {
		if s == str {
			return slice
		}
	}
	return append(slice, str)
}

// Parse parses OWASP dependency check XML and collect list of cpe
func Parse(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		log.Warnf("OWASP Dependency Check XML is not found: %s", path)
		return []string{}, nil
	}
	defer file.Close()

	b, err := ioutil.ReadAll(file)
	if err != nil {
		log.Warnf("Failed to read OWASP Dependency Check XML: %s", path)
		return []string{}, nil
	}

	var anal analysis
	if err := xml.Unmarshal(b, &anal); err != nil {
		return nil, xerrors.Errorf("Failed to unmarshal: %s", err)
	}

	cpes := []string{}
	for _, d := range anal.Dependencies {
		for _, ident := range d.Identifiers {
			id := ident.Id // Start with cpe:2.3:
			// Convert from CPE 2.3 to CPE 2.2
			if strings.HasPrefix(id, "cpe:2.3:") {
				wfn, err := naming.UnbindFS(id)
				if err != nil {
					return []string{}, err
				}
				id = naming.BindToURI(wfn)
			}
			cpes = appendIfMissing(cpes, id)
		}
	}
	return cpes, nil
}
