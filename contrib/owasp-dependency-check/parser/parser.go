package parser

import (
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

type analysis struct {
	Dependencies []dependency `xml:"dependencies>dependency"`
}

type dependency struct {
	Identifiers []identifier `xml:"identifiers>identifier"`
}

type identifier struct {
	Name string `xml:"name"`
	Type string `xml:"type,attr"`
}

func appendIfMissing(slice []string, str string) []string {
	for _, s := range slice {
		if s == str {
			return slice
		}
	}
	return append(slice, str)
}

// Parse parses XML and collect list of cpe
func Parse(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("Failed to open: %s", err)
	}
	defer file.Close()

	b, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("Failed to read: %s", err)
	}

	var anal analysis
	if err := xml.Unmarshal(b, &anal); err != nil {
		return nil, fmt.Errorf("Failed to unmarshal: %s", err)
	}

	cpes := []string{}
	for _, d := range anal.Dependencies {
		for _, ident := range d.Identifiers {
			if ident.Type == "cpe" {
				name := strings.TrimPrefix(ident.Name, "(")
				name = strings.TrimSuffix(name, ")")
				cpes = appendIfMissing(cpes, name)
			}
		}
	}
	return cpes, nil
}
