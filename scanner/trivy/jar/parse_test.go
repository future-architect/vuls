package jar

import (
	"archive/zip"
	"bytes"
	"testing"
)

func TestParseManifestUsesOnlyMainSection(t *testing.T) {
	manifestFile := newManifestFile(t, `Manifest-Version: 1.0
Implementation-Title: xercesImpl
Implementation-Version: 2.12.2
Implementation-Vendor-Id: xerces

Name: org/apache/xerces/xni/
Implementation-Title: org.apache.xerces.xni
Implementation-Version: 1.2
Implementation-Vendor-Id: org.apache.xerces
`)

	got, err := parseManifest(manifestFile)
	if err != nil {
		t.Fatalf("parseManifest() error = %v", err)
	}
	if got.implementationTitle != " xercesImpl" || got.implementationVersion != " 2.12.2" || got.implementationVendorID != " xerces" {
		t.Fatalf("parseManifest() read an individual section: %#v", got)
	}
}

func TestParseManifestSupportsCRAndFolding(t *testing.T) {
	manifestFile := newManifestFile(t, "Manifest-Version: 1.0\rImplementation-Title: long-\r title\rImplementation-Version: 1.2.3\rImplementation-Vendor-Id: example\r\rName: ignored\rImplementation-Version: 9.9.9\r")

	got, err := parseManifest(manifestFile)
	if err != nil {
		t.Fatalf("parseManifest() error = %v", err)
	}
	if got.implementationTitle != " long-title" || got.implementationVersion != " 1.2.3" || got.implementationVendorID != " example" {
		t.Fatalf("parseManifest() = %#v", got)
	}
}

func newManifestFile(t *testing.T, contents string) *zip.File {
	t.Helper()

	var archive bytes.Buffer
	zw := zip.NewWriter(&archive)
	w, err := zw.Create("META-INF/MANIFEST.MF")
	if err != nil {
		t.Fatalf("zip.Create() error = %v", err)
	}
	if _, err := w.Write([]byte(contents)); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip.Close() error = %v", err)
	}

	zr, err := zip.NewReader(bytes.NewReader(archive.Bytes()), int64(archive.Len()))
	if err != nil {
		t.Fatalf("zip.NewReader() error = %v", err)
	}
	return zr.File[0]
}
