package jar_test

import (
	"archive/zip"
	"bytes"
	"strings"
	"testing"

	"github.com/future-architect/vuls/scanner/trivy/jar"
)

func TestParseManifest(t *testing.T) {
	tests := []struct {
		name      string
		lines     []string
		lineBreak string
		want      jar.Manifest
	}{
		{
			name: "basic attributes with LF line endings",
			lines: []string{
				"Manifest-Version: 1.0",
				"Implementation-Title: xercesImpl",
				"Implementation-Version: 2.12.2",
				"Implementation-Vendor-Id: xerces",
			},
			lineBreak: "\n",
			want: jar.Manifest{
				ImplementationTitle:    " xercesImpl",
				ImplementationVersion:  " 2.12.2",
				ImplementationVendorID: " xerces",
			},
		},
		{
			name: "basic attributes with CRLF line endings",
			lines: []string{
				"Manifest-Version: 1.0",
				"Implementation-Title: xercesImpl",
				"Implementation-Version: 2.12.2",
				"Implementation-Vendor-Id: xerces",
			},
			lineBreak: "\r\n",
			want: jar.Manifest{
				ImplementationTitle:    " xercesImpl",
				ImplementationVersion:  " 2.12.2",
				ImplementationVendorID: " xerces",
			},
		},
		{
			name: "all supported attributes",
			lines: []string{
				"Manifest-Version: 1.0",
				"Implementation-Title: guava",
				"Implementation-Version: 31.1",
				"Implementation-Vendor: Google",
				"Implementation-Vendor-Id: com.google.guava",
				"Specification-Title: Guava",
				"Specification-Version: 31",
				"Specification-Vendor: Google LLC",
				"Bundle-Name: Guava",
				"Bundle-Version: 31.1.0",
				"Bundle-SymbolicName: com.google.guava",
			},
			lineBreak: "\r\n",
			want: jar.Manifest{
				ImplementationTitle:    " guava",
				ImplementationVersion:  " 31.1",
				ImplementationVendor:   " Google",
				ImplementationVendorID: " com.google.guava",
				SpecificationTitle:     " Guava",
				SpecificationVersion:   " 31",
				SpecificationVendor:    " Google LLC",
				BundleName:             " Guava",
				BundleVersion:          " 31.1.0",
				BundleSymbolicName:     " com.google.guava",
			},
		},
		{
			name: "empty manifest",
			want: jar.Manifest{},
		},
		{
			name: "variable values are skipped",
			lines: []string{
				"Manifest-Version: 1.0",
				"Bundle-Name: %bundleName",
				"Bundle-Version: 1.2.3",
			},
			lineBreak: "\r\n",
			want: jar.Manifest{
				BundleVersion: " 1.2.3",
			},
		},
		{
			name: "only the main section is read",
			lines: []string{
				"Manifest-Version: 1.0",
				"Implementation-Title: xercesImpl",
				"Implementation-Version: 2.12.2",
				"Implementation-Vendor-Id: xerces",
				"",
				"Name: org/apache/xerces/xni/",
				"Implementation-Title: org.apache.xerces.xni",
				"Implementation-Version: 1.2",
				"Implementation-Vendor-Id: org.apache.xerces",
			},
			lineBreak: "\n",
			want: jar.Manifest{
				ImplementationTitle:    " xercesImpl",
				ImplementationVersion:  " 2.12.2",
				ImplementationVendorID: " xerces",
			},
		},
		{
			name: "lone CR line endings and continuation folding",
			lines: []string{
				"Manifest-Version: 1.0",
				"Implementation-Title: long-",
				" title",
				"Implementation-Version: 1.2.3",
				"Implementation-Vendor-Id: example",
				"",
				"Name: ignored",
				"Implementation-Version: 9.9.9",
			},
			lineBreak: "\r",
			want: jar.Manifest{
				ImplementationTitle:    " long-title",
				ImplementationVersion:  " 1.2.3",
				ImplementationVendorID: " example",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var in string
			if len(tt.lines) > 0 {
				in = strings.Join(tt.lines, tt.lineBreak) + tt.lineBreak
			}
			got, err := jar.ParseManifest(newManifestFile(t, in))
			if err != nil {
				t.Fatalf("parseManifest() error = %v", err)
			}
			if got != tt.want.Internal() {
				t.Errorf("parseManifest() = %#v, want %#v", got, tt.want.Internal())
			}
		})
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
