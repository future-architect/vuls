package jar_test

import (
	"archive/zip"
	"bytes"
	"testing"

	"github.com/future-architect/vuls/scanner/trivy/jar"
)

func TestParseManifest(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want jar.Manifest
	}{
		{
			name: "basic attributes with LF line endings",
			in: "Manifest-Version: 1.0\n" +
				"Implementation-Title: xercesImpl\n" +
				"Implementation-Version: 2.12.2\n" +
				"Implementation-Vendor-Id: xerces\n",
			want: jar.Manifest{
				ImplementationTitle:    " xercesImpl",
				ImplementationVersion:  " 2.12.2",
				ImplementationVendorID: " xerces",
			},
		},
		{
			name: "basic attributes with CRLF line endings",
			in: "Manifest-Version: 1.0\r\n" +
				"Implementation-Title: xercesImpl\r\n" +
				"Implementation-Version: 2.12.2\r\n" +
				"Implementation-Vendor-Id: xerces\r\n",
			want: jar.Manifest{
				ImplementationTitle:    " xercesImpl",
				ImplementationVersion:  " 2.12.2",
				ImplementationVendorID: " xerces",
			},
		},
		{
			name: "all supported attributes",
			in: "Manifest-Version: 1.0\r\n" +
				"Implementation-Title: guava\r\n" +
				"Implementation-Version: 31.1\r\n" +
				"Implementation-Vendor: Google\r\n" +
				"Implementation-Vendor-Id: com.google.guava\r\n" +
				"Specification-Title: Guava\r\n" +
				"Specification-Version: 31\r\n" +
				"Specification-Vendor: Google LLC\r\n" +
				"Bundle-Name: Guava\r\n" +
				"Bundle-Version: 31.1.0\r\n" +
				"Bundle-SymbolicName: com.google.guava\r\n",
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
			in:   "",
			want: jar.Manifest{},
		},
		{
			name: "variable values are skipped",
			in: "Manifest-Version: 1.0\r\n" +
				"Bundle-Name: %bundleName\r\n" +
				"Bundle-Version: 1.2.3\r\n",
			want: jar.Manifest{
				BundleVersion: " 1.2.3",
			},
		},
		{
			name: "only the main section is read",
			in: "Manifest-Version: 1.0\n" +
				"Implementation-Title: xercesImpl\n" +
				"Implementation-Version: 2.12.2\n" +
				"Implementation-Vendor-Id: xerces\n" +
				"\n" +
				"Name: org/apache/xerces/xni/\n" +
				"Implementation-Title: org.apache.xerces.xni\n" +
				"Implementation-Version: 1.2\n" +
				"Implementation-Vendor-Id: org.apache.xerces\n",
			want: jar.Manifest{
				ImplementationTitle:    " xercesImpl",
				ImplementationVersion:  " 2.12.2",
				ImplementationVendorID: " xerces",
			},
		},
		{
			name: "lone CR line endings and continuation folding",
			in: "Manifest-Version: 1.0\r" +
				"Implementation-Title: long-\r" +
				" title\r" +
				"Implementation-Version: 1.2.3\r" +
				"Implementation-Vendor-Id: example\r" +
				"\r" +
				"Name: ignored\r" +
				"Implementation-Version: 9.9.9\r",
			want: jar.Manifest{
				ImplementationTitle:    " long-title",
				ImplementationVersion:  " 1.2.3",
				ImplementationVendorID: " example",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := jar.ParseManifest(newManifestFile(t, tt.in))
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
