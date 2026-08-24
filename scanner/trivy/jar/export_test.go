package jar

// Exports for external tests (package jar_test).

var ParseManifest = parseManifest

// Manifest exposes the fields of the package-internal manifest so that
// external tests can state expected values.
type Manifest struct {
	ImplementationVersion  string
	ImplementationTitle    string
	ImplementationVendor   string
	ImplementationVendorID string
	SpecificationTitle     string
	SpecificationVersion   string
	SpecificationVendor    string
	BundleName             string
	BundleVersion          string
	BundleSymbolicName     string
}

// Internal converts the exported fields into the package-internal manifest
// for comparison against parseManifest results.
func (m Manifest) Internal() manifest {
	return manifest{
		implementationVersion:  m.ImplementationVersion,
		implementationTitle:    m.ImplementationTitle,
		implementationVendor:   m.ImplementationVendor,
		implementationVendorID: m.ImplementationVendorID,
		specificationTitle:     m.SpecificationTitle,
		specificationVersion:   m.SpecificationVersion,
		specificationVendor:    m.SpecificationVendor,
		bundleName:             m.BundleName,
		bundleVersion:          m.BundleVersion,
		bundleSymbolicName:     m.BundleSymbolicName,
	}
}
