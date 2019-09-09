package models

// WordPressPackages has Core version, plugins and themes.
type WordPressPackages []WpPackage

// CoreVersion returns the core version of the installed WordPress
func (w WordPressPackages) CoreVersion() string {
	for _, p := range w {
		if p.Type == WPCore {
			return p.Version
		}
	}
	return ""
}

// Plugins returns a slice of plugins of the installed WordPress
func (w WordPressPackages) Plugins() (ps []WpPackage) {
	for _, p := range w {
		if p.Type == WPPlugin {
			ps = append(ps, p)
		}
	}
	return
}

// Themes returns a slice of themes of the installed WordPress
func (w WordPressPackages) Themes() (ps []WpPackage) {
	for _, p := range w {
		if p.Type == WPTheme {
			ps = append(ps, p)
		}
	}
	return
}

// Find searches by specified name
func (w WordPressPackages) Find(name string) (ps *WpPackage, found bool) {
	for _, p := range w {
		if p.Name == name {
			return &p, true
		}
	}
	return nil, false
}

const (
	// WPCore is a type `core` in WPPackage struct
	WPCore = "core"
	// WPPlugin is a type `plugin` in WPPackage struct
	WPPlugin = "plugin"
	// WPTheme is a type `theme` in WPPackage struct
	WPTheme = "theme"

	// Inactive is a inactive status in WPPackage struct
	Inactive = "inactive"
)

// WpPackage has a details of plugin and theme
type WpPackage struct {
	Name    string `json:"name,omitempty"`
	Status  string `json:"status,omitempty"` // active, inactive or must-use
	Update  string `json:"update,omitempty"` // available or none
	Version string `json:"version,omitempty"`
	Type    string `json:"type,omitempty"` // core, plugin, theme
}

// WpPackageFixStatus is used in Vulninfo.WordPress
type WpPackageFixStatus struct {
	Name    string `json:"name,omitempty"`
	FixedIn string `json:"fixedIn,omitempty"`
}
