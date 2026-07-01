package config

// Vuls2Conf is configuration items for vuls2
type Vuls2Conf struct {
	Repository string
	Digest     *string `json:",omitempty"`
	Path       string
	SkipUpdate bool
}
