package config

// Load loads configuration
func Load(path, keyPass string) error {
	var loader Loader
	loader = TOMLLoader{}
	return loader.Load(path, keyPass)
}

// Loader is interface of concrete loader
type Loader interface {
	Load(string, string) error
}
