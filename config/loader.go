package config

// Load loads configuration
func Load(path string) error {
	loader := TOMLLoader{}
	return loader.Load(path)
}

// Loader is interface of concrete loader
type Loader interface {
	Load(string, string) error
}
