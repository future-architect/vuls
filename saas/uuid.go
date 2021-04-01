package saas

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
	"github.com/hashicorp/go-uuid"
	"golang.org/x/xerrors"
)

// EnsureUUIDs generate a new UUID of the scan target server if UUID is not assigned yet.
// And then set the generated UUID to config.toml and scan results.
func EnsureUUIDs(servers map[string]config.ServerInfo, path string, scanResults models.ScanResults) (err error) {
	needsOverwrite, err := ensure(servers, path, scanResults, uuid.GenerateUUID)
	if err != nil {
		return xerrors.Errorf("Failed to ensure UUIDs. err: %w", err)
	}

	if !needsOverwrite {
		return
	}
	return writeToFile(config.Conf, path)
}

func ensure(servers map[string]config.ServerInfo, path string, scanResults models.ScanResults, generateFunc func() (string, error)) (needsOverwrite bool, err error) {
	for i, r := range scanResults {
		serverInfo := servers[r.ServerName]
		if serverInfo.UUIDs == nil {
			serverInfo.UUIDs = map[string]string{}
		}

		if r.IsContainer() {
			if id, found := serverInfo.UUIDs[r.ServerName]; !found {
				// Scanning with the -containers-only flag, the UUID of Host may not be generated,
				// so check it. If not, create a UUID of the Host and set it.
				serverInfo.UUIDs[r.ServerName], err = generateFunc()
				if err != nil {
					return false, err
				}
				needsOverwrite = true
			} else if _, err := uuid.ParseUUID(id); err != nil {
				// if the UUID of the host is invalid, re-generate it
				logging.Log.Warnf("UUID `%s` is invalid. Re-generate and overwrite", id)
				serverInfo.UUIDs[r.ServerName], err = generateFunc()
				if err != nil {
					return false, err
				}
				needsOverwrite = true
			}
		}

		name := r.ServerName
		if r.IsContainer() {
			name = fmt.Sprintf("%s@%s", r.Container.Name, r.ServerName)
		}

		if id, ok := serverInfo.UUIDs[name]; ok {
			if _, err := uuid.ParseUUID(id); err == nil {
				if r.IsContainer() {
					scanResults[i].Container.UUID = id
					scanResults[i].ServerUUID = serverInfo.UUIDs[r.ServerName]
				} else {
					scanResults[i].ServerUUID = id
				}
				// continue if the UUID has already assigned and valid
				continue
			}
			// re-generate
			logging.Log.Warnf("UUID `%s` is invalid. Re-generate and overwrite", id)
		}

		// Generate a new UUID and set to config and scanResult
		serverUUID, err := generateFunc()
		if err != nil {
			return false, err
		}
		serverInfo.UUIDs[name] = serverUUID
		servers[r.ServerName] = serverInfo

		if r.IsContainer() {
			scanResults[i].Container.UUID = serverUUID
			scanResults[i].ServerUUID = serverInfo.UUIDs[r.ServerName]
		} else {
			scanResults[i].ServerUUID = serverUUID
		}
		needsOverwrite = true
	}
	return needsOverwrite, nil
}

func writeToFile(cnf config.Config, path string) error {
	for name, server := range cnf.Servers {
		server = cleanForTOMLEncoding(server, cnf.Default)
		cnf.Servers[name] = server
	}
	if cnf.Default.WordPress != nil && cnf.Default.WordPress.IsZero() {
		cnf.Default.WordPress = nil
	}

	c := struct {
		Saas    *config.SaasConf             `toml:"saas"`
		Default config.ServerInfo            `toml:"default"`
		Servers map[string]config.ServerInfo `toml:"servers"`
	}{
		Saas:    &cnf.Saas,
		Default: cnf.Default,
		Servers: cnf.Servers,
	}

	// rename the current config.toml to config.toml.bak
	info, err := os.Lstat(path)
	if err != nil {
		return xerrors.Errorf("Failed to lstat %s: %w", path, err)
	}
	realPath := path
	if info.Mode()&os.ModeSymlink == os.ModeSymlink {
		if realPath, err = os.Readlink(path); err != nil {
			return xerrors.Errorf("Failed to Read link %s: %w", path, err)
		}
	}
	if err := os.Rename(realPath, realPath+".bak"); err != nil {
		return xerrors.Errorf("Failed to rename %s: %w", path, err)
	}

	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(c); err != nil {
		return xerrors.Errorf("Failed to encode to toml: %w", err)
	}
	str := strings.Replace(buf.String(), "\n  [", "\n\n  [", -1)
	str = fmt.Sprintf("%s\n\n%s",
		"# See README for details: https://vuls.io/docs/en/usage-settings.html",
		str)

	return ioutil.WriteFile(realPath, []byte(str), 0600)
}

func cleanForTOMLEncoding(server config.ServerInfo, def config.ServerInfo) config.ServerInfo {
	if reflect.DeepEqual(server.Optional, def.Optional) {
		server.Optional = nil
	}

	if def.User == server.User {
		server.User = ""
	}

	if def.Host == server.Host {
		server.Host = ""
	}

	if def.Port == server.Port {
		server.Port = ""
	}

	if def.KeyPath == server.KeyPath {
		server.KeyPath = ""
	}

	if reflect.DeepEqual(server.ScanMode, def.ScanMode) {
		server.ScanMode = nil
	}

	if def.Type == server.Type {
		server.Type = ""
	}

	if reflect.DeepEqual(server.CpeNames, def.CpeNames) {
		server.CpeNames = nil
	}

	if def.OwaspDCXMLPath == server.OwaspDCXMLPath {
		server.OwaspDCXMLPath = ""
	}

	if reflect.DeepEqual(server.IgnoreCves, def.IgnoreCves) {
		server.IgnoreCves = nil
	}

	if reflect.DeepEqual(server.Enablerepo, def.Enablerepo) {
		server.Enablerepo = nil
	}

	for k, v := range def.Optional {
		if vv, ok := server.Optional[k]; ok && v == vv {
			delete(server.Optional, k)
		}
	}

	if server.WordPress != nil {
		if server.WordPress.IsZero() || reflect.DeepEqual(server.WordPress, def.WordPress) {
			server.WordPress = nil
		}
	}

	return server
}
