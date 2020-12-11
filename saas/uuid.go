package saas

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	c "github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
	"github.com/hashicorp/go-uuid"
	"golang.org/x/xerrors"
)

func renameKeyNameUTC(scannedAt time.Time, uuid string, container models.Container) string {
	timestr := scannedAt.UTC().Format(time.RFC3339)
	if len(container.ContainerID) == 0 {
		return fmt.Sprintf("%s/%s.json", timestr, uuid)
	}
	return fmt.Sprintf("%s/%s@%s.json", timestr, container.UUID, uuid)
}

const reUUID = "[\\da-f]{8}-[\\da-f]{4}-[\\da-f]{4}-[\\da-f]{4}-[\\da-f]{12}"

// Scanning with the -containers-only flag at scan time, the UUID of Container Host may not be generated,
// so check it. Otherwise create a UUID of the Container Host and set it.
func getOrCreateServerUUID(r models.ScanResult, server c.ServerInfo) (serverUUID string, err error) {
	if id, ok := server.UUIDs[r.ServerName]; !ok {
		if serverUUID, err = uuid.GenerateUUID(); err != nil {
			return "", xerrors.Errorf("Failed to generate UUID: %w", err)
		}
	} else {
		matched, err := regexp.MatchString(reUUID, id)
		if !matched || err != nil {
			if serverUUID, err = uuid.GenerateUUID(); err != nil {
				return "", xerrors.Errorf("Failed to generate UUID: %w", err)
			}
		}
	}
	return serverUUID, nil
}

// EnsureUUIDs generate a new UUID of the scan target server if UUID is not assigned yet.
// And then set the generated UUID to config.toml and scan results.
func EnsureUUIDs(configPath string, results models.ScanResults) (err error) {
	// Sort Host->Container
	sort.Slice(results, func(i, j int) bool {
		if results[i].ServerName == results[j].ServerName {
			return results[i].Container.ContainerID < results[j].Container.ContainerID
		}
		return results[i].ServerName < results[j].ServerName
	})

	re := regexp.MustCompile(reUUID)
	for i, r := range results {
		server := c.Conf.Servers[r.ServerName]
		if server.UUIDs == nil {
			server.UUIDs = map[string]string{}
		}

		name := ""
		if r.IsContainer() {
			name = fmt.Sprintf("%s@%s", r.Container.Name, r.ServerName)
			serverUUID, err := getOrCreateServerUUID(r, server)
			if err != nil {
				return err
			}
			if serverUUID != "" {
				server.UUIDs[r.ServerName] = serverUUID
			}
		} else {
			name = r.ServerName
		}

		if id, ok := server.UUIDs[name]; ok {
			ok := re.MatchString(id)
			if !ok || err != nil {
				util.Log.Warnf("UUID is invalid. Re-generate UUID %s: %s", id, err)
			} else {
				if r.IsContainer() {
					results[i].Container.UUID = id
					results[i].ServerUUID = server.UUIDs[r.ServerName]
				} else {
					results[i].ServerUUID = id
				}
				// continue if the UUID has already assigned and valid
				continue
			}
		}

		// Generate a new UUID and set to config and scan result
		serverUUID, err := uuid.GenerateUUID()
		if err != nil {
			return err
		}
		server.UUIDs[name] = serverUUID
		server = cleanForTOMLEncoding(server, c.Conf.Default)
		c.Conf.Servers[r.ServerName] = server

		if r.IsContainer() {
			results[i].Container.UUID = serverUUID
			results[i].ServerUUID = server.UUIDs[r.ServerName]
		} else {
			results[i].ServerUUID = serverUUID
		}
	}

	for name, server := range c.Conf.Servers {
		server = cleanForTOMLEncoding(server, c.Conf.Default)
		c.Conf.Servers[name] = server
	}

	email := &c.Conf.EMail
	if email.SMTPAddr == "" {
		email = nil
	}

	slack := &c.Conf.Slack
	if slack.HookURL == "" {
		slack = nil
	}

	cveDict := &c.Conf.CveDict
	ovalDict := &c.Conf.OvalDict
	gost := &c.Conf.Gost
	exploit := &c.Conf.Exploit
	metasploit := &c.Conf.Metasploit
	http := &c.Conf.HTTP
	if http.URL == "" {
		http = nil
	}

	syslog := &c.Conf.Syslog
	if syslog.Host == "" {
		syslog = nil
	}

	aws := &c.Conf.AWS
	if aws.S3Bucket == "" {
		aws = nil
	}

	azure := &c.Conf.Azure
	if azure.AccountName == "" {
		azure = nil
	}

	stride := &c.Conf.Stride
	if stride.HookURL == "" {
		stride = nil
	}

	hipChat := &c.Conf.HipChat
	if hipChat.AuthToken == "" {
		hipChat = nil
	}

	chatWork := &c.Conf.ChatWork
	if chatWork.APIToken == "" {
		chatWork = nil
	}

	saas := &c.Conf.Saas
	if saas.GroupID == 0 {
		saas = nil
	}

	c := struct {
		CveDict    *c.GoCveDictConf  `toml:"cveDict"`
		OvalDict   *c.GovalDictConf  `toml:"ovalDict"`
		Gost       *c.GostConf       `toml:"gost"`
		Exploit    *c.ExploitConf    `toml:"exploit"`
		Metasploit *c.MetasploitConf `toml:"metasploit"`
		Slack      *c.SlackConf      `toml:"slack"`
		Email      *c.SMTPConf       `toml:"email"`
		HTTP       *c.HTTPConf       `toml:"http"`
		Syslog     *c.SyslogConf     `toml:"syslog"`
		AWS        *c.AWS            `toml:"aws"`
		Azure      *c.Azure          `toml:"azure"`
		Stride     *c.StrideConf     `toml:"stride"`
		HipChat    *c.HipChatConf    `toml:"hipChat"`
		ChatWork   *c.ChatWorkConf   `toml:"chatWork"`
		Saas       *c.SaasConf       `toml:"saas"`

		Default c.ServerInfo            `toml:"default"`
		Servers map[string]c.ServerInfo `toml:"servers"`
	}{
		CveDict:    cveDict,
		OvalDict:   ovalDict,
		Gost:       gost,
		Exploit:    exploit,
		Metasploit: metasploit,
		Slack:      slack,
		Email:      email,
		HTTP:       http,
		Syslog:     syslog,
		AWS:        aws,
		Azure:      azure,
		Stride:     stride,
		HipChat:    hipChat,
		ChatWork:   chatWork,
		Saas:       saas,

		Default: c.Conf.Default,
		Servers: c.Conf.Servers,
	}

	// rename the current config.toml to config.toml.bak
	info, err := os.Lstat(configPath)
	if err != nil {
		return xerrors.Errorf("Failed to lstat %s: %w", configPath, err)
	}
	realPath := configPath
	if info.Mode()&os.ModeSymlink == os.ModeSymlink {
		if realPath, err = os.Readlink(configPath); err != nil {
			return xerrors.Errorf("Failed to Read link %s: %w", configPath, err)
		}
	}
	if err := os.Rename(realPath, realPath+".bak"); err != nil {
		return xerrors.Errorf("Failed to rename %s: %w", configPath, err)
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

func cleanForTOMLEncoding(server c.ServerInfo, def c.ServerInfo) c.ServerInfo {
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

	return server
}
