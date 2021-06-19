package scanner

import (
	"reflect"
	"testing"

	_ "github.com/aquasecurity/fanal/analyzer/library/bundler"
	_ "github.com/aquasecurity/fanal/analyzer/library/cargo"
	_ "github.com/aquasecurity/fanal/analyzer/library/composer"
	_ "github.com/aquasecurity/fanal/analyzer/library/npm"
	_ "github.com/aquasecurity/fanal/analyzer/library/pipenv"
	_ "github.com/aquasecurity/fanal/analyzer/library/poetry"
	_ "github.com/aquasecurity/fanal/analyzer/library/yarn"
	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
)

func TestParseDockerPs(t *testing.T) {
	var test = struct {
		in       string
		expected []config.Container
	}{
		`c7ca0992415a romantic_goldberg ubuntu:14.04.5
f570ae647edc agitated_lovelace centos:latest`,
		[]config.Container{
			{
				ContainerID: "c7ca0992415a",
				Name:        "romantic_goldberg",
				Image:       "ubuntu:14.04.5",
			},
			{
				ContainerID: "f570ae647edc",
				Name:        "agitated_lovelace",
				Image:       "centos:latest",
			},
		},
	}

	r := newRHEL(config.ServerInfo{})
	actual, err := r.parseDockerPs(test.in)
	if err != nil {
		t.Errorf("Error occurred. in: %s, err: %+v", test.in, err)
		return
	}
	for i, e := range test.expected {
		if !reflect.DeepEqual(e, actual[i]) {
			t.Errorf("expected %v, actual %v", e, actual[i])
		}
	}
}

func TestParseLxdPs(t *testing.T) {
	var test = struct {
		in       string
		expected []config.Container
	}{
		`+-------+
| NAME  |
+-------+
| test1 |
+-------+
| test2 |
+-------+`,
		[]config.Container{
			{
				ContainerID: "test1",
				Name:        "test1",
			},
			{
				ContainerID: "test2",
				Name:        "test2",
			},
		},
	}

	r := newRHEL(config.ServerInfo{})
	actual, err := r.parseLxdPs(test.in)
	if err != nil {
		t.Errorf("Error occurred. in: %s, err: %+v", test.in, err)
		return
	}
	for i, e := range test.expected {
		if !reflect.DeepEqual(e, actual[i]) {
			t.Errorf("expected %v, actual %v", e, actual[i])
		}
	}
}

func TestParseIp(t *testing.T) {

	var test = struct {
		in        string
		expected4 []string
		expected6 []string
	}{
		in: `1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN \    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
1: lo    inet 127.0.0.1/8 scope host lo
1: lo    inet6 ::1/128 scope host \       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000\    link/ether 52:54:00:2a:86:4c brd ff:ff:ff:ff:ff:ff
2: eth0    inet 10.0.2.15/24 brd 10.0.2.255 scope global eth0
2: eth0    inet6 fe80::5054:ff:fe2a:864c/64 scope link \       valid_lft forever preferred_lft forever
3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000\    link/ether 08:00:27:36:76:60 brd ff:ff:ff:ff:ff:ff
3: eth1    inet 192.168.33.11/24 brd 192.168.33.255 scope global eth1
3: eth1    inet6 2001:db8::68/64 scope link \       valid_lft forever preferred_lft forever `,
		expected4: []string{"10.0.2.15", "192.168.33.11"},
		expected6: []string{"2001:db8::68"},
	}

	r := newRHEL(config.ServerInfo{})
	actual4, actual6 := r.parseIP(test.in)
	if !reflect.DeepEqual(test.expected4, actual4) {
		t.Errorf("expected %v, actual %v", test.expected4, actual4)
	}
	if !reflect.DeepEqual(test.expected6, actual6) {
		t.Errorf("expected %v, actual %v", test.expected6, actual6)
	}
}

func TestIsAwsInstanceID(t *testing.T) {
	var tests = []struct {
		in       string
		expected bool
	}{
		{"i-1234567a", true},
		{"i-1234567890abcdef0", true},
		{"i-1234567890abcdef0000000", true},
		{"e-1234567890abcdef0", false},
		{"i-1234567890abcdef0 foo bar", false},
		{"no data", false},
	}

	r := newAmazon(config.ServerInfo{})
	for _, tt := range tests {
		actual := r.isAwsInstanceID(tt.in)
		if tt.expected != actual {
			t.Errorf("expected %t, actual %t, str: %s", tt.expected, actual, tt.in)
		}
	}
}

func TestParseSystemctlStatus(t *testing.T) {
	var tests = []struct {
		in  string
		out string
	}{
		{
			in: `● NetworkManager.service - Network Manager
   Loaded: loaded (/usr/lib/systemd/system/NetworkManager.service; enabled; vendor preset: enabled)
   Active: active (running) since Wed 2018-01-10 17:15:39 JST; 2 months 10 days ago
     Docs: man:NetworkManager(8)
 Main PID: 437 (NetworkManager)
   Memory: 424.0K
   CGroup: /system.slice/NetworkManager.service
           ├─437 /usr/sbin/NetworkManager --no-daemon
           └─572 /sbin/dhclient -d -q -sf /usr/libexec/nm-dhcp-helper -pf /var/run/dhclient-ens160.pid -lf /var/lib/NetworkManager/dhclient-241ed966-e1c7-4d5c-a6a0-8a6dba457277-ens160.lease -cf /var/lib/NetworkManager/dhclient-ens160.conf ens160`,
			out: "NetworkManager.service",
		},
		{
			in:  `Failed to get unit for PID 700: PID 700 does not belong to any loaded unit.`,
			out: "",
		},
	}

	r := newCentOS(config.ServerInfo{})
	for _, tt := range tests {
		actual := r.parseSystemctlStatus(tt.in)
		if tt.out != actual {
			t.Errorf("expected %v, actual %v", tt.out, actual)
		}
	}
}

func Test_base_parseLsProcExe(t *testing.T) {
	type args struct {
		stdout string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "systemd",
			args: args{
				stdout: "lrwxrwxrwx 1 root root 0 Jun 29 17:13 /proc/1/exe -> /lib/systemd/systemd",
			},
			want:    "/lib/systemd/systemd",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &base{}
			got, err := l.parseLsProcExe(tt.args.stdout)
			if (err != nil) != tt.wantErr {
				t.Errorf("base.parseLsProcExe() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("base.parseLsProcExe() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_base_parseGrepProcMap(t *testing.T) {
	type args struct {
		stdout string
	}
	tests := []struct {
		name        string
		args        args
		wantSoPaths []string
	}{
		{
			name: "systemd",
			args: args{
				`/etc/selinux/targeted/contexts/files/file_contexts.bin
/etc/selinux/targeted/contexts/files/file_contexts.homedirs.bin
/usr/lib64/libdl-2.28.so
				/usr/lib64/libnss_files-2.17.so;601ccbf3`,
			},
			wantSoPaths: []string{
				"/etc/selinux/targeted/contexts/files/file_contexts.bin",
				"/etc/selinux/targeted/contexts/files/file_contexts.homedirs.bin",
				"/usr/lib64/libdl-2.28.so",
				`/usr/lib64/libnss_files-2.17.so`,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &base{}
			if gotSoPaths := l.parseGrepProcMap(tt.args.stdout); !reflect.DeepEqual(gotSoPaths, tt.wantSoPaths) {
				t.Errorf("base.parseGrepProcMap() = %v, want %v", gotSoPaths, tt.wantSoPaths)
			}
		})
	}
}

func Test_base_parseLsOf(t *testing.T) {
	type args struct {
		stdout string
	}
	tests := []struct {
		name        string
		args        args
		wantPortPid map[string][]string
	}{
		{
			name: "lsof",
			args: args{
				stdout: `systemd-r   474 systemd-resolve   13u  IPv4  11904      0t0  TCP localhost:53 (LISTEN)
sshd        644            root    3u  IPv4  16714      0t0  TCP *:22 (LISTEN)
sshd        644            root    4u  IPv6  16716      0t0  TCP *:22 (LISTEN)
squid       959           proxy   11u  IPv6  16351      0t0  TCP *:3128 (LISTEN)
node       1498          ubuntu   21u  IPv6  20132      0t0  TCP *:35401 (LISTEN)
node       1498          ubuntu   22u  IPv6  20133      0t0  TCP *:44801 (LISTEN)
rpcbind   568    rpc    7u  IPv6  15149      0t0  UDP *:111
docker-pr  9135            root    4u  IPv6 297133      0t0  TCP *:6379 (LISTEN)`,
			},
			wantPortPid: map[string][]string{
				"localhost:53": {"474"},
				"*:22":         {"644"},
				"*:3128":       {"959"},
				"*:35401":      {"1498"},
				"*:44801":      {"1498"},
				"*:6379":       {"9135"},
			},
		},
		{
			name: "lsof-duplicate-port",
			args: args{
				stdout: `sshd      832   root    3u  IPv4  15731      0t0  TCP *:22 (LISTEN)
sshd      832   root    4u  IPv6  15740      0t0  TCP *:22 (LISTEN)
master   1099   root   13u  IPv4  16657      0t0  TCP 127.0.0.1:25 (LISTEN)
master   1099   root   14u  IPv6  16658      0t0  TCP [::1]:25 (LISTEN)
httpd   32250   root    4u  IPv6 334982      0t0  TCP *:80 (LISTEN)
httpd   32251 apache    4u  IPv6 334982      0t0  TCP *:80 (LISTEN)
httpd   32252 apache    4u  IPv6 334982      0t0  TCP *:80 (LISTEN)
httpd   32253 apache    4u  IPv6 334982      0t0  TCP *:80 (LISTEN)
httpd   32254 apache    4u  IPv6 334982      0t0  TCP *:80 (LISTEN)
httpd   32255 apache    4u  IPv6 334982      0t0  TCP *:80 (LISTEN)`,
			},
			wantPortPid: map[string][]string{
				"*:22":         {"832"},
				"127.0.0.1:25": {"1099"},
				"[::1]:25":     {"1099"},
				"*:80":         {"32250", "32251", "32252", "32253", "32254", "32255"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &base{}
			if gotPortPid := l.parseLsOf(tt.args.stdout); !reflect.DeepEqual(gotPortPid, tt.wantPortPid) {
				t.Errorf("base.parseLsOf() = %v, want %v", gotPortPid, tt.wantPortPid)
			}
		})
	}
}

func Test_detectScanDest(t *testing.T) {
	tests := []struct {
		name   string
		args   base
		expect map[string][]string
	}{
		{
			name: "empty",
			args: base{osPackages: osPackages{
				Packages: models.Packages{"curl": models.Package{
					Name:       "curl",
					Version:    "7.64.0-4+deb10u1",
					NewVersion: "7.64.0-4+deb10u1",
				}},
			}},
			expect: map[string][]string{},
		},
		{
			name: "single-addr",
			args: base{osPackages: osPackages{
				Packages: models.Packages{"libaudit1": models.Package{
					Name:       "libaudit1",
					Version:    "1:2.8.4-3",
					NewVersion: "1:2.8.4-3",
					AffectedProcs: []models.AffectedProcess{
						{PID: "21", Name: "sshd", ListenPortStats: []models.PortStat{{BindAddress: "127.0.0.1", Port: "22"}}}, {PID: "10876", Name: "sshd"}},
				},
				}},
			},
			expect: map[string][]string{"127.0.0.1": {"22"}},
		},
		{
			name: "dup-addr-port",
			args: base{osPackages: osPackages{
				Packages: models.Packages{"libaudit1": models.Package{
					Name:       "libaudit1",
					Version:    "1:2.8.4-3",
					NewVersion: "1:2.8.4-3",
					AffectedProcs: []models.AffectedProcess{
						{PID: "21", Name: "sshd", ListenPortStats: []models.PortStat{{BindAddress: "127.0.0.1", Port: "22"}}}, {PID: "21", Name: "sshd", ListenPortStats: []models.PortStat{{BindAddress: "127.0.0.1", Port: "22"}}}},
				},
				}},
			},
			expect: map[string][]string{"127.0.0.1": {"22"}},
		},
		{
			name: "multi-addr",
			args: base{osPackages: osPackages{
				Packages: models.Packages{"libaudit1": models.Package{
					Name:       "libaudit1",
					Version:    "1:2.8.4-3",
					NewVersion: "1:2.8.4-3",
					AffectedProcs: []models.AffectedProcess{
						{PID: "21", Name: "sshd", ListenPortStats: []models.PortStat{{BindAddress: "127.0.0.1", Port: "22"}}}, {PID: "21", Name: "sshd", ListenPortStats: []models.PortStat{{BindAddress: "192.168.1.1", Port: "22"}}}, {PID: "6261", Name: "nginx", ListenPortStats: []models.PortStat{{BindAddress: "127.0.0.1", Port: "80"}}}},
				},
				}},
			},
			expect: map[string][]string{"127.0.0.1": {"22", "80"}, "192.168.1.1": {"22"}},
		},
		{
			name: "asterisk",
			args: base{
				osPackages: osPackages{
					Packages: models.Packages{"libaudit1": models.Package{
						Name:       "libaudit1",
						Version:    "1:2.8.4-3",
						NewVersion: "1:2.8.4-3",
						AffectedProcs: []models.AffectedProcess{
							{PID: "21", Name: "sshd", ListenPortStats: []models.PortStat{{BindAddress: "*", Port: "22"}}}},
					},
					}},
				ServerInfo: config.ServerInfo{
					IPv4Addrs: []string{"127.0.0.1", "192.168.1.1"},
				},
			},
			expect: map[string][]string{"127.0.0.1": {"22"}, "192.168.1.1": {"22"}},
		}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if dest := tt.args.detectScanDest(); !reflect.DeepEqual(dest, tt.expect) {
				t.Errorf("base.detectScanDest() = %v, want %v", dest, tt.expect)
			}
		})
	}
}

func Test_updatePortStatus(t *testing.T) {
	type args struct {
		l             base
		listenIPPorts []string
	}
	tests := []struct {
		name   string
		args   args
		expect models.Packages
	}{
		{name: "nil_affected_procs",
			args: args{
				l: base{osPackages: osPackages{
					Packages: models.Packages{"libc-bin": models.Package{Name: "libc-bin"}},
				}},
				listenIPPorts: []string{"127.0.0.1:22"}},
			expect: models.Packages{"libc-bin": models.Package{Name: "libc-bin"}}},
		{name: "nil_listen_ports",
			args: args{
				l: base{osPackages: osPackages{
					Packages: models.Packages{"bash": models.Package{Name: "bash", AffectedProcs: []models.AffectedProcess{{PID: "1", Name: "bash"}}}},
				}},
				listenIPPorts: []string{"127.0.0.1:22"}},
			expect: models.Packages{"bash": models.Package{Name: "bash", AffectedProcs: []models.AffectedProcess{{PID: "1", Name: "bash"}}}}},
		{name: "update_match_single_address",
			args: args{
				l: base{osPackages: osPackages{
					Packages: models.Packages{"libc6": models.Package{Name: "libc6", AffectedProcs: []models.AffectedProcess{{PID: "1", Name: "bash"}, {PID: "75", Name: "sshd", ListenPortStats: []models.PortStat{{BindAddress: "127.0.0.1", Port: "22"}}}}}},
				}},
				listenIPPorts: []string{"127.0.0.1:22"}},
			expect: models.Packages{"libc6": models.Package{Name: "libc6", AffectedProcs: []models.AffectedProcess{{PID: "1", Name: "bash"}, {PID: "75", Name: "sshd", ListenPortStats: []models.PortStat{{BindAddress: "127.0.0.1", Port: "22", PortReachableTo: []string{"127.0.0.1"}}}}}}}},
		{name: "update_match_multi_address",
			args: args{
				l: base{osPackages: osPackages{
					Packages: models.Packages{"libc6": models.Package{Name: "libc6", AffectedProcs: []models.AffectedProcess{{PID: "1", Name: "bash"}, {PID: "75", Name: "sshd", ListenPortStats: []models.PortStat{{BindAddress: "127.0.0.1", Port: "22"}, {BindAddress: "192.168.1.1", Port: "22"}}}}}},
				}},
				listenIPPorts: []string{"127.0.0.1:22", "192.168.1.1:22"}},
			expect: models.Packages{"libc6": models.Package{Name: "libc6", AffectedProcs: []models.AffectedProcess{{PID: "1", Name: "bash"}, {PID: "75", Name: "sshd", ListenPortStats: []models.PortStat{
				{BindAddress: "127.0.0.1", Port: "22", PortReachableTo: []string{"127.0.0.1"}},
				{BindAddress: "192.168.1.1", Port: "22", PortReachableTo: []string{"192.168.1.1"}},
			}}}}}},
		{name: "update_match_asterisk",
			args: args{
				l: base{osPackages: osPackages{
					Packages: models.Packages{"libc6": models.Package{Name: "libc6", AffectedProcs: []models.AffectedProcess{{PID: "1", Name: "bash"}, {PID: "75", Name: "sshd", ListenPortStats: []models.PortStat{{BindAddress: "*", Port: "22"}}}}}},
				}},
				listenIPPorts: []string{"127.0.0.1:22", "127.0.0.1:80", "192.168.1.1:22"}},
			expect: models.Packages{"libc6": models.Package{Name: "libc6", AffectedProcs: []models.AffectedProcess{{PID: "1", Name: "bash"}, {PID: "75", Name: "sshd", ListenPortStats: []models.PortStat{
				{BindAddress: "*", Port: "22", PortReachableTo: []string{"127.0.0.1", "192.168.1.1"}},
			}}}}}},
		{name: "update_multi_packages",
			args: args{
				l: base{osPackages: osPackages{
					Packages: models.Packages{
						"packa": models.Package{Name: "packa", AffectedProcs: []models.AffectedProcess{{PID: "75", Name: "sshd", ListenPortStats: []models.PortStat{{BindAddress: "127.0.0.1", Port: "80"}}}}},
						"packb": models.Package{Name: "packb", AffectedProcs: []models.AffectedProcess{{PID: "75", Name: "sshd", ListenPortStats: []models.PortStat{{BindAddress: "127.0.0.1", Port: "22"}}}}},
						"packc": models.Package{Name: "packc", AffectedProcs: []models.AffectedProcess{{PID: "75", Name: "sshd", ListenPortStats: []models.PortStat{{BindAddress: "127.0.0.1", Port: "22"}, {BindAddress: "192.168.1.1", Port: "22"}}}}},
						"packd": models.Package{Name: "packd", AffectedProcs: []models.AffectedProcess{{PID: "75", Name: "sshd", ListenPortStats: []models.PortStat{{BindAddress: "*", Port: "22"}}}}},
					},
				}},
				listenIPPorts: []string{"127.0.0.1:22", "192.168.1.1:22"}},
			expect: models.Packages{
				"packa": models.Package{Name: "packa", AffectedProcs: []models.AffectedProcess{{PID: "75", Name: "sshd", ListenPortStats: []models.PortStat{{BindAddress: "127.0.0.1", Port: "80", PortReachableTo: []string{}}}}}},
				"packb": models.Package{Name: "packb", AffectedProcs: []models.AffectedProcess{{PID: "75", Name: "sshd", ListenPortStats: []models.PortStat{{BindAddress: "127.0.0.1", Port: "22", PortReachableTo: []string{"127.0.0.1"}}}}}},
				"packc": models.Package{Name: "packc", AffectedProcs: []models.AffectedProcess{{PID: "75", Name: "sshd", ListenPortStats: []models.PortStat{{BindAddress: "127.0.0.1", Port: "22", PortReachableTo: []string{"127.0.0.1"}}, {BindAddress: "192.168.1.1", Port: "22", PortReachableTo: []string{"192.168.1.1"}}}}}},
				"packd": models.Package{Name: "packd", AffectedProcs: []models.AffectedProcess{{PID: "75", Name: "sshd", ListenPortStats: []models.PortStat{{BindAddress: "*", Port: "22", PortReachableTo: []string{"127.0.0.1", "192.168.1.1"}}}}}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.args.l.updatePortStatus(tt.args.listenIPPorts)
			if !reflect.DeepEqual(tt.args.l.osPackages.Packages, tt.expect) {
				t.Errorf("l.updatePortStatus() = %v, want %v", tt.args.l.osPackages.Packages, tt.expect)
			}
		})
	}
}

func Test_findPortScanSuccessOn(t *testing.T) {
	type args struct {
		listenIPPorts    []string
		searchListenPort models.PortStat
	}
	tests := []struct {
		name   string
		args   args
		expect []string
	}{
		{name: "open_empty", args: args{listenIPPorts: []string{}, searchListenPort: models.PortStat{BindAddress: "127.0.0.1", Port: "22"}}, expect: []string{}},
		{name: "port_empty", args: args{listenIPPorts: []string{"127.0.0.1:22"}, searchListenPort: models.PortStat{}}, expect: []string{}},
		{name: "single_match", args: args{listenIPPorts: []string{"127.0.0.1:22"}, searchListenPort: models.PortStat{BindAddress: "127.0.0.1", Port: "22"}}, expect: []string{"127.0.0.1"}},
		{name: "no_match_address", args: args{listenIPPorts: []string{"127.0.0.1:22"}, searchListenPort: models.PortStat{BindAddress: "192.168.1.1", Port: "22"}}, expect: []string{}},
		{name: "no_match_port", args: args{listenIPPorts: []string{"127.0.0.1:22"}, searchListenPort: models.PortStat{BindAddress: "127.0.0.1", Port: "80"}}, expect: []string{}},
		{name: "asterisk_match", args: args{listenIPPorts: []string{"127.0.0.1:22", "127.0.0.1:80", "192.168.1.1:22"}, searchListenPort: models.PortStat{BindAddress: "*", Port: "22"}}, expect: []string{"127.0.0.1", "192.168.1.1"}},
	}

	l := base{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if match := l.findPortTestSuccessOn(tt.args.listenIPPorts, tt.args.searchListenPort); !reflect.DeepEqual(match, tt.expect) {
				t.Errorf("findPortTestSuccessOn() = %v, want %v", match, tt.expect)
			}
		})
	}
}
