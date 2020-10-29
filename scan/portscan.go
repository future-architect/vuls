package scan

import (
	"net"
	"strings"
	"time"

	"github.com/future-architect/vuls/models"
)

func (l *base) parseListenPorts(port string) models.ListenPort {
	sep := strings.LastIndex(port, ":")
	if sep == -1 {
		return models.ListenPort{}
	}
	return models.ListenPort{Address: port[:sep], Port: port[sep+1:]}
}

func (l *base) scanPorts() (err error) {
	dest := l.detectScanDest()
	open, err := l.execPortsScan(dest)
	if err != nil {
		return err
	}
	l.updatePortStatus(open)

	return nil
}

func (l *base) detectScanDest() map[string][]string {
	scanIPPortsMap := map[string][]string{}

	for _, p := range l.osPackages.Packages {
		if p.AffectedProcs == nil {
			continue
		}
		for _, proc := range p.AffectedProcs {
			if proc.ListenPorts == nil {
				continue
			}
			for _, port := range proc.ListenPorts {
				scanIPPortsMap[port.Address] = append(scanIPPortsMap[port.Address], port.Port)
			}
		}
	}

	scanDestIPPorts := map[string][]string{}
	for addr, ports := range scanIPPortsMap {
		if addr == "*" {
			for _, addr := range l.ServerInfo.IPv4Addrs {
				scanDestIPPorts[addr] = append(scanDestIPPorts[addr], ports...)
			}
		} else {
			scanDestIPPorts[addr] = append(scanDestIPPorts[addr], ports...)
		}
	}

	uniqScanDestIPPorts := map[string][]string{}
	for i, scanDest := range scanDestIPPorts {
		m := map[string]bool{}
		for _, e := range scanDest {
			if !m[e] {
				m[e] = true
				uniqScanDestIPPorts[i] = append(uniqScanDestIPPorts[i], e)
			}
		}
	}

	return uniqScanDestIPPorts
}

func (l *base) execPortsScan(scanDestIPPorts map[string][]string) ([]string, error) {
	listenIPPorts := []string{}

	for ip, ports := range scanDestIPPorts {
		if !isLocalExec(l.ServerInfo.Port, l.ServerInfo.Host) && net.ParseIP(ip).IsLoopback() {
			continue
		}
		for _, port := range ports {
			scanDest := ip + ":" + port
			conn, err := net.DialTimeout("tcp", scanDest, time.Duration(1)*time.Second)
			if err != nil {
				continue
			}
			conn.Close()
			listenIPPorts = append(listenIPPorts, scanDest)
		}
	}

	return listenIPPorts, nil
}

func (l *base) updatePortStatus(listenIPPorts []string) {
	for name, p := range l.osPackages.Packages {
		if p.AffectedProcs == nil {
			continue
		}
		for i, proc := range p.AffectedProcs {
			if proc.ListenPorts == nil {
				continue
			}
			for j, port := range proc.ListenPorts {
				l.osPackages.Packages[name].AffectedProcs[i].ListenPorts[j].PortScanSuccessOn = l.findPortScanSuccessOn(listenIPPorts, port)
			}
		}
	}
}

func (l *base) findPortScanSuccessOn(listenIPPorts []string, searchListenPort models.ListenPort) []string {
	addrs := []string{}

	for _, ipPort := range listenIPPorts {
		ipPort := l.parseListenPorts(ipPort)
		if searchListenPort.Address == "*" {
			if searchListenPort.Port == ipPort.Port {
				addrs = append(addrs, ipPort.Address)
			}
		} else if searchListenPort.Address == ipPort.Address && searchListenPort.Port == ipPort.Port {
			addrs = append(addrs, ipPort.Address)
		}
	}

	return addrs
}
