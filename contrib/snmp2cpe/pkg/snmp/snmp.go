package snmp

import (
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/pkg/errors"
)

type options struct {
	community string
	debug     bool
}

// Option ...
type Option interface {
	apply(*options)
}

type communityOption string

func (c communityOption) apply(opts *options) {
	opts.community = string(c)
}

// WithCommunity ...
func WithCommunity(c string) Option {
	return communityOption(c)
}

type debugOption bool

func (d debugOption) apply(opts *options) {
	opts.debug = bool(d)
}

// WithDebug ...
func WithDebug(d bool) Option {
	return debugOption(d)
}

// Get ...
func Get(version gosnmp.SnmpVersion, ipaddr string, opts ...Option) (Result, error) {
	var options options
	for _, o := range opts {
		o.apply(&options)
	}

	r := Result{SysDescr0: "", EntPhysicalTables: map[int]EntPhysicalTable{}}

	params := &gosnmp.GoSNMP{
		Target:             ipaddr,
		Port:               161,
		Version:            version,
		Timeout:            time.Duration(2) * time.Second,
		Retries:            3,
		ExponentialTimeout: true,
		MaxOids:            gosnmp.MaxOids,
	}

	switch version {
	case gosnmp.Version1, gosnmp.Version2c:
		params.Community = options.community
	case gosnmp.Version3:
		return Result{}, errors.New("not implemented")
	}

	if err := params.Connect(); err != nil {
		return Result{}, errors.Wrap(err, "failed to connect")
	}
	defer params.Conn.Close()

	for _, oid := range []string{"1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.47.1.1.1.1.12.1", "1.3.6.1.2.1.47.1.1.1.1.7.1", "1.3.6.1.2.1.47.1.1.1.1.10.1"} {
		resp, err := params.Get([]string{oid})
		if err != nil {
			return Result{}, errors.Wrap(err, "send SNMP GET request")
		}
		for _, v := range resp.Variables {
			if options.debug {
				switch v.Type {
				case gosnmp.OctetString:
					log.Printf("DEBUG: %s -> %s", v.Name, string(v.Value.([]byte)))
				default:
					log.Printf("DEBUG: %s -> %v", v.Name, v.Value)
				}
			}

			switch {
			case v.Name == ".1.3.6.1.2.1.1.1.0":
				if v.Type == gosnmp.OctetString {
					r.SysDescr0 = string(v.Value.([]byte))
				}
			case strings.HasPrefix(v.Name, ".1.3.6.1.2.1.47.1.1.1.1.12."):
				i, err := strconv.Atoi(strings.TrimPrefix(v.Name, ".1.3.6.1.2.1.47.1.1.1.1.12."))
				if err != nil {
					return Result{}, errors.Wrap(err, "failed to get index")
				}
				if v.Type == gosnmp.OctetString {
					b := r.EntPhysicalTables[i]
					b.EntPhysicalMfgName = string(v.Value.([]byte))
					r.EntPhysicalTables[i] = b
				}
			case strings.HasPrefix(v.Name, ".1.3.6.1.2.1.47.1.1.1.1.7."):
				i, err := strconv.Atoi(strings.TrimPrefix(v.Name, ".1.3.6.1.2.1.47.1.1.1.1.7."))
				if err != nil {
					return Result{}, errors.Wrap(err, "failed to get index")
				}
				if v.Type == gosnmp.OctetString {
					b := r.EntPhysicalTables[i]
					b.EntPhysicalName = string(v.Value.([]byte))
					r.EntPhysicalTables[i] = b
				}
			case strings.HasPrefix(v.Name, ".1.3.6.1.2.1.47.1.1.1.1.10."):
				i, err := strconv.Atoi(strings.TrimPrefix(v.Name, ".1.3.6.1.2.1.47.1.1.1.1.10."))
				if err != nil {
					return Result{}, errors.Wrap(err, "failed to get index")
				}
				if v.Type == gosnmp.OctetString {
					b := r.EntPhysicalTables[i]
					b.EntPhysicalSoftwareRev = string(v.Value.([]byte))
					r.EntPhysicalTables[i] = b
				}
			}
		}
	}

	return r, nil
}
