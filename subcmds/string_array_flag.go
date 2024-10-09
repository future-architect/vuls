package subcmds

import "strings"

type stringArrayFlag struct {
	target *[]string
}

func (f *stringArrayFlag) String() string {
	if f.target == nil {
		return ""
	}
	return strings.Join(*f.target, ",")
}

func (f *stringArrayFlag) Set(value string) error {
	*f.target = strings.Split(value, ",")
	return nil
}
