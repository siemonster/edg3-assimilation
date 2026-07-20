package adapters

import (
	"fmt"
	"regexp"
	"strconv"
)

// RFC 5424: <PRI>VERSION TIMESTAMP HOST APP PROCID MSGID [SD] MSG
var syslogRE = regexp.MustCompile(
	`^<(\d{1,3})>1 (\S+) (\S+) (\S+) (\S+) (\S+) (?:-|\[.*?\]) ?(.*)$`)

type syslog5424 struct{}

// NewSyslog5424 returns an adapter for RFC 5424 syslog lines.
func NewSyslog5424() Adapter { return syslog5424{} }

func (syslog5424) Name() string { return "syslog5424" }

func (syslog5424) Parse(line []byte) (Record, error) {
	m := syslogRE.FindStringSubmatch(string(line))
	if m == nil {
		return nil, fmt.Errorf("line is not RFC 5424 syslog")
	}
	priority, err := strconv.Atoi(m[1])
	if err != nil || priority > 191 {
		return nil, fmt.Errorf("priority %q is out of range", m[1])
	}
	return Record{
		"ts": m[2], "host": m[3], "app": m[4], "procid": m[5], "msgid": m[6], "msg": m[7],
		"severity": strconv.Itoa(priority % 8), "facility": strconv.Itoa(priority / 8),
	}, nil
}
