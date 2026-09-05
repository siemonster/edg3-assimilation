package adapters

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// RFC 5424: <PRI>VERSION TIMESTAMP HOST APP PROCID MSGID [SD] MSG
var syslogRE = regexp.MustCompile(
	`^<(\d{1,3})>1 (\S+) (\S+) (\S+) (\S+) (\S+) (?:-|\[.*?\]) ?(.*)$`)

type syslog5424 struct{}

// NewSyslog5424 returns an adapter for RFC 5424 syslog lines.
func NewSyslog5424() Adapter { return syslog5424{} }

func (syslog5424) Name() string { return "syslog5424" }

func (syslog5424) Parse(line []byte) (Record, error) {
	text := string(line)
	if strings.TrimSpace(text) == "" {
		return nil, nil // a blank line carries no event
	}
	m := syslogRE.FindStringSubmatch(text)
	if m == nil {
		return nil, fmt.Errorf("line is not RFC 5424 syslog")
	}
	priority, err := strconv.Atoi(m[1])
	if err != nil || priority > 191 {
		return nil, fmt.Errorf("priority %q is out of range", m[1])
	}
	rec := Record{"severity": strconv.Itoa(priority % 8), "facility": strconv.Itoa(priority / 8)}
	// RFC 5424's NILVALUE ("-") marks a field absent; drop it rather than
	// keep the dash as a literal value.
	for key, value := range map[string]string{
		"ts": m[2], "host": m[3], "app": m[4], "procid": m[5], "msgid": m[6], "msg": m[7],
	} {
		if value != "-" {
			rec[key] = value
		}
	}
	return rec, nil
}
