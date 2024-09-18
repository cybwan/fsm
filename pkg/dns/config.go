package dns

import (
	"github.com/jonboulle/clockwork"
)

// Config holds the configuration parameters
type Config struct {
	Bind             string
	NXDomain         bool
	Nullroute        string
	Nullroutev6      string
	Nameservers      []string
	Interval         int
	Timeout          int
	Expire           uint32
	Maxcount         int
	QuestionCacheCap int
	TTL              uint32
	Blocklist        []string
	Whitelist        []string
	CustomDNSRecords []string
}

// WallClock is the wall clock
var WallClock = clockwork.NewRealClock()
