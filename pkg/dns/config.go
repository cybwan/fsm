package dns

import (
	"github.com/jonboulle/clockwork"
)

// Config holds the configuration parameters
type Config struct {
	NXDomain         bool     // response to blocked queries with a NXDOMAIN
	Nullroute        string   // ipv4 address to forward blocked queries to
	Nullroutev6      string   // ipv6 address to forward blocked queries to
	Nameservers      []string // nameservers to forward queries to
	Interval         int      // concurrency interval for lookups in miliseconds
	Timeout          int      // query timeout for dns lookups in seconds
	Expire           uint32   // cache entry lifespan in seconds
	Maxcount         int      // cache capacity, 0 for infinite
	QuestionCacheCap int      // question cache capacity, 0 for infinite but not recommended (this is used for storing logs)
	TTL              uint32
	Blocklist        []string // manual blocklist entries
	Whitelist        []string // manual whitelist entries
	CustomDNSRecords []string // manual custom dns entries
}

// WallClock is the wall clock
var WallClock = clockwork.NewRealClock()
