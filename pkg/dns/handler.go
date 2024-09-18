package dns

import (
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	notIPQuery = 0
	_IP4Query  = 4
	_IP6Query  = 6
)

// Question type
type Question struct {
	Qname  string `json:"name"`
	Qtype  string `json:"type"`
	Qclass string `json:"class"`
}

// QuestionCacheEntry represents a full query from a client with metadata
type QuestionCacheEntry struct {
	Date    int64    `json:"date"`
	Remote  string   `json:"client"`
	Blocked bool     `json:"blocked"`
	Query   Question `json:"query"`
}

// String formats a question
func (q *Question) String() string {
	return q.Qname + " " + q.Qclass + " " + q.Qtype
}

// DNSHandler type
type DNSHandler struct {
	requestChannel chan DNSOperationData
	resolver       *Resolver
	cache          Cache
	negCache       Cache
	active         bool
	muActive       sync.RWMutex
}

// DNSOperationData type
type DNSOperationData struct {
	Net string
	w   dns.ResponseWriter
	req *dns.Msg
}

// NewHandler returns a new DNSHandler
func NewHandler(config *Config, blockCache *MemoryBlockCache, questionCache *MemoryQuestionCache) *DNSHandler {
	var (
		clientConfig *dns.ClientConfig
		resolver     *Resolver
		cache        Cache
		negCache     Cache
	)

	resolver = &Resolver{clientConfig}

	cache = &MemoryCache{
		Backend:  make(map[string]*Mesg, config.Maxcount),
		Maxcount: config.Maxcount,
	}
	negCache = &MemoryCache{
		Backend:  make(map[string]*Mesg),
		Maxcount: config.Maxcount,
	}

	handler := &DNSHandler{
		requestChannel: make(chan DNSOperationData),
		resolver:       resolver,
		cache:          cache,
		negCache:       negCache,
		active:         true,
	}

	go handler.do(config, blockCache, questionCache)

	return handler
}

func (h *DNSHandler) do(config *Config, blockCache *MemoryBlockCache, questionCache *MemoryQuestionCache) {
	for {
		data, ok := <-h.requestChannel
		if !ok {
			break
		}
		func(Net string, w dns.ResponseWriter, req *dns.Msg) {
			defer func(w dns.ResponseWriter) {
				err := w.Close()
				if err != nil {
				}
			}(w)
			q := req.Question[0]
			Q := Question{UnFqdn(q.Name), dns.TypeToString[q.Qtype], dns.ClassToString[q.Qclass]}

			var remote net.IP
			if Net == "tcp" {
				remote = w.RemoteAddr().(*net.TCPAddr).IP
			} else {
				remote = w.RemoteAddr().(*net.UDPAddr).IP
			}

			log.Info().Msgf("%s lookup　%s\n", remote, Q.String())

			IPQuery := h.isIPQuery(q)

			// Only query cache when qtype == 'A'|'AAAA' , qclass == 'IN'
			key := KeyGen(Q)
			if IPQuery > 0 {
				mesg, blocked, err := h.cache.Get(key)
				if err != nil {
					if mesg, blocked, err = h.negCache.Get(key); err != nil {
						log.Debug().Msgf("%s didn't hit cache\n", Q.String())
					} else {
						log.Debug().Msgf("%s hit negative cache\n", Q.String())
						h.HandleFailed(w, req)
						return
					}
				} else {
					if blocked {
						log.Debug().Msgf("%s hit cache and was blocked: forwarding request\n", Q.String())
					} else {
						log.Debug().Msgf("%s hit cache\n", Q.String())

						// we need this copy against concurrent modification of ID
						msg := *mesg
						msg.Id = req.Id
						h.WriteReplyMsg(w, &msg)
						return
					}
				}
			}
			// Check blocklist
			var blacklisted = false
			var drblblacklisted bool

			if IPQuery > 0 {
				blacklisted = blockCache.Exists(Q.Qname)
				log.Debug().Msgf("DrblBlistCheck is disabled for =>", Q.Qname, "The result is =>", drblblacklisted)

				if blacklisted || drblblacklisted {
					m := new(dns.Msg)
					m.SetReply(req)

					if config.NXDomain {
						m.SetRcode(req, dns.RcodeNameError)
					} else {
						nullroute := net.ParseIP(config.Nullroute)
						nullroutev6 := net.ParseIP(config.Nullroutev6)

						switch IPQuery {
						case _IP4Query:
							rrHeader := dns.RR_Header{
								Name:   q.Name,
								Rrtype: dns.TypeA,
								Class:  dns.ClassINET,
								Ttl:    config.TTL,
							}
							a := &dns.A{Hdr: rrHeader, A: nullroute}
							m.Answer = append(m.Answer, a)
						case _IP6Query:
							rrHeader := dns.RR_Header{
								Name:   q.Name,
								Rrtype: dns.TypeAAAA,
								Class:  dns.ClassINET,
								Ttl:    config.TTL,
							}
							a := &dns.AAAA{Hdr: rrHeader, AAAA: nullroutev6}
							m.Answer = append(m.Answer, a)
						}
					}

					h.WriteReplyMsg(w, m)

					log.Info().Msgf("%s found in blocklist\n", Q.Qname)

					// log query
					NewEntry := QuestionCacheEntry{Date: time.Now().Unix(), Remote: remote.String(), Query: Q, Blocked: true}
					go questionCache.Add(NewEntry)

					// cache the block; we don't know the true TTL for blocked entries: we just enforce our config
					err := h.cache.Set(key, m, true)
					if err != nil {
						log.Error().Msgf("Set %s block cache failed: %s\n", Q.String(), err.Error())
					}

					return
				}
				log.Debug().Msgf("%s not found in blocklist\n", Q.Qname)
			}

			// log query
			NewEntry := QuestionCacheEntry{Date: time.Now().Unix(), Remote: remote.String(), Query: Q, Blocked: false}
			go questionCache.Add(NewEntry)

			mesg, err := h.resolver.Lookup(Net, req, config.Timeout, config.Interval, config.Nameservers)

			if err != nil {
				log.Error().Msgf("resolve query error %s\n", err)
				h.HandleFailed(w, req)

				// cache the failure, too!
				if err = h.negCache.Set(key, nil, false); err != nil {
					log.Error().Msgf("set %s negative cache failed: %v\n", Q.String(), err)
				}
				return
			}

			if mesg.Truncated && Net == "udp" {
				mesg, err = h.resolver.Lookup("tcp", req, config.Timeout, config.Interval, config.Nameservers)
				if err != nil {
					log.Error().Msgf("resolve tcp query error %s\n", err)
					h.HandleFailed(w, req)

					// cache the failure, too!
					if err = h.negCache.Set(key, nil, false); err != nil {
						log.Error().Msgf("set %s negative cache failed: %v\n", Q.String(), err)
					}
					return
				}
			}

			//find the smallest ttl
			ttl := config.Expire
			var candidateTTL uint32

			for index, answer := range mesg.Answer {
				log.Debug().Msgf("Answer %d - %s\n", index, answer.String())

				candidateTTL = answer.Header().Ttl

				if candidateTTL > 0 && candidateTTL < ttl {
					ttl = candidateTTL
				}
			}

			h.WriteReplyMsg(w, mesg)

			if IPQuery > 0 && len(mesg.Answer) > 0 {
				if blacklisted {
					log.Debug().Msgf("%s is blacklisted and grimd not active: not caching\n", Q.String())
				} else {
					err = h.cache.Set(key, mesg, false)
					if err != nil {
						log.Error().Msgf("set %s cache failed: %s\n", Q.String(), err.Error())
					}
					log.Debug().Msgf("insert %s into cache with ttl %d\n", Q.String(), ttl)
				}
			}
		}(data.Net, data.w, data.req)
	}
}

// DoTCP begins a tcp query
func (h *DNSHandler) DoTCP(w dns.ResponseWriter, req *dns.Msg) {
	h.muActive.RLock()
	if h.active {
		h.requestChannel <- DNSOperationData{"tcp", w, req}
	}
	h.muActive.RUnlock()
}

// DoUDP begins a udp query
func (h *DNSHandler) DoUDP(w dns.ResponseWriter, req *dns.Msg) {
	h.muActive.RLock()
	if h.active {
		h.requestChannel <- DNSOperationData{"udp", w, req}
	}
	h.muActive.RUnlock()
}

// HandleFailed handles dns failures
func (h *DNSHandler) HandleFailed(w dns.ResponseWriter, message *dns.Msg) {
	m := new(dns.Msg)
	m.SetRcode(message, dns.RcodeServerFailure)
	h.WriteReplyMsg(w, m)
}

// WriteReplyMsg writes the dns reply
func (h *DNSHandler) WriteReplyMsg(w dns.ResponseWriter, message *dns.Msg) {
	defer func() {
		if r := recover(); r != nil {
			log.Info().Msgf("Recovered in WriteReplyMsg: %s\n", r)
		}
	}()

	err := w.WriteMsg(message)
	if err != nil {
		log.Error().Err(err).Msg(err.Error())
	}
}

func (h *DNSHandler) isIPQuery(q dns.Question) int {
	if q.Qclass != dns.ClassINET {
		return notIPQuery
	}

	switch q.Qtype {
	case dns.TypeA:
		return _IP4Query
	case dns.TypeAAAA:
		return _IP6Query
	default:
		return notIPQuery
	}
}

// UnFqdn function
func UnFqdn(s string) string {
	if dns.IsFqdn(s) {
		return s[:len(s)-1]
	}
	return s
}
