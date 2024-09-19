package dns

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"

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
func NewHandler(config *Config, blockCache *MemoryBlockCache) *DNSHandler {
	var (
		clientConfig *dns.ClientConfig
		resolver     *Resolver
	)

	resolver = &Resolver{clientConfig}

	handler := &DNSHandler{
		requestChannel: make(chan DNSOperationData),
		resolver:       resolver,
		active:         true,
	}

	go handler.do(config, blockCache)

	return handler
}

func (h *DNSHandler) do(config *Config, blockCache *MemoryBlockCache) {
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

			for index, q := range req.Question {
				if strings.HasSuffix(q.Name, ".svc.cluster.local.") {
					if segs := strings.Split(q.Name, "."); len(segs) == 7 {
						req.Question[index].Name = fmt.Sprintf("%s.%s.svc.cluster.local.", segs[0], segs[1])
					}
				}
			}

			q := req.Question[0]
			Q := Question{UnFqdn(q.Name), dns.TypeToString[q.Qtype], dns.ClassToString[q.Qclass]}

			var remote net.IP
			if Net == "tcp" {
				remote = w.RemoteAddr().(*net.TCPAddr).IP
			} else {
				remote = w.RemoteAddr().(*net.UDPAddr).IP
			}

			log.Info().Msgf("%s lookup　%s\n", remote, Q.String())
			fmt.Printf("%s lookup　%s\n", remote, Q.String())

			ipQuery := h.isIPQuery(q)
			if ipQuery == 0 {
				m := new(dns.Msg)
				m.SetReply(req)
				m.SetRcode(req, dns.RcodeNameError)
				h.WriteReplyMsg(w, m)
				return
			}

			if blacklisted := blockCache.Exists(Q.Qname); blacklisted {
				m := new(dns.Msg)
				m.SetReply(req)

				if config.NXDomain {
					m.SetRcode(req, dns.RcodeNameError)
				} else {
					nullroute := net.ParseIP(config.Nullroute)
					nullroutev6 := net.ParseIP(config.Nullroutev6)

					switch ipQuery {
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
				return
			}

			res, err := h.resolver.Lookup(Net, req, config.Timeout, config.Interval, config.Nameservers)

			if err != nil {
				log.Error().Msgf("resolve query error %s\n", err)
				h.HandleFailed(w, req)
				return
			}

			if res.Truncated && Net == "udp" {
				res, err = h.resolver.Lookup("tcp", req, config.Timeout, config.Interval, config.Nameservers)
				if err != nil {
					log.Error().Msgf("resolve tcp query error %s\n", err)
					h.HandleFailed(w, req)
					return
				}
			}

			reqbytes, _ := json.MarshalIndent(req, "", "")
			resbytes, _ := json.MarshalIndent(res, "", "")
			fmt.Println(string(reqbytes), "=>", string(resbytes), "\n\n")

			h.WriteReplyMsg(w, res)
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
