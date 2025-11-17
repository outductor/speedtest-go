package speedtest

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"syscall"
	"time"
)

var (
	version          = "1.7.10"
	DefaultUserAgent = fmt.Sprintf("showwin/speedtest-go %s", version)
)

type Proto int

const (
	HTTP Proto = iota
	TCP
	ICMP
)

// Speedtest is a speedtest client.
type Speedtest struct {
	User *User
	Manager

	doer        *http.Client // HTTP client for speed tests (with IPv4/IPv6 restrictions)
	setupClient *http.Client // HTTP client for initial setup (dual-stack, no restrictions)
	config      *UserConfig
	tcpDialer   *net.Dialer
	ipDialer    *net.Dialer
}

type UserConfig struct {
	T             *http.Transport
	UserAgent     string
	Proxy         string
	Source        string
	DnsBindSource bool
	DialerControl func(network, address string, c syscall.RawConn) error
	Debug         bool
	PingMode      Proto

	SavingMode     bool
	MaxConnections int

	CityFlag     string
	LocationFlag string
	Location     *Location

	Keyword string // Fuzzy search

	IPv4Only bool
	IPv6Only bool

	// Internal fields set based on IPv4Only/IPv6Only
	tcpNetwork  string
	udpNetwork  string
	icmpNetwork string
}

func parseAddr(addr string) (string, string) {
	prefixIndex := strings.Index(addr, "://")
	if prefixIndex != -1 {
		return addr[:prefixIndex], addr[prefixIndex+3:]
	}
	return "", addr // ignore address network prefix
}

func (s *Speedtest) NewUserConfig(uc *UserConfig) {
	if uc.Debug {
		dbg.Enable()
	}

	if uc.SavingMode {
		uc.MaxConnections = 1 // Set the number of concurrent connections to 1
	}
	s.SetNThread(uc.MaxConnections)

	if len(uc.CityFlag) > 0 {
		var err error
		uc.Location, err = GetLocation(uc.CityFlag)
		if err != nil {
			dbg.Printf("Warning: skipping command line arguments: --city. err: %v\n", err.Error())
		}
	}
	if len(uc.LocationFlag) > 0 {
		var err error
		uc.Location, err = ParseLocation(uc.CityFlag, uc.LocationFlag)
		if err != nil {
			dbg.Printf("Warning: skipping command line arguments: --location. err: %v\n", err.Error())
		}
	}

	// Determine network types based on IPv4/IPv6 preferences
	uc.tcpNetwork = "tcp"
	uc.udpNetwork = "udp"
	uc.icmpNetwork = "ip:icmp"
	if uc.IPv4Only {
		uc.tcpNetwork = "tcp4"
		uc.udpNetwork = "udp4"
		uc.icmpNetwork = "ip4:icmp"
		dbg.Printf("Network: IPv4 only\n")
	} else if uc.IPv6Only {
		uc.tcpNetwork = "tcp6"
		uc.udpNetwork = "udp6"
		uc.icmpNetwork = "ip6:icmp"
		dbg.Printf("Network: IPv6 only\n")
	}

	var tcpSource net.Addr // If nil, a local address is automatically chosen.
	var icmpSource net.Addr
	var proxy = http.ProxyFromEnvironment
	s.config = uc
	if len(s.config.UserAgent) == 0 {
		s.config.UserAgent = DefaultUserAgent
	}
	if len(uc.Source) > 0 {
		_, address := parseAddr(uc.Source)
		addr0, err := net.ResolveTCPAddr(uc.tcpNetwork, fmt.Sprintf("[%s]:0", address)) // dynamic tcp port
		if err == nil {
			tcpSource = addr0
		} else {
			dbg.Printf("Warning: skipping parse the source address. err: %s\n", err.Error())
		}
		addr1, err := net.ResolveIPAddr("ip", address) // dynamic tcp port
		if err == nil {
			icmpSource = addr1
		} else {
			dbg.Printf("Warning: skipping parse the source address. err: %s\n", err.Error())
		}
		if uc.DnsBindSource {
			net.DefaultResolver.Dial = func(ctx context.Context, network, dnsServer string) (net.Conn, error) {
				// Override network type based on IPv4/IPv6 preference
				if uc.IPv4Only {
					if strings.HasPrefix(network, "udp") {
						network = "udp4"
					} else if strings.HasPrefix(network, "tcp") {
						network = "tcp4"
					}
				} else if uc.IPv6Only {
					if strings.HasPrefix(network, "udp") {
						network = "udp6"
					} else if strings.HasPrefix(network, "tcp") {
						network = "tcp6"
					}
				}
				dialer := &net.Dialer{
					Timeout: 5 * time.Second,
					LocalAddr: func(network string) net.Addr {
						switch network {
						case "udp", "udp4", "udp6":
							return &net.UDPAddr{IP: net.ParseIP(address)}
						case "tcp", "tcp4", "tcp6":
							return &net.TCPAddr{IP: net.ParseIP(address)}
						default:
							return nil
						}
					}(network),
				}
				return dialer.DialContext(ctx, network, dnsServer)
			}
		}
	}

	if len(uc.Proxy) > 0 {
		if parse, err := url.Parse(uc.Proxy); err != nil {
			dbg.Printf("Warning: skipping parse the proxy host. err: %s\n", err.Error())
		} else {
			proxy = func(_ *http.Request) (*url.URL, error) {
				return parse, err
			}
		}
	}

	s.tcpDialer = &net.Dialer{
		LocalAddr: tcpSource,
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   uc.DialerControl,
	}

	s.ipDialer = &net.Dialer{
		LocalAddr: icmpSource,
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   uc.DialerControl,
	}

	// Create a custom DialContext that enforces the network type for speed tests
	dialContext := func(ctx context.Context, network, address string) (net.Conn, error) {
		// Override the network type based on IPv4/IPv6 preference
		if uc.IPv4Only && strings.HasPrefix(network, "tcp") {
			network = "tcp4"
		} else if uc.IPv6Only && strings.HasPrefix(network, "tcp") {
			network = "tcp6"
		}
		return s.tcpDialer.DialContext(ctx, network, address)
	}

	// HTTP Transport for speed tests (with IPv4/IPv6 restrictions)
	s.config.T = &http.Transport{
		Proxy:                 proxy,
		DialContext:           dialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	s.doer.Transport = s

	// Create a separate HTTP Transport for initial setup (dual-stack, no IPv4/IPv6 restrictions)
	// This allows fetching server lists and user info even when using -6 flag with IPv6-only servers
	setupTransport := &http.Transport{
		Proxy:                 proxy,
		DialContext:           s.tcpDialer.DialContext, // No network type override
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	// setupClient uses the dual-stack transport
	s.setupClient = &http.Client{Transport: setupTransport}
}

func (s *Speedtest) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Add("User-Agent", s.config.UserAgent)
	return s.config.T.RoundTrip(req)
}

// Option is a function that can be passed to New to modify the Client.
type Option func(*Speedtest)

// WithDoer sets the http.Client used to make requests.
func WithDoer(doer *http.Client) Option {
	return func(s *Speedtest) {
		s.doer = doer
	}
}

// WithUserConfig adds a custom user config for speedtest.
// This configuration may be overwritten again by WithDoer,
// because client and transport are parent-child relationship:
// `New(WithDoer(myDoer), WithUserAgent(myUserAgent), WithDoer(myDoer))`
func WithUserConfig(userConfig *UserConfig) Option {
	return func(s *Speedtest) {
		s.NewUserConfig(userConfig)
		dbg.Printf("Source: %s\n", s.config.Source)
		dbg.Printf("Proxy: %s\n", s.config.Proxy)
		dbg.Printf("SavingMode: %v\n", s.config.SavingMode)
		dbg.Printf("Keyword: %v\n", s.config.Keyword)
		dbg.Printf("PingType: %v\n", s.config.PingMode)
		dbg.Printf("OS: %s, ARCH: %s, NumCPU: %d\n", runtime.GOOS, runtime.GOARCH, runtime.NumCPU())
	}
}

// New creates a new speedtest client.
func New(opts ...Option) *Speedtest {
	s := &Speedtest{
		doer:    http.DefaultClient,
		Manager: NewDataManager(),
	}
	// load default config
	s.NewUserConfig(&UserConfig{UserAgent: DefaultUserAgent})

	for _, opt := range opts {
		opt(s)
	}
	return s
}

func Version() string {
	return version
}

var defaultClient = New()
