package dnsredir

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/http/cookiejar"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// A persistConn hold the dns.Conn and the last used time(time.Time struct)
// Taken from github.com/coredns/plugin/forward/persistent.go
type persistConn struct {
	c    *dns.Conn
	used time.Time
}

func (pc *persistConn) String() string {
	return fmt.Sprintf("{%T c=%v used=%v}", pc, pc.c.RemoteAddr(), pc.used)
}

// Transport settings
// Inspired from coredns/plugin/forward/persistent.go
// addr isn't sealed into this struct since it's a high-level item
type Transport struct {
	avgDialTime int64 // Cumulative moving average dial time in ns(i.e. time.Duration)

	recursionDesired bool          // RD flag
	expire           time.Duration // [sic] After this duration a connection is expired
	tlsConfig        *tls.Config
	proxy            *socks5Dialer

	conns [typeTotalCount][]*persistConn // Buckets for udp, tcp and tcp-tls
	dial  chan string
	yield chan *persistConn
	ret   chan *persistConn
	stop  chan struct{}
}

func newTransport() *Transport {
	return &Transport{
		avgDialTime: int64(minDialTimeout),
		expire:      defaultConnExpire,
		conns:       [typeTotalCount][]*persistConn{},
		dial:        make(chan string),
		yield:       make(chan *persistConn),
		ret:         make(chan *persistConn),
		stop:        make(chan struct{}),
	}
}

func (t *Transport) connManager() {
	ticker := time.NewTicker(t.expire)

	for {
		select {
		case proto := <-t.dial:
			transType := stringToTransportType(proto)
			// Take the last used conn - complexity O(1)
			if stack := t.conns[transType]; len(stack) > 0 {
				pc := stack[len(stack)-1]
				if time.Since(pc.used) < t.expire {
					// Found one, remove from pool and return this conn.
					t.conns[transType] = stack[:len(stack)-1]
					t.ret <- pc
					continue
				}
				// clear entire cache if the last conn is expired
				t.conns[transType] = nil
				// now, the connections being passed to closeConns() are not reachable from
				// transport methods anymore. So, it's safe to close them in a separate goroutine
				go closeConns(stack)
			}
			t.ret <- nil

		case pc := <-t.yield:
			transType := t.transportTypeFromConn(pc)
			t.conns[transType] = append(t.conns[transType], pc)

		case <-ticker.C:
			t.cleanup(false)

		case <-t.stop:
			t.cleanup(true)
			close(t.ret)
			return
		}
	}
}

func closeConns(conns []*persistConn) {
	for _, pc := range conns {
		Close(pc.c)
	}
}

// cleanup removes connections from cache.
func (t *Transport) cleanup(all bool) {
	staleTime := time.Now().Add(-t.expire)

	for transType, stack := range t.conns {
		if len(stack) == 0 {
			continue
		}
		if all {
			t.conns[transType] = nil
			// now, the connections being passed to closeConns() are not reachable from
			// transport methods anymore. So, it's safe to close them in a separate goroutine
			go closeConns(stack)
			continue
		}
		if stack[0].used.After(staleTime) {
			// Skip if all connections are valid
			continue
		}

		// connections in stack are sorted by "used"
		firstGood := sort.Search(len(stack), func(i int) bool {
			return stack[i].used.After(staleTime)
		})
		t.conns[transType] = stack[firstGood:]
		log.Debugf("Going to cleanup expired connection(s): %v count: %v", stack[0].c.RemoteAddr(), firstGood)
		// now, the connections being passed to closeConns() are not reachable from
		// transport methods anymore. So, it's safe to close them in a separate goroutine
		go closeConns(stack[:firstGood])
	}
}

// It is hard to pin a value to this, the import thing is to no block forever, losing at cached connection is not terrible.
const yieldTimeout = 25 * time.Millisecond

// Yield return the connection to transport for reuse.
func (t *Transport) Yield(pc *persistConn) {
	pc.used = time.Now() // update used time

	// Make this non-blocking, because in the case of a very busy forwarder we will *block* on this yield. This
	// blocks the outer go-routine and stuff will just pile up.  We timeout when the send fails to as returning
	// these connection is an optimization anyway.
	select {
	case t.yield <- pc:
		return
	case <-time.After(yieldTimeout):
		return
	}
}

// Start starts the transport's connection manager.
func (t *Transport) Start() { go t.connManager() }

// Stop stops the transport's connection manager.
func (t *Transport) Stop() { close(t.stop) }

// UpstreamHostDownFunc can be used to customize how Down behaves
// see: proxy/healthcheck/healthcheck.go
type UpstreamHostDownFunc func(*UpstreamHost) bool

// UpstreamHost represents a single upstream DNS server
type UpstreamHost struct {
	proto string // DNS protocol, i.e. "udp", "tcp", etc.
	addr  string // IP:PORT

	fails    int32                // Fail count
	downFunc UpstreamHostDownFunc // This function should be side-effect safe

	c *dns.Client // DNS client used for health check

	// Transport settings related to this upstream host
	// Currently, it's the same as HealthCheck.transport since Caddy doesn't over nested blocks
	// XXX: We may support per-upstream specific transport once Caddy supported nesting blocks in future
	transport *Transport

	httpClient         *http.Client
	requestContentType string
}

func (uh *UpstreamHost) Name() string {
	return uh.proto + "://" + uh.addr
}

func (uh *UpstreamHost) IsDOH() bool {
	return uh.proto == "https"
}

func (uh *UpstreamHost) InitDOH(u *reloadableUpstream) {
	if !strings.HasSuffix(uh.proto, "doh") {
		return
	}

	var resolver *net.Resolver
	if len(u.bootstrap) != 0 {
		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				var d net.Dialer
				// Randomly choose a bootstrap DNS to resolve upstream host
				addr := u.bootstrap[rand.Intn(len(u.bootstrap))]
				return d.DialContext(ctx, network, addr)
			},
		}
	} else {
		// Fallback to use system default resolvers, which located at /etc/resolv.conf
	}

	dialer := &net.Dialer{
		Timeout:   8 * time.Second,
		KeepAlive: 30 * time.Second,
		Resolver:  resolver,
	}
	httpTransport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   5,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   8 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	dialContext := dialer.DialContext
	if u.proxy != nil {
		httpTransport.Proxy = nil
		dialContext = u.proxy.DialContext
	}
	httpTransport.DialContext = dialContext
	if u.noIPv6 {
		httpTransport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			if strings.HasPrefix(network, "tcp") {
				network = "tcp4"
			}
			return dialContext(ctx, network, addr)
		}
	}

	cookieJar, err := cookiejar.New(nil)
	if err != nil {
		panic(fmt.Sprintf("cookiejar.New() failed, error: %v", err))
	}
	switch uh.proto {
	case "json-doh":
		uh.requestContentType = mimeTypeDnsJson
	case "ietf-doh":
		uh.requestContentType = mimeTypeDnsMessage
	case "doh":
		uh.requestContentType = mimeTypeDohAny
	default:
		panic(fmt.Sprintf("Unknown DOH protocol %q", uh.proto))
	}
	uh.proto = "https"
	uh.httpClient = &http.Client{
		Transport: httpTransport,
		Jar:       cookieJar,
		Timeout:   10 * time.Second,
	}
}

// Taken from coredns/plugin/forward/connect.go
// see: https://en.wikipedia.org/wiki/Moving_average#Cumulative_moving_average
//
// limitDialTimeout is a utility function to auto-tune timeout values
// average observed time is moved towards the last observed delay moderated by a weight
// next timeout to use will be the double of the computed average, limited by min and max frame.
func limitDialTimeout(currentAvg *int64, minValue, maxValue time.Duration) time.Duration {
	rt := time.Duration(atomic.LoadInt64(currentAvg))
	if rt < minValue {
		return minValue
	}
	if rt < maxValue/2 {
		return rt * 2
	}
	return maxValue
}

func (t *Transport) dialTimeout() time.Duration {
	return limitDialTimeout(&t.avgDialTime, minDialTimeout, maxDialTimeout)
}

func (t *Transport) updateDialTimeout(newDialTime time.Duration) {
	oldDialTime := time.Duration(atomic.LoadInt64(&t.avgDialTime))
	dt := int64(newDialTime - oldDialTime)
	atomic.AddInt64(&t.avgDialTime, dt/cumulativeAvgWeight)
}

func dialTimeout0(network, address string, tlsConfig *tls.Config, timeout time.Duration, bootstrap []string, noIPv6 bool, pd *socks5Dialer) (*dns.Conn, error) {
	if pd != nil {
		return dialProxyConn(network, address, tlsConfig, timeout, pd)
	}

	var resolver *net.Resolver

	if len(bootstrap) != 0 {
		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				if noIPv6 {
					if strings.HasPrefix(network, "tcp") {
						network = "tcp4"
					}
					if strings.HasPrefix(network, "udp") {
						network = "udp4"
					}
				}
				var d net.Dialer
				// Randomly choose a bootstrap DNS to resolve upstream host
				addr := bootstrap[rand.Intn(len(bootstrap))]
				return d.DialContext(ctx, network, addr)
			},
		}
	} else {
		// Fallback to use system default resolvers, which located at /etc/resolv.conf
	}

	dialer := &net.Dialer{
		Timeout:  timeout,
		Resolver: resolver,
	}
	client := dns.Client{Net: network, Dialer: dialer, TLSConfig: tlsConfig}
	return client.Dial(address)
}

// [sic] DialTimeoutWithTLS acts like DialWithTLS but takes a timeout.
// Taken from dns.DialTimeoutWithTLS() with modification
func dialTimeoutWithTLS(network, address string, tlsConfig *tls.Config, timeout time.Duration, bootstrap []string, noIPv6 bool, pd *socks5Dialer) (*dns.Conn, error) {
	if !strings.HasSuffix(network, "-tls") {
		network += "-tls"
	}
	return dialTimeout0(network, address, tlsConfig, timeout, bootstrap, noIPv6, pd)
}

// [sic] DialTimeout acts like Dial but takes a timeout.
// Taken from dns.DialTimeout() with modification
func dialTimeout(network, address string, timeout time.Duration, bootstrap []string, noIPv6 bool, pd *socks5Dialer) (*dns.Conn, error) {
	return dialTimeout0(network, address, nil, timeout, bootstrap, noIPv6, pd)
}

// Return:
//
//	#0	Persistent connection
//	#1	true if it's a cached connection
//	#2	error(if any)
func (uh *UpstreamHost) Dial(proto string, bootstrap []string, noIPv6 bool) (*persistConn, bool, error) {
	if uh.proto != "dns" {
		proto = protoToNetwork(uh.proto)
	}

	uh.transport.dial <- proto
	pc := <-uh.transport.ret
	if pc != nil {
		return pc, true, nil
	}

	reqTime := time.Now()
	timeout := uh.transport.dialTimeout()
	if proto == "tcp-tls" {
		conn, err := dialTimeoutWithTLS(proto, uh.addr, uh.transport.tlsConfig, timeout, bootstrap, noIPv6, uh.transport.proxy)
		uh.transport.updateDialTimeout(time.Since(reqTime))
		if err != nil {
			return nil, false, err
		}
		return &persistConn{c: conn}, false, err
	}
	conn, err := dialTimeout(proto, uh.addr, timeout, bootstrap, noIPv6, uh.transport.proxy)
	uh.transport.updateDialTimeout(time.Since(reqTime))
	if err != nil {
		return nil, false, err
	}
	return &persistConn{c: conn}, false, err
}

func (uh *UpstreamHost) dohExchange(ctx context.Context, state *request.Request) (*dns.Msg, error) {
	var (
		resp *http.Response
		err  error
	)

	requestContentType := uh.requestContentType
	if requestContentType == mimeTypeDohAny {
		// The DOH upstream host support both JSON and RFC-8484, randomly choose one.
		if rand.Intn(2) == 0 {
			requestContentType = mimeTypeDnsJson
		} else {
			requestContentType = mimeTypeDnsMessage
		}
	}

	switch requestContentType {
	case mimeTypeDnsJson:
		resp, err = uh.jsonDnsExchange(ctx, state, requestContentType)
	case mimeTypeDnsMessage:
		resp, err = uh.ietfDnsExchange(ctx, state, requestContentType)
	default:
		panic(fmt.Sprintf("Unexpected DOH Content-Type: %q", requestContentType))
	}
	if err != nil {
		return nil, err
	}
	defer Close(resp.Body)

	contentType := strings.SplitN(resp.Header.Get("Content-Type"), ";", 2)[0]
	switch contentType {
	case mimeTypeJson:
		fallthrough
	case mimeTypeDnsJson:
		return uh.jsonDnsParseResponse(state, resp, contentType, requestContentType)
	case mimeTypeDnsMessage:
		fallthrough
	case mimeTypeDnsUdpWireFormat:
		return uh.ietfDnsParseResponse(state, resp, contentType, requestContentType)
	default:
		switch requestContentType {
		case mimeTypeDnsJson:
			return uh.jsonDnsParseResponse(state, resp, contentType, requestContentType)
		case mimeTypeDnsMessage:
			return uh.ietfDnsParseResponse(state, resp, contentType, requestContentType)
		default:
			panic(fmt.Sprintf("Unknown request Content-Type: %q", requestContentType))
		}
	}
}

func (uh *UpstreamHost) Exchange(ctx context.Context, state *request.Request, bootstrap []string, noIPv6 bool) (*dns.Msg, error) {
	if uh.IsDOH() {
		return uh.dohExchange(ctx, state)
	}

	pc, cached, err := uh.Dial(state.Proto(), bootstrap, noIPv6)
	if err != nil {
		return nil, err
	}
	if cached {
		log.Debugf("Cached connection used for %v", uh.Name())
	} else {
		log.Debugf("New connection established for %v", uh.Name())
	}

	pc.c.UDPSize = uint16(state.Size())
	if pc.c.UDPSize < dns.MinMsgSize {
		pc.c.UDPSize = dns.MinMsgSize
	}

	_ = pc.c.SetWriteDeadline(time.Now().Add(maxWriteTimeout))
	if err := pc.c.WriteMsg(state.Req); err != nil {
		Close(pc.c)
		if err == io.EOF && cached {
			return nil, errCachedConnClosed
		}
		return nil, err
	}

	_ = pc.c.SetReadDeadline(time.Now().Add(maxReadTimeout))
	ret, err := pc.c.ReadMsg()
	if err != nil {
		Close(pc.c)
		if err == io.EOF && cached {
			return nil, errCachedConnClosed
		}
		return nil, err
	}
	if state.Req.Id != ret.Id {
		Close(pc.c)
		// Unlike coredns/plugin/forward/connect.go drop out-of-order responses
		//	we pursuing not to tolerate such error
		// Thus we have some time to retry for another upstream, for example
		return nil, errors.New(fmt.Sprintf(
			"met out-of-order response\nid: %v cached: %v name: %q\nresponse:\n%v",
			state.Req.Id, cached, state.Name(), ret))
	}

	uh.transport.Yield(pc)
	return ret, nil
}

// For health check we send to . IN NS +norec message to the upstream.
// Dial timeouts and empty replies are considered fails
//
//	basically anything else constitutes a healthy upstream.
func (uh *UpstreamHost) Check() error {
	if err, rtt := uh.send(); err != nil {
		HealthCheckFailureCount.WithLabelValues(uh.Name()).Inc()
		atomic.AddInt32(&uh.fails, 1)
		log.Warningf("hc: DNS %v failed  rtt: %v err: %v", uh.Name(), rtt, err)
		return err
	} else {
		// Reset failure counter once health check success
		atomic.StoreInt32(&uh.fails, 0)
		return nil
	}
}

func (uh *UpstreamHost) send() (error, time.Duration) {
	if uh.IsDOH() {
		return uh.dohSend()
	}
	return uh.udpWireFormatSend()
}

func (uh *UpstreamHost) dohSend() (error, time.Duration) {
	req := &dns.Msg{}
	req.SetQuestion(".", dns.TypeNS)
	req.MsgHdr.RecursionDesired = uh.transport.recursionDesired
	state := &request.Request{Req: req}
	t := time.Now()
	msg, err := uh.dohExchange(context.Background(), state)
	rtt := time.Since(t)
	if err != nil && msg != nil {
		if msg.Response || msg.Opcode == dns.OpcodeQuery {
			log.Warningf("hc: Correct DNS %v malformed response  err: %v msg: %v", uh.Name(), err, msg)
			err = nil
		}
	}
	return err, rtt
}

func (uh *UpstreamHost) udpWireFormatSend() (error, time.Duration) {
	req := &dns.Msg{}
	req.SetQuestion(".", dns.TypeNS)
	req.MsgHdr.RecursionDesired = uh.transport.recursionDesired
	t := time.Now()

	var (
		msg *dns.Msg
		rtt time.Duration
		err error
	)
	if uh.transport.proxy != nil {
		msg, err = uh.proxyExchange(req)
		rtt = time.Since(t)
	} else {
		// rtt stands for Round Trip Time, it may 0 if Exchange() failed
		msg, rtt, err = uh.c.Exchange(req, uh.addr)
		if err != nil && rtt == 0 {
			rtt = time.Since(t)
		}
	}
	// If we got a header, we're alright, basically only care about I/O errors 'n stuff.
	if err != nil && msg != nil {
		// Silly check, something sane came back.
		if msg.Response || msg.Opcode == dns.OpcodeQuery {
			log.Warningf("hc: Correct DNS %v malformed response  err: %v msg: %v", uh.Name(), err, msg)
			err = nil
		}
	}
	return err, rtt
}

// proxyExchange sends a health check query over a fresh connection dialed
// through the configured SOCKS5 proxy.
func (uh *UpstreamHost) proxyExchange(req *dns.Msg) (*dns.Msg, error) {
	network := protoToNetwork(uh.proto)
	if network == "dns" {
		network = "udp"
	}
	conn, err := dialProxyConn(network, uh.addr, uh.transport.tlsConfig, uh.transport.dialTimeout(), uh.transport.proxy)
	if err != nil {
		return nil, err
	}
	defer Close(conn)

	_ = conn.SetWriteDeadline(time.Now().Add(maxWriteTimeout))
	if err := conn.WriteMsg(req); err != nil {
		return nil, err
	}
	_ = conn.SetReadDeadline(time.Now().Add(maxReadTimeout))
	return conn.ReadMsg()
}

// UpstreamHostPool is an array of upstream DNS servers
type UpstreamHostPool []*UpstreamHost

// Down checks whether the upstream host is down or not
// Down will try to use uh.downFunc first, and will fallback
//
//	to some default criteria if necessary.
func (uh *UpstreamHost) Down() bool {
	if uh.downFunc == nil {
		log.Warningf("Upstream host %v have no downFunc, fallback to default", uh.Name())
		return atomic.LoadInt32(&uh.fails) > 0
	}

	down := uh.downFunc(uh)
	if down {
		log.Debugf("%v marked as down...", uh.Name())
		HealthCheckAllDownCount.WithLabelValues(uh.Name()).Inc()
	}
	return down
}

type HealthCheck struct {
	wg   sync.WaitGroup // Wait until all running goroutines to stop
	stop chan struct{}  // Signal health check worker to stop

	hosts  UpstreamHostPool
	policy Policy
	spray  Policy

	// [PENDING]
	//failTimeout time.Duration	// Single health check timeout

	maxFails      int32         // Maximum fail count considered as down
	checkInterval time.Duration // Health check interval

	// A global transport since Caddy doesn't support over nested blocks
	transport *Transport
}

func (hc *HealthCheck) Start() {
	if hc.checkInterval != 0 {
		hc.wg.Add(1)
		go func() {
			defer hc.wg.Done()
			hc.healthCheckWorker()
		}()
	}

	for _, host := range hc.hosts {
		host.transport.Start()
	}
}

func (hc *HealthCheck) Stop() {
	close(hc.stop)
	hc.wg.Wait()

	for _, host := range hc.hosts {
		host.transport.Stop()
	}
}

func (hc *HealthCheck) healthCheck() {
	for _, host := range hc.hosts {
		go host.Check()
	}
}

func (hc *HealthCheck) healthCheckWorker() {
	// Kick off initial health check immediately
	hc.healthCheck()

	ticker := time.NewTicker(hc.checkInterval)
	for {
		select {
		case <-ticker.C:
			hc.healthCheck()
		case <-hc.stop:
			return
		}
	}
}

// Select an upstream host based on the policy and the health check result
// Taken from proxy/healthcheck/healthcheck.go with modification
func (hc *HealthCheck) Select() *UpstreamHost {
	pool := hc.hosts
	if len(pool) == 1 {
		if pool[0].Down() && hc.spray == nil {
			return nil
		}
		return pool[0]
	}

	allDown := true
	for _, host := range pool {
		if !host.Down() {
			allDown = false
			break
		}
	}
	if allDown {
		if hc.spray == nil {
			return nil
		}
		return hc.spray.Select(pool)
	}

	if hc.policy == nil {
		// Default policy is random
		h := (&Random{}).Select(pool)
		if h != nil {
			return h
		}
		if hc.spray == nil {
			return nil
		}
		return hc.spray.Select(pool)
	}

	h := hc.policy.Select(pool)
	if h != nil {
		return h
	}

	if hc.spray == nil {
		return nil
	}
	return hc.spray.Select(pool)
}

const (
	defaultConnExpire = 15 * time.Second
	minDialTimeout    = 1 * time.Second
	// Relatively short dial timeout, so we can retry with other upstreams
	maxDialTimeout      = 5 * time.Second
	cumulativeAvgWeight = 4

	maxWriteTimeout = 2 * time.Second
	maxReadTimeout  = 2 * time.Second
)
