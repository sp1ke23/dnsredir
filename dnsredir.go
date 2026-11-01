/*
 * Created Feb 16, 2020
 */

package dnsredir

import (
	"context"
	"errors"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/debug"
	"github.com/coredns/coredns/plugin/metrics"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
	"strconv"
	"sync/atomic"
	"time"
)

var log = clog.NewWithPlugin(pluginName)

type Dnsredir struct {
	Next plugin.Handler

	Upstreams *[]Upstream
}

// Upstream manages a pool of proxy upstream hosts
// see: github.com/coredns/proxy#proxy.go
type Upstream interface {
	// Check if given domain name should be routed to this upstream zone
	Match(name string) bool
	// Select an upstream host to be routed to, nil if no available host
	Select() *UpstreamHost

	// Exchanger returns the exchanger to be used for this upstream
	//Exchanger() interface{}
	// Send question to upstream host and await for response
	//Exchange(ctx context.Context, state request.Request) (*dns.Msg, error)

	Start() error
	Stop() error
}

func (r *Dnsredir) OnStartup() error {
	for _, up := range *r.Upstreams {
		if err := up.Start(); err != nil {
			return err
		}
	}
	return nil
}

func (r *Dnsredir) OnShutdown() error {
	for _, up := range *r.Upstreams {
		if err := up.Stop(); err != nil {
			return err
		}
	}
	return nil
}

func (r *Dnsredir) ServeDNS(ctx context.Context, w dns.ResponseWriter, req *dns.Msg) (int, error) {
	state := &request.Request{W: w, Req: req}
	name := state.Name()

	server := metrics.WithServer(ctx)
	upstream0, t := r.match(server, name)
	if upstream0 == nil {
		log.Debugf("%q not found in name list, t: %v", name, t)
		return plugin.NextOrFailure(r.Name(), r.Next, ctx, w, req)
	}
	upstream := upstream0.(*reloadableUpstream)
	log.Debugf("%q in name list, t: %v", name, t)

	var reply *dns.Msg
	var upstreamErr error
	var tryCount int32
	deadline := time.Now().Add(defaultTimeout)
	for time.Now().Before(deadline) {
		start := time.Now()

		tryCount++
		host := upstream.Select()
		if host == nil || tryCount > upstream.maxRetry {
			log.Debug(errNoHealthy)
			if upstream.serveFallback(ctx, w, state, server) {
				return dns.RcodeSuccess, nil
			}
			return dns.RcodeServerFailure, errNoHealthy
		}
		log.Debugf("Upstream host %v is selected", host.Name())

		for {
			t := time.Now()
			reply, upstreamErr = host.Exchange(ctx, state, upstream.bootstrap, upstream.noIPv6)
			log.Debugf("rtt: %v", time.Since(t))
			if upstreamErr == errCachedConnClosed {
				// [sic] Remote side closed conn, can only happen with TCP.
				// Retry for another connection
				log.Debugf("%v: %v", upstreamErr, host.Name())
				continue
			}
			break
		}

		if upstreamErr != nil {
			if upstream.maxFails != 0 {
				log.Warningf("Exchange() failed  error: %v", upstreamErr)
				healthCheck(upstream, host)
			}
			continue
		}

		if !state.Match(reply) {
			debug.Hexdumpf(reply, "Wrong reply  id: %v, qname: %v qtype: %v", reply.Id, state.QName(), state.QType())

			formerr := new(dns.Msg)
			formerr.SetRcode(state.Req, dns.RcodeFormatError)
			_ = w.WriteMsg(formerr)
			return dns.RcodeSuccess, nil
		}

		if reply.Rcode == dns.RcodeServerFailure && upstream.serveFallback(ctx, w, state, server) {
			return dns.RcodeSuccess, nil
		}

		// Add resolved IPs to ipset/pf before write response to DNS resolver
		// 	thus the rule based routing can take effect immediately
		ipsetAddIP(upstream, reply)
		pfAddIP(upstream, reply)
		_ = w.WriteMsg(reply)

		RequestDuration.WithLabelValues(server, host.Name()).Observe(float64(time.Since(start).Milliseconds()))
		RequestCount.WithLabelValues(server, host.Name()).Inc()

		rc, ok := dns.RcodeToString[reply.Rcode]
		if !ok {
			rc = strconv.Itoa(reply.Rcode)
		}
		RcodeCount.WithLabelValues(server, host.Name(), rc).Inc()
		return dns.RcodeSuccess, nil
	}

	if upstream.serveFallback(ctx, w, state, server) {
		return dns.RcodeSuccess, nil
	}
	if upstreamErr == nil {
		upstreamErr = errNoHealthy
	}
	return dns.RcodeServerFailure, upstreamErr
}

// serveFallback sends the request to the fallback upstreams when every regular
// upstream failed. Fallbacks always dial directly, so a dead proxy does not
// take them down, and DNS keeps working (possibly with polluted answers)
// instead of failing closed.
func (u *reloadableUpstream) serveFallback(ctx context.Context, w dns.ResponseWriter, state *request.Request, server string) bool {
	for _, host := range u.fallbackHosts {
		start := time.Now()
		reply, err := host.Exchange(ctx, state, u.bootstrap, u.noIPv6)
		if err != nil {
			log.Warningf("fallback %v failed: %v", host.Name(), err)
			continue
		}
		if !state.Match(reply) {
			log.Warningf("fallback %v returned a mismatched reply", host.Name())
			continue
		}
		ipsetAddIP(u, reply)
		pfAddIP(u, reply)
		if err := w.WriteMsg(reply); err != nil {
			log.Warningf("fallback %v: write failed: %v", host.Name(), err)
			continue
		}
		RequestDuration.WithLabelValues(server, host.Name()).Observe(float64(time.Since(start).Milliseconds()))
		RequestCount.WithLabelValues(server, host.Name()).Inc()
		rc, ok := dns.RcodeToString[reply.Rcode]
		if !ok {
			rc = strconv.Itoa(reply.Rcode)
		}
		RcodeCount.WithLabelValues(server, host.Name(), rc).Inc()
		return true
	}
	return false
}

func healthCheck(r *reloadableUpstream, uh *UpstreamHost) {
	// Skip unnecessary health checking
	if r.checkInterval == 0 || r.maxFails == 0 {
		return
	}

	failTimeout := defaultFailTimeout
	fails := atomic.AddInt32(&uh.fails, 1)
	go func(uh *UpstreamHost) {
		time.Sleep(failTimeout)
		// Failure count may go negative here, should be rectified by HC eventually
		atomic.AddInt32(&uh.fails, -1)
		// Kick off health check on every failureCheck failure
		if fails%failureCheck == 0 {
			_ = uh.Check()
		}
	}(uh)
}

func (r *Dnsredir) Name() string { return pluginName }

func (r *Dnsredir) match(server, name string) (Upstream, time.Duration) {
	t1 := time.Now()

	if r.Upstreams == nil {
		panic("Why Dnsredir.Upstreams is nil?!")
	}

	// Don't check validity of domain name, delegate to upstream host
	if len(name) > 1 {
		name = removeTrailingDot(name)
	}

	for _, up := range *r.Upstreams {
		// For maximum performance, we search the first matched item and return directly
		// Unlike proxy plugin, which try to find longest match
		if up.Match(name) {
			t2 := time.Since(t1)
			NameLookupDuration.WithLabelValues(server, "1").Observe(float64(t2.Milliseconds()))
			return up, t2
		}
	}

	t2 := time.Since(t1)
	NameLookupDuration.WithLabelValues(server, "0").Observe(float64(t2.Milliseconds()))
	return nil, t2
}

var (
	errNoHealthy        = errors.New("no healthy upstream host")
	errCachedConnClosed = errors.New("cached connection was closed by peer")
)

const (
	defaultTimeout     = 15 * time.Second
	defaultFailTimeout = 2000 * time.Millisecond
	failureCheck       = 3
)
