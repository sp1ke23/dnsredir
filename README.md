# dnsredir

[![coredns-dnsredir auto build](https://github.com/leiless/dnsredir/actions/workflows/build.yml/badge.svg)](https://github.com/leiless/dnsredir/actions/workflows/build.yml)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-cc6600.svg)](release)
[![Corefile](https://img.shields.io/badge/try-Corefile-bb33ff)](https://git.io/JJZ3N)
[![License](https://img.shields.io/badge/license-Apache%202-blue)](LICENSE)

## Name

*dnsredir* - yet another seems better forward/proxy plugin for CoreDNS, mainly focused on speed and reliable.

*dnsredir* plugin works just like the *forward* plugin which re-uses already opened sockets to the upstreams. Currently, it supports `UDP`, `TCP`, `DNS-over-TLS`, and `DNS-over-HTTPS` and uses in continuous health checking.

Like the *proxy* plugin, it also supports multiple backends, which each upstream also supports multiple TLS server names. Load balancing features including multiple policies, health checks and failovers.

The health check works by sending `. IN NS` to upstream host. Any response that is not a network error(for example, `REFUSED`, `SERVFAIL`, etc.) is taken as a healthy upstream.

When all upstream hosts are down this plugin can opt fallback to randomly selecting an upstream host and sending the requests to it as last resort.

## Syntax

The phrase *redirect* and *forward* can be used interchangeably, unless explicitly stated otherwise.

In its most basic form, a simple DNS redirecter uses the following syntax:

```Corefile
dnsredir FROM... {
    to TO...
}
```

* `FROM...` is the file list which contains base domain to match for the request to be redirected. URL can also be used, currently only `HTTPS` is supported(due to security reasons).

    `.`(i.e. root zone) can be used solely to match all incoming requests as a fallback.

    Two kind of formats are supported currently:

    * `DOMAIN`, which the whole line is the domain name.

    * `server=/DOMAIN/...`, which is the format of `dnsmasq` config file, note that only the `DOMAIN` will be honored, other fields will be simply discarded.

    Text after `#` character will be treated as comment.

    Unparsable lines(including whitespace-only line) are therefore just ignored.

* `to TO...` are the destination endpoints to redirected to. This is a mandatory option.

    The `to` syntax allows you to specify a protocol, a port, etc:

    `[dns://]IP[:PORT]` use protocol specified in incoming DNS requests, it may `UDP` or `TCP`.

    `[udp://]IP:[:PORT]` use `UDP` protocol for DNS query, even if request comes in `TCP`.

    `[tcp://]IP:[:PORT]` use `TCP` protocol for DNS query, even if request comes in `UDP`.

    `tls://IP[:PORT][@TLS_SERVER_NAME]` for DNS over TLS, if you combine `:` and `@`, `@` must come last. Be aware of some DoT servers require TLS server name as a mandatory option.

    `json-doh://URL` use [JSON](https://developers.google.com/speed/public-dns/docs/doh/json) `DNS over HTTPS` for DNS query.

    `ietf-doh://URL` use IETF([RFC 8484](https://tools.ietf.org/html/rfc8484)) `DNS over HTTPS` for DNS query.

    `doh://URL` randomly choose JSON or IETF `DNS over HTTPS` for DNS query, make sure the upstream host support both of type.

    Example:

    ```
    dns://1.1.1.1
    8.8.8.8
    tcp://9.9.9.9
    udp://2606:4700:4700::1111

    tls://1.1.1.1@one.one.one.one
    tls://8.8.8.8
    tls://dns.quad9.net

    doh://cloudflare-dns.com/dns-query
    json-doh://1.1.1.1/dns-query
    json-doh://dns.google/resolve
    ietf-doh://dns.quad9.net/dns-query
    ```

An expanded syntax can be utilized to unleash of the power of `dnsredir` plugin:

```Corefile
dnsredir FROM... {
    path_reload DURATION
    url_reload DURATION [read_timeout]

    [INLINE]
    except IGNORED_NAME...

    spray
    policy random|round_robin|sequential
    health_check DURATION [no_rec]
    max_fails INTEGER

    to TO...
    expire DURATION
    tls CERT KEY CA
    tls_servername NAME
    bootstrap BOOTSTRAP...
    proxy SOCKS5_URL
    no_ipv6

    ipset SETNAME...
    pf [+OPTION...] NAME[:ANCHOR]...
}
```

Some of the options take a `DURATION` as argument, **zero time(i.e. `0`) duration to disable corresponding feature** unless it's explicitly stated otherwise. Valid time duration examples: `0`, `500ms`, `3s`, `1h`, `2h15m`, etc.

* `FROM...` and `to TO...` as above.

* `path_reload` changes the reload interval between each path in `FROM...`. Default is `2s`, minimal is `1s`.

* `url_reload` configure URL reload interval and read timeout:

    * `DURATION` specifies reload interval between each URL in `FROM...`. Default is `30m`, minimal is `15s`.

    * `[read_timeout]` optional argument to set URL read timeout. Default is `30s`, minimal is `3s`.

* `INLINE` are the domain names embedded in `Corefile`, they serve as supplementaries. Note that domain names in `FROM...` will still be read. `INLINE` is forbidden if you specify `.`(i.e. root zone) as `FROM...`.

    It usually not a good idea to embed too many `INLINE` domains in `Corefile`, in which case you should put them into a sole file, say, `user_custom.conf`.

* `except` is a space-separated list of domains to exclude from redirecting. Requests that match none of these names will be passed through.

    It usually not a good idea to embed too many `except` domains in `Corefile`, in which case you should try to delete them directly in `to` files.

* `spray` when all upstreams in `to` are marked as unhealthy, randomly pick one to send the traffic with. (Last resort, as a failsafe.)

* `policy` specifies the policy to use for selecting upstream hosts. The default is `random`.

    * `random` will randomly select a healthy upstream host.

    * `round_robin` will select a healthy upstream host in round robin order.

    * `sequential` will select a healthy upstream host in sequential order.

* `health_check` configure the behaviour of health checking of the upstream hosts:

     * `DURATION` specifies health checking interval. Default is `2s`, minimal is `1s`.

     * `[no_rec]` optional argument to set `RecursionDesired` flag to `false` for health checking. Default is `true`, i.e. recursion is desired.

* `max_fails` is the maximum number of consecutive health checking failures that are needed before considering an upstream as down. `0` to disable this feature(which the upstream will never be marked as down). Default is `3`.

* `expire` will expire (cached) connections after this time interval. Default is `15s`, minimal is `1s`.

* `tls CERT KEY CA` define the TLS properties for TLS connection. From 0 to 3 arguments can be specified:

    * `tls` - No client authentication is used, and the system CAs are used to verify the server certificate.

    * `tls CA` - No client authentication is used, and the CA file is used to verify the server certificate.

    * `tls CERT KEY` - Client authentication is used with the specified CERT/KEY pair. The server certificate is verified with the system CAs.

    * `tls CERT KEY CA` - Client authentication is used with the specified CERT/KEY pair. The server certificate is verified with the given CA file.

    Note that this TLS config is global for redirecting DNS requests.

* `tls_servername` specifies the global TLS server name used in the TLS configuration.

    For example, `cloudflare-dns.com` can be used for `1.1.1.1`(Cloudflare), and `quad9.net` can be used for `9.9.9.9`(Quad9).

    Note that this is a global name, it doesn't affect the TLS server names specified in `to TO...`.

* `bootstrap` specifies the bootstrap DNS servers(must be valid IP address) to resolve domain names in `to TO...`(if any).

* `proxy` dials the upstream connections through a `SOCKS5` proxy, the URL format is `socks5://[USER:PASSWORD@]HOST:PORT`(`socks5h://` is accepted as an alias). Both the host given in `to TO...` and the DoH request are sent to the proxy, so name resolution happens on the proxy side. All upstream transports are supported: `tcp://`/`tls://`/DoH go through `CONNECT`, while `udp://`(and `dns://` when the request arrives over UDP) uses `UDP ASSOCIATE` as defined by RFC 1928. Note that the proxy must implement `UDP ASSOCIATE` for the UDP case.

  Example:

  ```Corefile
  dnsredir /etc/dnsredir/foreign.lst {
      to tls://1.1.1.1@cloudflare-dns.com
      proxy socks5://127.0.0.1:1080
  }
  ```

* `no_ipv6` specifies don't try to resolve `IPv6` addresses for DNS exchange in `bootstrap`, in other words, use `IPv4` only.

* `ipset`(needs *root* user privilege) specifies resolved IP addresses from `FROM...` will be added to ipset `SETNAME...`.

    Note that only `IPv4`, `IPv6` protocol families are supported, and this option **only effective** on Linux.

    `SETNAME...` must be present, otherwise add IP will be failed.

* `pf`(needs *root* user privilege) specifies resolved IP addresses from `FROM...` will be added to the pf tables denoted by `NAME:[ANCHOR]...`

    The pf table name is a combo of name and anchor, if your table have a optional anchor, the anchor should follow the name by a colon(i.e. `:`).

    Optional options can be specified in the format: `+OPTION...`. Currently, supported options are:

    * `+create` - Create the given pf table if it does not exist.

    * `+v4_only` - Only add IPv4 addresses to the pf tables.

    * `+v6_only` - Only add IPv6 addresses to the pf tables.

    By default, IPv4 and IPv6 will all be added to the pf tables.

    Note that options should come before the pf tables.

    pf is generally available in BSD-derived systems, yet this sub-directive is **only effective** on macOS.

## Metrics

If monitoring is enabled (via the _prometheus_ plugin) then the following metrics are exported:

* `coredns_dnsredir_name_lookup_duration_ms{server, matched}` - duration per domain name lookup

* `coredns_dnsredir_request_duration_ms{server, to}` - duration per upstream interaction.

* `coredns_dnsredir_request_count_total{server, to}` - query count per upstream.

* `coredns_dnsredir_response_rcode_count_total{server, to, rcode}` - count of RCODEs per upstream.

* `coredns_dnsredir_hc_failure_count_total{to}` - number of failed health checks per upstream.

* `coredns_dnsredir_hc_all_down_count_total{to}` - counter of when all upstreams marked as down.

Where `server` is the _Server Block_ address responsible for the request(and metric). `matched` is the match flag, `"1"` is it's in any name list, `"0"` otherwise.

## Caveats

* To yield a maximum match performance, we search and return the first matched upstream, thus the block order between `dnsredir`s are important. Unlike the `proxy` plugin, which always try to find a longest match, i.e. position-independent search.

* Inappropriate URL read timeout will cause either failed to fetch URL content or _Server Block_ hijack(due to read timeout too large), thus DNS queries may fallback to other upstream servers, the answer may not optimal.

## Bugs

Sometimes you modified `Corefile` and yet Caddy server failed to reload the new config with the error "Error during parsing", *dnsredir* will do sanity check during parsing, if you misconfiged the `Corefile`, you're out of lock:

* Argument count mismatch, out of range arguments, unrecognizable arguments, etc.

* Missing mandatory property `to TO...`.

* Used unsupported DNS transport type in `to TO...`.

* `except` and `INLINE` share some same domain names(which yields a conflict).

* `.`(i.e. root zone) is matched yet `INLINE` also embedded in _Server Block_(still a conflict).

Also note that some of the properties are cumulative: `INLINE`, `except`, `to`, `ipset`, in which case `INLINE` domains should be put one domain per line.

Rationale: Strict checking to ensure that user can detect errors ASAP, and make the `Corefile` less confusing.

If you think you found a bug in `dnsredir`, please [issue a bug report](issues). Enhancements are also welcomed.

## Acknowledgments

Implementation and documentation of this plugin mainly inspired by [*forward*](https://coredns.io/plugins/forward/), [*proxy*](https://coredns.io/explugins/proxy/), [*hosts*](https://coredns.io/plugins/hosts/) plugin.

Part of the code inspired by [*m13253/dns-over-https*](https://github.com/m13253/dns-over-https), [*missdeer/ipset*](https://github.com/missdeer/ipset).

## Examples

Redirect all requests to Cloudflare DNS:

```Corefile
dnsredir . {
    to tls://1.1.1.1 tls://1.0.0.1
    tls_servername one.one.one.one

    # Or use domain name directly, which we don't need to specify TLS server name any more
    to tls://one.one.one.one
    # Bootstrap DNS server used to resolve one.one.one.one
    bootstrap 192.168.10.1
}
```

Redirect all requests to with different upstreams:

```Corefile
dnsredir . {
    # 1.1.1.1 uses the global TLS server name
    # 8.8.8.8 and 9.9.9.9 uses its own TLS server name
    to tls://1.1.1.1 tls://8.8.8.8@dns.google tls://9.9.9.9@quad9.net
    tls_servername cloudflare-dns.com
}
```

Redirect domains listed in file and fallback to Google DNS:

```Corefile
dnsredir accelerated-domains.china.conf {
    path_reload 3s
    max_fails 0
    to 114.114.114.114 223.5.5.5 udp://119.29.29.29
    policy round_robin

    # INLINE domain
    example.org
    example.net
}

dnsredir google.china.conf apple.china.conf {
    path_reload 10s
    to tls://dns.rubyfish.cn dns://101.6.6.6
    except adservice.google.com doubleclick.net
}

dnsredir . {
    to tls://8.8.8.8@8888.google tls://2001:4860:4860::64@dns.google
    policy sequential
    spray
}
```

Add resolved domain name IPs in list file to ipset `cn4` and `cn6`:

```Corefile
dnsredir user_custom.conf {
    to 192.168.10.1 192.168.20.1
    ipset cn4 cn6
}
```

[Sample Corefile for dnsredir plugin](https://gist.github.com/leiless/5fbdeafb69d56fe737ba639ded9ac124) contain a full-featured `Corefile`, although it mainly targets for China mainland users, you can also use it as a cross reference to write your own `Corefile`.

## LICENSE

*dnsredir* uses the same [LICENSE](LICENSE) as with [CoreDNS](https://github.com/coredns/coredns).

