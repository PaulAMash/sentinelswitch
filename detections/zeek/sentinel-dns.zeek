##! SentinelDNS: per-source DNS anomaly detection (query rate, NXDOMAIN ratio, DGA-like labels).

@load base/frameworks/notice
@load base/frameworks/sumstats
@load base/protocols/dns

module SentinelDNS;

export {
    redef enum Notice::Type += {
        ## A host issued an abnormal number of DNS queries with a high NXDOMAIN ratio.
        NXDomain_Burst,
        ## A host issued an abnormal number of DNS queries.
        High_Query_Rate,
    };

    const window = 1min &redef;
    const rate_threshold = 100.0 &redef;      # queries per window
    const nxdomain_threshold = 0.5 &redef;    # ratio of NXDOMAIN answers
    const min_nxdomain = 50.0 &redef;
}

# Crude entropy estimate for the first label, used to flag DGA-like names.
function label_entropy(name: string): double
    {
    local label = split_string(name, /\./)[0];
    if ( |label| < 8 ) return 0.0;
    local counts: table[string] of count;
    for ( c in label ) counts[c] = (c in counts) ? counts[c] + 1 : 1;
    local h = 0.0;
    for ( ch, n in counts )
        {
        local p = n / (|label| + 0.0);
        h -= p * (ln(p) / ln(2.0));
        }
    return h;
    }

event zeek_init()
    {
    local r_q = SumStats::Reducer($stream="sentinel.dns.query", $apply=set(SumStats::SUM, SumStats::UNIQUE));
    local r_nx = SumStats::Reducer($stream="sentinel.dns.nxdomain", $apply=set(SumStats::SUM));
    local r_dga = SumStats::Reducer($stream="sentinel.dns.dga", $apply=set(SumStats::SUM));
    SumStats::create([$name="sentinel-dns",
                      $epoch=window,
                      $reducers=set(r_q, r_nx, r_dga),
                      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                          {
                          local q = result["sentinel.dns.query"];
                          local nx = result["sentinel.dns.nxdomain"];
                          local dga = result["sentinel.dns.dga"];
                          if ( q$sum < rate_threshold ) return;
                          local ratio = nx$sum / q$sum;
                          local sub = fmt("queries_per_minute=%.0f nxdomain_ratio=%.2f unique_domains=%d dga_like=%s",
                                          q$sum / (interval_to_double(window) / 60.0), ratio, q$unique, dga$sum > 0.3 * q$sum ? "T" : "F");
                          if ( ratio >= nxdomain_threshold && nx$sum >= min_nxdomain )
                              NOTICE([$note=NXDomain_Burst, $src=key$host, $msg=fmt("%s DNS NXDOMAIN burst", key$host), $sub=sub, $identifier=cat(key$host)]);
                          else
                              NOTICE([$note=High_Query_Rate, $src=key$host, $msg=fmt("%s DNS query rate", key$host), $sub=sub, $identifier=cat(key$host)]);
                          }]);
    }

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
    {
    SumStats::observe("sentinel.dns.query", [$host=c$id$orig_h], [$str=query]);
    if ( label_entropy(query) > 3.4 )
        SumStats::observe("sentinel.dns.dga", [$host=c$id$orig_h], [$num=1]);
    }

event dns_message(c: connection, is_orig: bool, msg: dns_msg, len: count)
    {
    if ( ! is_orig && msg$rcode == 3 )
        SumStats::observe("sentinel.dns.nxdomain", [$host=c$id$resp_h], [$num=1]);
    }
