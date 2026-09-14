##! Scan thresholds tuned for a small lab segment. The default policy/misc/scan thresholds are too high
##! to fire on a /24 with ~30 hosts, so SentinelSwitch lowers them and shortens the interval.

@load policy/misc/scan

module SentinelScan;

redef Scan::addr_scan_interval = 2min;
redef Scan::port_scan_interval = 2min;
redef Scan::addr_scan_threshold = 15.0;   # distinct hosts on one port -> Scan::Address_Scan
redef Scan::port_scan_threshold = 100.0;  # distinct ports on one host -> Scan::Port_Scan

# Hosts allowed to scan: the authorized vulnerability scanner. Notices are still logged, but the
# SentinelSwitch correlation layer subtracts confidence for tagged assets.
const authorized_scanners: set[addr] = { 10.20.0.48 } &redef;

hook Notice::policy(n: Notice::Info)
    {
    if ( n$note == Scan::Port_Scan || n$note == Scan::Address_Scan )
        {
        if ( n?$src && n$src in authorized_scanners )
            add n$actions[Notice::ACTION_LOG];
        else
            add n$actions[Notice::ACTION_ALARM];
        }
    }
