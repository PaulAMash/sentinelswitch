##! SentinelSwitch Zeek policy for the SPAN-fed sensor on SEC-TP01 (eth1).
##! Loaded from local.zeek on the sensor; the digital twin models the notices produced here.

@load base/frameworks/notice
@load policy/misc/scan
@load policy/protocols/conn/known-hosts
@load policy/protocols/conn/known-services
@load policy/protocols/ssl/known-certs
@load policy/frameworks/software/vulnerable
@load policy/frameworks/software/version-changes

@load ./sentinel-scan
@load ./sentinel-dns

redef Site::local_nets += {
    10.10.10.0/24, 10.20.0.0/24, 10.30.0.0/24, 10.40.0.0/24, 10.50.0.0/24, 10.99.0.0/24,
};

# Zeek writes JSON so the SentinelSwitch normalizer can consume it without a parser.
redef LogAscii::use_json = T;
