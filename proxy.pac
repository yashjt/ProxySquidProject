function FindProxyForURL(url, host) {

    // === BYPASS PROXY (send DIRECT) ===

    // Localhost always direct
    if (isPlainHostName(host)) return "DIRECT";
    if (host === "localhost" || host === "127.0.0.1") return "DIRECT";

    // Internal/private IP ranges — direct (like a firewall "allow internal")
    if (isInNet(host, "10.0.0.0",     "255.0.0.0"))   return "DIRECT";
    if (isInNet(host, "172.16.0.0",   "255.240.0.0")) return "DIRECT";
    if (isInNet(host, "192.168.0.0",  "255.255.0.0")) return "DIRECT";

    // Trusted domains — bypass proxy entirely
    var directDomains = [
        "apple.com",
        "icloud.com",
        "northeastern.edu"
    ];
    for (var i = 0; i < directDomains.length; i++) {
        if (dnsDomainIs(host, "." + directDomains[i]) || host === directDomains[i]) {
            return "DIRECT";
        }
    }

    // === BLOCK LIST (send to Squid, which will deny) ===
    var blockedDomains = [
        "malicious-site.com",
        "ads.example.com",
        "tracking.io",
        "https://www.google.com/"
    ];
    for (var i = 0; i < blockedDomains.length; i++) {
        if (dnsDomainIs(host, "." + blockedDomains[i]) || host === blockedDomains[i]) {
            return "PROXY 127.0.0.1:3128";  // Squid ACL will DENY these
        }
    }

    // === DEFAULT — route everything else through Squid for logging/inspection ===
    return "PROXY 127.0.0.1:3128";
}