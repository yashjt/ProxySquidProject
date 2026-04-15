function FindProxyForURL(url, host) {
    if (isPlainHostName(host)) return "DIRECT";
    if (host === "localhost" || host === "127.0.0.1") return "DIRECT";
    if (isInNet(host, "10.0.0.0",    "255.0.0.0"))   return "DIRECT";
    if (isInNet(host, "172.16.0.0",  "255.240.0.0")) return "DIRECT";
    if (isInNet(host, "192.168.0.0", "255.255.0.0")) return "DIRECT";
    return "PROXY 127.0.0.1:3128";
}