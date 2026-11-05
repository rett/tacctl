package conf

// BreakglassFirewallKey is the key of tacctl.yaml that says what the server
// does with the TCP connections of a held address: reject, drop or off
// (0.2.24, 'tacctl config breakglass-firewall'; internal/firewall).
const BreakglassFirewallKey = "breakglass.firewall"
