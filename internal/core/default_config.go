package core

// DefaultConfig is the profile written the first time a config directory
// has no config.yaml. Ports match Clash Verge Rev: mixed 7897, socks 7898,
// http 7899, external controller 127.0.0.1:9097. Traffic matches DIRECT.
const DefaultConfig = `# Clash Go default profile (Clash Verge Rev ports).
mixed-port: 7897
socks-port: 7898
port: 7899
allow-lan: false
mode: rule
log-level: info
ipv6: true
find-process-mode: off
unified-delay: true
geo-auto-update: false
profile:
  store-selected: true
tun:
  enable: false
dns:
  enable: false
proxies: []
rules:
  - MATCH,DIRECT
`
