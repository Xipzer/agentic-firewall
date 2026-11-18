package coverage

// ClassInfo is one entry of the attack universe (docs/attack-universe.md).
// See and Act state v0.1 coverage honestly: "yes", "partial" or "no".
type ClassInfo struct {
	Class, Family, See, Act string
}

var Taxonomy = []ClassInfo{
	{"recon.scan.vertical", "reconnaissance", "yes", "yes"},
	{"recon.scan.horizontal", "reconnaissance", "yes", "yes"},
	{"recon.scan.slow", "reconnaissance", "yes", "yes"},
	{"recon.fingerprint", "reconnaissance", "partial", "partial"},
	{"access.bruteforce", "initial access", "yes", "yes"},
	{"access.exploit", "initial access", "no", "no"},
	{"access.phishing", "initial access", "partial", "partial"},
	{"dos.syn-flood", "denial of service", "yes", "yes"},
	{"dos.connection-flood", "denial of service", "yes", "yes"},
	{"dos.flood", "denial of service", "yes", "yes"},
	{"dos.table-exhaustion", "denial of service", "yes", "yes"},
	{"dos.volumetric", "denial of service", "partial", "no"},
	{"dos.slow-application", "denial of service", "partial", "no"},
	{"infra.known-bad", "command and control", "yes", "yes"},
	{"c2.beacon", "command and control", "partial", "no"},
	{"c2.dns-tunnel", "command and control", "no", "no"},
	{"lateral.scan", "lateral movement", "yes", "partial"},
	{"lateral.bruteforce", "lateral movement", "yes", "partial"},
	{"lateral.link-spoof", "lateral movement", "no", "no"},
	{"exfil.volume", "exfiltration", "partial", "no"},
	{"exfil.covert", "exfiltration", "no", "no"},
	{"impact.ransomware-spread", "impact", "partial", "partial"},
	{"defence.manipulation", "attacks on the defence", "yes", "yes"},
	{"peer.reported", "peers", "yes", "partial"},
}
