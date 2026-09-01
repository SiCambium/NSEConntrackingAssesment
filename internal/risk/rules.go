package risk

// wellKnownPorts is used by UNRECOGNIZED_APP_ON_UNUSUAL_PORT: a port
// outside this set with no DPI application tag is more likely to be
// something worth a second look than IANA-common traffic the device just
// didn't classify.
var wellKnownPorts = map[int]bool{
	20: true, 21: true, 22: true, 25: true, 53: true, 67: true, 68: true, 80: true,
	110: true, 123: true, 143: true, 443: true, 465: true, 587: true, 993: true, 995: true,
	3478: true, // STUN, common for VoIP/WebRTC (seen in real captures)
}

// legacyAdminPorts carry high risk on general LAN-to-WAN traffic: remote
// shell/admin protocols with no encryption or with a long CVE history.
var legacyAdminPorts = map[int]bool{
	23:  true,                       // telnet
	512: true, 513: true, 514: true, // rexec, rlogin, rsh
	111: true, // rpcbind
}

// cleartextPorts carry credentials or content in plaintext.
var cleartextPorts = map[int]bool{
	21:  true, // ftp
	23:  true, // telnet
	25:  true, // smtp (unencrypted submission)
	69:  true, // tftp
	110: true, // pop3
	143: true, // imap
}

const cleartextHTTPPort = 80

// HighVolumeThresholdBytes gates HIGH_VOLUME_FIRST_CONTACT.
const HighVolumeThresholdBytes = 50 * 1024 * 1024 // 50MB

// LongLivedThresholdSeconds gates LONG_LIVED_UNVERIFIED.
const LongLivedThresholdSeconds = 2 * 60 * 60 // 2h

// LowConfidenceSampleCount gates LOW_CONFIDENCE_SAMPLE.
const LowConfidenceSampleCount = 3
