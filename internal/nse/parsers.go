// Package nse parses the CLI output of Cambium NSE3000/NSE4000 firewalls.
//
// The ConntrackFlow/Summary shapes and the stripCLI/lastField helpers are
// ported from SiCambium/NSELocalSSH's internal/nse/parsers.go, which was
// built and verified against real device captures (see testdata/). Keeping
// the same field names and parsing approach here means this package stays
// trivially diffable against the upstream source if the CLI output format
// ever changes.
package nse

import (
	"regexp"
	"strconv"
	"strings"
)

var promptRE = regexp.MustCompile(`(?m)^[A-Za-z0-9._-]+\([^)]*\)#\s*$`)

// stripCLI removes the echoed command line and the trailing CLI prompt from
// raw SSH session output, leaving just the command's response body.
func stripCLI(raw, command string) string {
	text := strings.ReplaceAll(raw, "\r", "")
	if command != "" {
		trimmed := strings.TrimLeft(text, "\n")
		if strings.HasPrefix(strings.TrimSpace(trimmed), command) {
			if i := strings.Index(trimmed, "\n"); i >= 0 {
				text = trimmed[i+1:]
			} else {
				text = ""
			}
		}
	}
	text = promptRE.ReplaceAllString(text, "")
	return strings.Trim(text, "\n")
}

func lastField(line string) string {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return ""
	}
	return fields[len(fields)-1]
}

// ConntrackSummary is the parsed result of `service show conntrack`.
type ConntrackSummary struct {
	Limit int    `json:"limit"`
	Usage int    `json:"usage"`
	Flows int    `json:"flows"`
	NAT   int    `json:"nat"`
	Raw   string `json:"raw,omitempty"`
}

var conntrackFlowRe = regexp.MustCompile(`(\d+)\s+flow entries`)

// ParseConntrackSummary parses `service show conntrack` output.
func ParseConntrackSummary(raw string) ConntrackSummary {
	body := stripCLI(raw, "service show conntrack")
	out := ConntrackSummary{Raw: body}
	for _, line := range strings.Split(body, "\n") {
		s := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(s, "Total Conntrack Limit:"):
			out.Limit, _ = strconv.Atoi(lastField(s))
		case strings.HasPrefix(s, "Total Conntrack Usage:"):
			out.Usage, _ = strconv.Atoi(lastField(s))
		case strings.HasPrefix(s, "Total NAT Usage:"):
			out.NAT, _ = strconv.Atoi(lastField(s))
		}
		if m := conntrackFlowRe.FindStringSubmatch(s); len(m) == 2 {
			out.Flows, _ = strconv.Atoi(m[1])
		}
	}
	return out
}

// ConntrackFlow is one row of `show conntrack` output.
type ConntrackFlow struct {
	Protocol    string `json:"protocol"`
	TTL         string `json:"ttl"`
	OriginSrc   string `json:"origin_src"`
	OriginDst   string `json:"origin_dst"`
	SrcPort     string `json:"src_port"`
	DstPort     string `json:"dst_port"`
	TxPackets   int64  `json:"tx_packets"`
	TxBytes     int64  `json:"tx_bytes"`
	RxPackets   int64  `json:"rx_packets"`
	RxBytes     int64  `json:"rx_bytes"`
	NatedIP     string `json:"nated_ip,omitempty"`
	NatedPort   string `json:"nated_port,omitempty"`
	TCPState    string `json:"tcp_state,omitempty"`
	Direction   string `json:"direction,omitempty"`
	Application string `json:"application,omitempty"`
	HostName    string `json:"host_name,omitempty"`
}

// ParseConntrackFlows parses `show conntrack` output into individual flow rows.
func ParseConntrackFlows(raw string) []ConntrackFlow {
	var rows []ConntrackFlow
	for _, line := range strings.Split(stripCLI(raw, "show conntrack"), "\n") {
		s := strings.TrimSpace(line)
		if s == "" || strings.HasPrefix(s, "=") || strings.HasPrefix(s, "Connection") || strings.HasPrefix(s, "Protocol") {
			continue
		}
		parts := strings.Split(s, "|")
		if len(parts) < 15 {
			continue
		}
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}
		proto := strings.ToUpper(parts[0])
		if proto != "TCP" && proto != "UDP" && proto != "ICMP" && proto != "GRE" {
			continue
		}
		txp, _ := strconv.ParseInt(parts[6], 10, 64)
		txb, _ := strconv.ParseInt(parts[7], 10, 64)
		rxp, _ := strconv.ParseInt(parts[8], 10, 64)
		rxb, _ := strconv.ParseInt(parts[9], 10, 64)
		host := ""
		if len(parts) > 15 {
			host = strings.TrimSpace(strings.Join(parts[15:], " "))
		}
		natedPort := parts[11]
		if natedPort == "0" {
			natedPort = ""
		}
		state := parts[12]
		if state == "N/A" {
			state = ""
		}
		rows = append(rows, ConntrackFlow{
			Protocol: parts[0], TTL: parts[1], OriginSrc: parts[2], OriginDst: parts[3],
			SrcPort: parts[4], DstPort: parts[5], TxPackets: txp, TxBytes: txb,
			RxPackets: rxp, RxBytes: rxb, NatedIP: parts[10], NatedPort: natedPort,
			TCPState: state, Direction: parts[13], Application: parts[14], HostName: host,
		})
	}
	return rows
}
