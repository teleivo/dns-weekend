// Part 2: Parse a DNS Response
//
// Goal: take raw bytes from a DNS response and extract the IP address.
//
// A DNS response has the same 12-byte header structure as a query, followed by:
//   - Question section   (one or more questions, same format as in the query)
//   - Answer section     (resource records)
//   - Authority section  (resource records)
//   - Additional section (resource records)
//
// Resource record wire format:
//   Name   – encoded domain name (may use compression pointers, see below)
//   Type   – 2 bytes
//   Class  – 2 bytes
//   TTL    – 4 bytes
//   RDLen  – 2 bytes (byte length of the following data field)
//   Data   – RDLen bytes
//
// DNS name compression: if the top 2 bits of a length byte are both 1 (i.e.
// the byte has 0xC0 set), the following byte forms a 14-bit offset into the
// original packet buffer where the full name continues. Your decoder must
// follow this pointer instead of reading a normal label.
//
// What to implement (you decide the types and structure):
//   - Parse a full DNS packet from raw []byte into whatever structure suits you.
//     The packet must expose: header counts, questions, answers, authorities,
//     and additionals.
//   - Decode a domain name from wire format, with compression pointer support.
//   - Convert a 4-byte IPv4 address to a dotted-decimal string.
//   - Send a query to 8.8.8.8:53 over UDP, parse the response, and return the
//     IP from the first A record. Call this function lookupDomain(domain string) string.

package dns

import (
	"net"
	"testing"
)

// TestDecodeNameSimple checks decoding of an uncompressed wire-format name.
// The input is the raw bytes of an encoded name as it appears in a DNS packet.
// decodeNameSimple returns the human-readable domain string and the number of
// bytes consumed (including the terminating null byte), so the caller can
// advance its read position past the name.
func TestDecodeNameSimple(t *testing.T) {
	tests := []struct {
		raw       []byte
		wantName  string
		wantBytes int
	}{
		{
			// \x06 google \x03 com \x00
			raw:       []byte{6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm', 0},
			wantName:  "google.com",
			wantBytes: 12,
		},
		{
			// \x03 www \x07 example \x03 com \x00
			raw:       []byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
			wantName:  "www.example.com",
			wantBytes: 17,
		},
		{
			// Name followed by trailing bytes that must not be consumed.
			// \x06 google \x03 com \x00 <extra bytes>
			raw:       []byte{6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm', 0, 0x00, 0x01, 0x00, 0x01},
			wantName:  "google.com",
			wantBytes: 12,
		},
	}

	for _, tt := range tests {
		gotName, gotBytes := decodeNameSimple(tt.raw)
		if gotName != tt.wantName {
			t.Errorf("decodeNameSimple name:\n got  %q\n want %q", gotName, tt.wantName)
		}
		if gotBytes != tt.wantBytes {
			t.Errorf("decodeNameSimple bytes read: got %d, want %d", gotBytes, tt.wantBytes)
		}
	}
}

// TestIPToString checks that a 4-byte slice becomes dotted-decimal notation.
func TestIPToString(t *testing.T) {
	tests := []struct {
		raw  []byte
		want string
	}{
		{[]byte{8, 8, 8, 8}, "8.8.8.8"},
		{[]byte{93, 184, 216, 34}, "93.184.216.34"},
		{[]byte{1, 2, 3, 4}, "1.2.3.4"},
	}
	for _, tt := range tests {
		got := ipToString(tt.raw)
		if got != tt.want {
			t.Errorf("ipToString(%v): got %q, want %q", tt.raw, got, tt.want)
		}
	}
}

// TestParsePacket checks that a real captured DNS response is parsed correctly.
//
// This is a raw UDP payload from a DNS response for "www.example.com" TypeA,
// as returned by 8.8.8.8. It contains one question, one answer, and uses
// name compression.
//
// Expectations:
//   - header: 1 question, 1 answer, 0 authorities, 0 additionals
//   - answer: Type=1 (A), Data decodes to "93.184.216.34"
//
// You must implement parsePacket(data []byte) that returns something your
// code can use to access these fields.
func TestParsePacket(t *testing.T) {
	// Real DNS response bytes (captured from 8.8.8.8 for www.example.com).
	raw := []byte{
		// Header
		0x00, 0x01, // ID
		0x81, 0x80, // Flags: response, recursion desired+available
		0x00, 0x01, // NumQuestions: 1
		0x00, 0x01, // NumAnswers: 1
		0x00, 0x00, // NumAuthorities: 0
		0x00, 0x00, // NumAdditionals: 0
		// Question: www.example.com, Type A, Class IN
		0x03, 'w', 'w', 'w',
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,       // end of name
		0x00, 0x01, // Type A
		0x00, 0x01, // Class IN
		// Answer: name compressed pointer → offset 12 (the question name)
		0xc0, 0x0c, // pointer to offset 12
		0x00, 0x01, // Type A
		0x00, 0x01, // Class IN
		0x00, 0x00, 0x0e, 0x10, // TTL: 3600
		0x00, 0x04, // RDLen: 4
		93, 184, 216, 34, // Data: 93.184.216.34
	}

	pkt := parsePacket(raw)

	// The packet must contain 1 question and 1 answer.
	if pkt.Header.NumQuestions != 1 {
		t.Errorf("NumQuestions: got %d, want 1", pkt.Header.NumQuestions)
	}
	if pkt.Header.NumAnswers != 1 {
		t.Errorf("NumAnswers: got %d, want 1", pkt.Header.NumAnswers)
	}
	if len(pkt.Answers) != 1 {
		t.Fatalf("len(answers): got %d, want 1", len(pkt.Answers))
	}

	ans := pkt.Answers[0]
	if ans.Type != 1 {
		t.Errorf("answer Type: got %d, want 1 (A)", ans.Type)
	}
	gotIP := ans.Content
	if gotIP != "93.184.216.34" {
		t.Errorf("answer IP: got %q, want \"93.184.216.34\"", gotIP)
	}
}

// TestLookupDomain performs a live DNS lookup via 8.8.8.8.
//
// Implement lookupDomain(domain string) string.
// It should: build a query (with recursion desired), send it over UDP to
// 8.8.8.8:53, parse the response, and return the IP from the first A record.
func TestLookupDomain(t *testing.T) {
	ip := lookupDomain("www.example.com")
	if net.ParseIP(ip) == nil {
		t.Errorf("lookupDomain returned %q, which is not a valid IP", ip)
	}
}
