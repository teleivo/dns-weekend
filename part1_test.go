// NOTE: https://datatracker.ietf.org/doc/html/rfc1035
// - DNS Wire format
//
// Part 1: Build a DNS Query
//
// Goal: construct a valid DNS query packet in binary wire format.
//
// DNS wire format overview:
//   - All multi-byte integers are big-endian.
//   - A message starts with a 12-byte header, followed by the question section.
//   - The header has 6 fields, each 2 bytes: ID, Flags, NumQuestions,
//     NumAnswers, NumAuthorities, NumAdditionals.
//   - The question section contains: encoded name, 2-byte Type, 2-byte Class.
//   - A domain name is encoded as a sequence of length-prefixed labels,
//     terminated by a zero byte. E.g. "google.com" →
//     \x06google\x03com\x00
//
// What to implement (you decide the types and structure):
//   - Encode a domain name into DNS wire format.
//   - Serialise a DNS header into 12 bytes.
//   - Serialise a DNS question into bytes.
//   - Build a complete query packet from a domain name and record type.
//
// Constants you will need:
//   TypeA   = 1
//   ClassIN = 1
//   FlagRecursionDesired = 1 << 8  (set this flag in Part 1 queries)

package dns

import (
	"encoding/binary"
	"testing"
)

// TestEncodeName checks that domain names are encoded into DNS wire format.
func TestEncodeName(t *testing.T) {
	tests := []struct {
		domain string
		want   []byte
	}{
		{
			domain: "google.com",
			// \x06 google \x03 com \x00
			want: []byte{6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm', 0},
		},
		{
			domain: "www.example.com",
			// \x03 www \x07 example \x03 com \x00
			want: []byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
		},
	}

	for _, tt := range tests {
		got := encodeName(tt.domain)
		if string(got) != string(tt.want) {
			t.Errorf("encodeName(%q)\n got  %v\n want %v", tt.domain, got, tt.want)
		}
	}
}

// TestBuildQuery checks that a full DNS query packet is correctly formed.
//
// We verify the packet structurally rather than against a fixed golden byte
// sequence (the ID is random), so we parse the fields back out.
func TestBuildQuery(t *testing.T) {
	pkt := buildQuery("www.example.com", 1 /* TypeA */)

	if len(pkt) < 12 {
		t.Fatalf("packet too short: %d bytes", len(pkt))
	}

	// Header fields (big-endian, 2 bytes each, at offsets 0–11).
	// ID (bytes 0–1): any non-zero value is fine (random).
	flags := binary.BigEndian.Uint16(pkt[2:4])
	numQuestions := binary.BigEndian.Uint16(pkt[4:6])
	numAnswers := binary.BigEndian.Uint16(pkt[6:8])
	numAuthorities := binary.BigEndian.Uint16(pkt[8:10])
	numAdditionals := binary.BigEndian.Uint16(pkt[10:12])

	// Recursion Desired flag must be set (bit 8).
	if flags&(1<<8) == 0 {
		t.Errorf("Flags: Recursion Desired bit not set, got flags=0x%04x", flags)
	}
	if numQuestions != 1 {
		t.Errorf("NumQuestions: got %d, want 1", numQuestions)
	}
	if numAnswers != 0 {
		t.Errorf("NumAnswers: got %d, want 0", numAnswers)
	}
	if numAuthorities != 0 {
		t.Errorf("NumAuthorities: got %d, want 0", numAuthorities)
	}
	if numAdditionals != 0 {
		t.Errorf("NumAdditionals: got %d, want 0", numAdditionals)
	}

	// Question section starts at byte 12.
	// Encoded name for "www.example.com":
	wantName := []byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	nameEnd := 12 + len(wantName)
	if len(pkt) < nameEnd+4 {
		t.Fatalf("packet too short to contain question section")
	}
	gotName := pkt[12:nameEnd]
	if string(gotName) != string(wantName) {
		t.Errorf("Question name\n got  %v\n want %v", gotName, wantName)
	}

	// Type and Class follow the name (2 bytes each).
	qType := binary.BigEndian.Uint16(pkt[nameEnd : nameEnd+2])
	qClass := binary.BigEndian.Uint16(pkt[nameEnd+2 : nameEnd+4])
	if qType != 1 {
		t.Errorf("Question Type: got %d, want 1 (TypeA)", qType)
	}
	if qClass != 1 {
		t.Errorf("Question Class: got %d, want 1 (ClassIN)", qClass)
	}
}
