// // Part 3: Build a Recursive Resolver
// //
// // Goal: resolve domain names without relying on a recursive resolver like
// // 8.8.8.8. Instead, start from a root nameserver and follow the referral
// // chain yourself until you find the answer.
// //
// // How iterative resolution works:
// //  1. Send a query to a root nameserver (pick one, e.g. "198.41.0.4").
// //  2. The root server won't know the answer, but will return NS records
// //     pointing to the TLD nameservers (e.g. ".com" servers).
// //  3. Query a TLD nameserver. It returns NS records pointing to the
// //     authoritative nameservers for the domain.
// //  4. Query an authoritative nameserver. It returns the A record (IP).
// //
// // At each step the response may contain:
// //   - An answer section with a TypeA record  → you're done, return the IP.
// //   - An additional section with a TypeA record for a nameserver → use that
// //     IP for the next query.
// //   - An authority section with a TypeNS record (nameserver hostname) but no
// //     glue IP → you must resolve the nameserver hostname first, then retry.
// //
// // Changes from Part 2:
// //   - buildQuery should now set flags=0 (no recursion desired).
// //   - parseRecord must handle TypeNS records: Data should be the nameserver
// //     domain name (decoded from wire format), not raw bytes.
// //
// // What to implement (you decide the types and structure):
// //   - sendQuery(ip, domain string, recordType int) – send a query to a
// //     specific nameserver IP and return the parsed packet.
// //   - getAnswer(pkt)      – return the IP from the first TypeA answer, or "".
// //   - getNameserverIP(pkt) – return the IP from the first TypeA additional, or "".
// //   - getNameserver(pkt)   – return the name from the first TypeNS authority, or "".
// //   - resolve(domain string, recordType int) string – the iterative resolver.

package dns

// import (
// 	"net"
// 	"testing"
// )

// // TestGetAnswer checks extraction of the first A-record IP from an answer section.
// func TestGetAnswer(t *testing.T) {
// 	// Minimal packet with one TypeA answer containing 1.2.3.4.
// 	raw := []byte{
// 		// Header: 0 questions, 1 answer
// 		0x00, 0x00,
// 		0x81, 0x80,
// 		0x00, 0x00, // NumQuestions
// 		0x00, 0x01, // NumAnswers
// 		0x00, 0x00,
// 		0x00, 0x00,
// 		// Answer record: name=\x00 (root), Type A, Class IN, TTL 60, Data 1.2.3.4
// 		0x00,                   // name: root (empty)
// 		0x00, 0x01,             // Type A
// 		0x00, 0x01,             // Class IN
// 		0x00, 0x00, 0x00, 0x3c, // TTL 60
// 		0x00, 0x04,             // RDLen 4
// 		1, 2, 3, 4,             // 1.2.3.4
// 	}

// 	pkt := parsePacket(raw)
// 	got := getAnswer(pkt)
// 	if got != "1.2.3.4" {
// 		t.Errorf("getAnswer: got %q, want \"1.2.3.4\"", got)
// 	}
// }

// // TestGetAnswerMissing checks that getAnswer returns "" when there are no A records.
// func TestGetAnswerMissing(t *testing.T) {
// 	// Packet with zero answers.
// 	raw := []byte{
// 		0x00, 0x00,
// 		0x81, 0x80,
// 		0x00, 0x00, // NumQuestions
// 		0x00, 0x00, // NumAnswers
// 		0x00, 0x00,
// 		0x00, 0x00,
// 	}

// 	pkt := parsePacket(raw)
// 	got := getAnswer(pkt)
// 	if got != "" {
// 		t.Errorf("getAnswer on empty packet: got %q, want \"\"", got)
// 	}
// }

// // TestResolve performs a live iterative resolution starting from a root server.
// //
// // resolve(domain, recordType) must NOT use 8.8.8.8 or any other recursive
// // resolver. It must walk the delegation chain itself.
// //
// // Root nameserver IP to start from: "198.41.0.4" (a.root-servers.net)
// func TestResolve(t *testing.T) {
// 	tests := []struct {
// 		domain string
// 	}{
// 		{"www.example.com"},
// 		{"www.recurse.com"},
// 	}

// 	for _, tt := range tests {
// 		ip := resolve(tt.domain, 1 /* TypeA */)
// 		if net.ParseIP(ip) == nil {
// 			t.Errorf("resolve(%q) = %q, not a valid IP", tt.domain, ip)
// 		}
// 		t.Logf("resolve(%q) = %s", tt.domain, ip)
// 	}
// }
