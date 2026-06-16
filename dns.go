package dns

import (
	"bytes"
	"encoding/binary"
	"math/rand/v2"
	"net"
	"net/netip"
	"strings"
)

type DNSHeader struct {
	Id             uint16
	Flags          uint16
	NumQuestions   uint16
	NumAnswers     uint16
	NumAuthorities uint16
	NumAdditionals uint16
}

type DNSQuery struct {
	Header    DNSHeader
	Questions []DNSQuestion
}

type DNSQuestion struct {
	Name  string
	Type  uint16
	Class uint16
}

type DNSAnswer struct {
	Name    string
	Type    uint16
	Class   uint16
	TTL     uint32
	RDLen   uint16
	Content string
}

type DNSResponse struct {
	Header    DNSHeader
	Questions []DNSQuestion
	Answers   []DNSAnswer
}

func NewQuery(addr string) DNSQuery {
	dnsQuestion := DNSQuestion{
		Name:  addr,
		Type:  1,
		Class: 1,
	}
	questions := []DNSQuestion{dnsQuestion}
	dnsHeader := DNSHeader{
		Id:           uint16(rand.UintN(65535)),
		Flags:        1 << 8,
		NumQuestions: uint16(len(questions)),
	}
	return DNSQuery{
		Header:    dnsHeader,
		Questions: questions,
	}
}

func buildQuery(addr string, recordType int) []byte {
	query := NewQuery(addr)
	var queryBuf []byte
	queryBuf, _ = binary.Append(queryBuf, binary.BigEndian, query.Header)

	for _, q := range query.Questions {
		queryBuf = append(queryBuf, encodeName(q.Name)...)
		queryBuf = binary.BigEndian.AppendUint16(queryBuf, q.Type)
		queryBuf = binary.BigEndian.AppendUint16(queryBuf, q.Class)
	}
	return queryBuf
}

func parsePacket(in []byte) DNSResponse {
	original := in
	var result DNSResponse
	var header DNSHeader
	if _, err := binary.Decode(in, binary.BigEndian, &header); err != nil {
		panic(err)
	}
	result.Header = header
	in = in[12:]

	questions := make([]DNSQuestion, header.NumQuestions)
	for i := range header.NumQuestions {
		name, offset := decodeNameSimple(in)
		questions[i].Name = name
		in = in[offset:]

		questions[i].Type = binary.BigEndian.Uint16(in)
		questions[i].Class = binary.BigEndian.Uint16(in[2:])

		in = in[4:]
	}

	answers := make([]DNSAnswer, header.NumAnswers)
	for i := range header.NumAnswers {
		// todo fix parsing answer name which can be a pointer
		// if next two bits are 1 then read 2 bytes as offset pointer pointing us back in in to get the domain name
		// if next two bits are 0 then call decodeNameSimple
		// name, offset := decodeNameSimple(in)
		// answers[i].Name = name
		if in[0]&0xC0 == 0xC0 {
			// It's a pointer - read the offset from the lower 14 bits
			offset := binary.BigEndian.Uint16(in[:2]) & 0x3FFF
			name, _ := decodeNameSimple(original[offset:])
			answers[i].Name = name
			in = in[2:] // pointer is always exactly 2 bytes
		} else {
			// It's a normal label sequence
			name, bytesRead := decodeNameSimple(in)
			answers[i].Name = name
			in = in[bytesRead:]
		}
		answers[i].Type = binary.BigEndian.Uint16(in)
		answers[i].Class = binary.BigEndian.Uint16(in[2:])
		answers[i].TTL = binary.BigEndian.Uint32(in[4:])
		answers[i].RDLen = binary.BigEndian.Uint16(in[8:])
		answers[i].Content = ipToString(in[10:])

		in = in[14:]
	}

	result.Questions = questions
	result.Answers = answers

	return result
}

func encodeName(addr string) []byte {
	var b bytes.Buffer
	s := strings.Split(addr, ".")
	for _, v := range s {
		b.WriteByte(byte(len(v)))
		b.WriteString(v)
	}
	b.WriteByte(0)
	return b.Bytes()
}

// []byte{len, char, char, char, len, char, char, ..., 0}
// []byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
func decodeNameSimple(rawResp []byte) (string, int) {
	var components []string
	i := 0
	for {
		length := int(rawResp[i])
		if length == 0 {
			i++
			break
		}
		components = append(components, string(rawResp[i+1:i+1+length]))
		i = i + length + 1
	}

	return strings.Join(components, "."), i
}

func ipToString(in []byte) string {
	return netip.AddrFrom4([4]byte(in)).String()
}

func lookupDomain(in string) string {
	query := NewQuery(in)

	var queryBuf []byte
	queryBuf, _ = binary.Append(queryBuf, binary.BigEndian, query.Header)
	for _, q := range query.Questions {
		queryBuf = append(queryBuf, encodeName(q.Name)...)
		queryBuf = binary.BigEndian.AppendUint16(queryBuf, q.Type)
		queryBuf = binary.BigEndian.AppendUint16(queryBuf, q.Class)
	}

	// we need to make a request via udp to a dns server like 8.8.8.8
	conn, err := net.Dial("tcp", "8.8.8.8")

	return ""
}
