package unixdiag

import (
	"encoding/binary"
	"testing"
)

// buildMsg assembles a unix_diag_msg + attributes the way the kernel
// lays them out.
func buildMsg(typ, state uint8, ino uint32, path []byte, peer uint32) []byte {
	le := binary.LittleEndian
	b := make([]byte, diagMsgLen)
	b[0] = 1 // AF_UNIX
	b[1] = typ
	b[2] = state
	le.PutUint32(b[4:], ino)

	attr := func(atype uint16, payload []byte) {
		hdr := make([]byte, 4)
		le.PutUint16(hdr, uint16(4+len(payload)))
		le.PutUint16(hdr[2:], atype)
		b = append(b, hdr...)
		b = append(b, payload...)
		for len(b)%4 != 0 {
			b = append(b, 0)
		}
	}
	if path != nil {
		attr(attrName, path)
	}
	if peer != 0 {
		p := make([]byte, 4)
		le.PutUint32(p, peer)
		attr(attrPeer, p)
	}
	return b
}

func TestParseMessageNamedListener(t *testing.T) {
	msg := buildMsg(TypeStream, StateListen, 4242, []byte("/var/run/docker.sock"), 0)
	s, err := ParseMessage(msg)
	if err != nil {
		t.Fatal(err)
	}
	if s.Inode != 4242 || s.Path != "/var/run/docker.sock" || s.PeerInode != 0 {
		t.Fatalf("parsed %+v", s)
	}
	if !s.Listening() {
		t.Fatal("stream listener not detected")
	}
}

func TestParseMessagePeeredPair(t *testing.T) {
	// The accepted server-side socket: named (inherits the listener's
	// path), peered to the client.
	srv, err := ParseMessage(buildMsg(TypeStream, StateEstablished, 100, []byte("/run/reports.sock\x00"), 200))
	if err != nil {
		t.Fatal(err)
	}
	if srv.Path != "/run/reports.sock" || srv.PeerInode != 200 {
		t.Fatalf("server side %+v", srv)
	}
	if srv.Listening() {
		t.Fatal("established socket wrongly listening")
	}

	// The client: unnamed, peered back.
	cli, err := ParseMessage(buildMsg(TypeStream, StateEstablished, 200, nil, 100))
	if err != nil {
		t.Fatal(err)
	}
	if cli.Path != "" || cli.PeerInode != 100 {
		t.Fatalf("client side %+v", cli)
	}
}

func TestParseMessageAbstract(t *testing.T) {
	s, err := ParseMessage(buildMsg(TypeStream, StateListen, 7, []byte("\x00dbus-session"), 0))
	if err != nil {
		t.Fatal(err)
	}
	if s.Path != "@dbus-session" {
		t.Fatalf("abstract path = %q", s.Path)
	}
}

func TestParseMessageDgram(t *testing.T) {
	named := buildMsg(TypeDgram, 7, 55, []byte("/run/systemd/notify"), 0)
	s, _ := ParseMessage(named)
	if !s.Listening() {
		t.Fatal("named dgram socket should count as a receiver")
	}
	unnamed := buildMsg(TypeDgram, StateEstablished, 56, nil, 55)
	c, _ := ParseMessage(unnamed)
	if c.Listening() || c.PeerInode != 55 {
		t.Fatalf("dgram client %+v", c)
	}
}

func TestParseMessageTruncated(t *testing.T) {
	if _, err := ParseMessage(make([]byte, 8)); err == nil {
		t.Fatal("short message must error")
	}
	// Corrupt attribute length must not panic or loop.
	msg := buildMsg(TypeStream, StateListen, 1, []byte("/x"), 0)
	msg[diagMsgLen] = 0xFF // absurd attr length
	if _, err := ParseMessage(msg); err != nil {
		t.Fatalf("corrupt attr should degrade, not error: %v", err)
	}
}
