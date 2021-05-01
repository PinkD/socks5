package socks5

import (
	"fmt"
	"io"
	"net"
	"sync"
)

const BufferSize = 2048

//FIXME: insecure implementation of UDP server, anyone could send package here without authentication

/*
   +----+------+------+----------+----------+----------+
   |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
   +----+------+------+----------+----------+----------+
   | 2  |  1   |  1   | Variable |    2     | Variable |
   +----+------+------+----------+----------+----------+

  The fields in the UDP request header are:

       o  RSV  Reserved X'0000'
       o  FRAG    Current fragment number
       o  ATYP    address type of following addresses:
          o  IP V4 address: X'01'
          o  DOMAINNAME: X'03'
          o  IP V6 address: X'04'
       o  DST.ADDR       desired destination address
       o  DST.PORT       desired destination port
       o  DATA     user data
*/

// S5Request is used both as request and response
type S5Request struct {
	Reserve  [2]byte
	Frag     byte
	AddrType byte
	IPv4     *net.IPAddr
	IPv6     *net.IPAddr
	FQDN     string
	Port     uint16
	Data     []byte
}

func (r *S5Request) Size() int {
	// 0 reserved for ip
	l := 4 + 0 + 2 + len(r.Data)
	switch r.AddrType {
	case AddressIPv4:
		l += 4
	case AddressIPv6:
		l += 16
	case AddressDomainName:
		l += len(r.FQDN)
	}
	return l
}

func (r *S5Request) RemoteAddress() string {
	return fmt.Sprintf("%s:%d", r.Remote(), r.Port)
}

func (r *S5Request) Remote() string {
	switch r.AddrType {
	case AddressIPv4:
		return r.IPv4.String()
	case AddressIPv6:
		return r.IPv6.String()
	case AddressDomainName:
		return r.FQDN
	default:
		return ""
	}
}

func (r *S5Request) FromPacket(packet []byte) {
	offset := 0
	r.Reserve = [2]byte{packet[0], packet[1]}
	offset += 2
	r.Frag = packet[2]
	offset++
	r.AddrType = packet[3]
	offset++
	switch r.AddrType {
	case AddressIPv4:
		r.IPv4 = new(net.IPAddr)
		r.IPv4.IP = packet[offset : offset+4]
		offset += 4
	case AddressIPv6:
		r.IPv6 = new(net.IPAddr)
		r.IPv6.IP = packet[offset : offset+16]
		offset += 16
	case AddressDomainName:
		addrLen := int(packet[offset])
		offset++
		r.FQDN = string(packet[offset : offset+addrLen])
		offset += addrLen
	default:
		panic(fmt.Sprintf("bad address type %d", r.AddrType))
		return
	}
	r.Port = uint16(packet[offset])<<8 + uint16(packet[offset+1])
	offset += 2
	r.Data = packet[offset:]
}

func (r *S5Request) ToPacket() []byte {
	packet := make([]byte, 22+len(r.Data))
	offset := 0
	packet[0] = r.Reserve[0]
	packet[1] = r.Reserve[1]
	offset += 2
	packet[2] = r.Frag
	offset++
	packet[3] = r.AddrType
	offset++
	switch r.AddrType {
	case AddressIPv4:
		copy(packet[offset:offset+4], r.IPv4.IP)
		offset += 4
	case AddressIPv6:
		copy(packet[offset:offset+16], r.IPv6.IP)
		offset += 16
	case AddressDomainName:
		l := len(r.FQDN)
		packet[offset] = byte(l)
		offset++
		copy(packet[offset:offset+l], r.FQDN)
		offset += l
	}
	packet[offset] = byte(r.Port >> 8)
	packet[offset+1] = byte(r.Port & 0xFF)
	offset += 2
	copy(packet[offset:], r.Data)
	// cut extra
	return packet[:offset+len(r.Data)]
}

func S5RequestFromPacket(packet []byte) *S5Request {
	r := &S5Request{}
	r.FromPacket(packet)
	return r
}

type UDPRequest struct {
	Address *net.UDPAddr
	Request *S5Request
}

var l sync.RWMutex
var connMap map[string]*UDPRequest
var conn *net.UDPConn

func (s *Server) handleUDP(udpConn *net.UDPConn) {
	connMap = make(map[string]*UDPRequest)

	localAddr := &net.UDPAddr{IP: net.IPv4zero, Port: 0}
	c, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		s.config.Logger.Printf("failed to listen udp: %s", err)
		return
	}
	conn = c

	go s.serveLocalConnection(udpConn)
	go s.serveRequest(udpConn)
}

// map[conn]map[remoteAddr]*UDPRequest
// var connMap sync.Map

func (s *Server) serveLocalConnection(udpConn *net.UDPConn) {
	go func() {
		for {
			buffer := make([]byte, BufferSize)
			n, addr, err := conn.ReadFromUDP(buffer)
			if err != nil {
				s.config.Logger.Printf("failed to receive udp from %s: %s", addr, err)
				return
			}
			s.config.Logger.Printf("receive data from remote: %s", addr)
			buffer = buffer[:n]
			l.RLock()
			r, ok := connMap[addr.String()]
			l.RUnlock()
			if !ok {
				s.config.Logger.Printf("no client connection for packet from %s", addr)
				continue
			}
			r.Request.Data = buffer
			s.handleUDPResponse(udpConn, r)
		}
	}()
}

func (s *Server) serveRequest(udpConn *net.UDPConn) {
	for {
		buffer := make([]byte, BufferSize)
		n, src, err := udpConn.ReadFromUDP(buffer)
		if err != nil {
			if err == io.EOF {
				continue
			}
			s.config.Logger.Printf("udp socks: Failed to accept udp traffic: %v", err)
		}

		s.config.Logger.Printf("accept udp: %s", src)

		buffer = buffer[:n]
		r := &UDPRequest{
			Address: src,
			Request: S5RequestFromPacket(buffer),
		}
		if r.Request.Frag != 0 {
			s.config.Logger.Printf("fragment is not supported yet, from %s", src)
			continue
		}
		s.handleUDPRequest(r)
	}
}

func (s *Server) handleUDPRequest(r *UDPRequest) {
	ra := r.Request.RemoteAddress()
	addr, err := net.ResolveUDPAddr("udp", ra)
	if err != nil {
		s.config.Logger.Printf("failed to resolve remote %s: %s", ra)
		return
	}
	s.config.Logger.Printf("send data to remote %s", addr)
	n, err := conn.WriteToUDP(r.Request.Data, addr)
	if err != nil {
		s.config.Logger.Printf("fail to send udp to %s: %s", ra, err)
		return
	}
	l.Lock()
	connMap[ra] = r
	l.Unlock()
	size := len(r.Request.Data)
	if n != size {
		s.config.Logger.Printf("send udp to %s: size %d mismatch %d", ra, n, size)
	}
}

func (s *Server) handleUDPResponse(conn *net.UDPConn, r *UDPRequest) {
	n, err := conn.WriteToUDP(r.Request.ToPacket(), r.Address)
	if err != nil {
		s.config.Logger.Printf("send response to %s: %s", r.Address, err)
	}
	s.config.Logger.Printf("send response to client: %s", r.Address)
	size := r.Request.Size()
	if n != size {
		s.config.Logger.Printf("send reply to %s: size mismatch, expected %d got %d", r.Address, size, n)
	}
}
