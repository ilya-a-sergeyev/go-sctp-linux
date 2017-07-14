package net

import (
	"context"
	"syscall"
	"time"
)

// +build darwin freebsd

type SCTPConn struct {
	conn
	sim   syscall.SCTPInitMsg // SCTP is on the connection since it's used when the connection is established
	sinfo syscall.SCTPSndInfo
	rinfo *syscall.SCTPRcvInfo
}

func newSCTPConn(fd *netFD) *SCTPConn {
	sim := syscall.SCTPInitMsg{Num_ostreams: 100, Max_instreams: 100, Max_attempts: 0, Max_init_timeo: 0}
	sinfo := syscall.SCTPSndInfo{Sid: 0, Ppid: 0, Assoc_id: 0, Context: 0, Flags: 0}
	rinfo := syscall.SCTPRcvInfo{}
	c := &SCTPConn{conn{fd}, sim, sinfo, &rinfo}
	setSCTPInitMsg(c.fd, &c.sim)
	c.SetNoDelaySCTP(true)
	c.SetReceiveReceiveInfo(false)
	return c
}

func newSCTPConnInitMsg(fd *netFD, sim syscall.SCTPInitMsg) *SCTPConn {
	sinfo := syscall.SCTPSndInfo{Sid: 0, Ppid: 0, Assoc_id: 0, Context: 0, Flags: 0}
	rinfo := syscall.SCTPRcvInfo{}
	c := &SCTPConn{conn{fd}, sim, sinfo, &rinfo}
	setSCTPInitMsg(c.fd, &c.sim)
	c.SetNoDelaySCTP(true)
	c.SetReceiveReceiveInfo(false)
	return c
}

func (c *SCTPConn) SetSCTPInitMessage(sim syscall.SCTPInitMsg) error {
	if !c.ok() {
		return syscall.EINVAL
	}
	return setSCTPInitMsg(c.fd, &c.sim)
}

func (c *SCTPConn) SetNumOStreams(n uint16) error {
	if !c.ok() {
		return syscall.EINVAL
	}
	c.sim.Num_ostreams = n
	return setSCTPInitMsg(c.fd, &c.sim)
}

func (c *SCTPConn) SetMaxInStreams(n uint16) error {
	if !c.ok() {
		return syscall.EINVAL
	}
	c.sim.Max_instreams = n
	return setSCTPInitMsg(c.fd, &c.sim)
}

func (c *SCTPConn) SetMaxAttempts(n uint16) error {
	if !c.ok() {
		return syscall.EINVAL
	}
	c.sim.Max_attempts = n
	return setSCTPInitMsg(c.fd, &c.sim)
}

func (c *SCTPConn) SetMaxInitTimeout(n uint16) error {
	if !c.ok() {
		return syscall.EINVAL
	}
	c.sim.Max_init_timeo = n
	return setSCTPInitMsg(c.fd, &c.sim)
}

func (c *SCTPConn) SetNoDelaySCTP(noDelay bool) error {
	if !c.ok() {
		return syscall.EINVAL
	}
	return setNoDelaySCTP(c.fd, noDelay)
}

func (c *SCTPConn) SetReceiveReceiveInfo(b bool) error {
	if !c.ok() {
		return syscall.EINVAL
	}
	return setReceiveReceiveInfo(c.fd, b)
}

//
// set syscall.SCTPSndInfo values
//

func (c *SCTPConn) SetSid(sid uint16) error {
	if !c.ok() {
		return syscall.EINVAL
	}
	c.sinfo.Sid = sid
	return nil
}

func (c *SCTPConn) Flags(flags uint16) error {
	if !c.ok() {
		return syscall.EINVAL
	}
	c.sinfo.Flags = flags
	return nil
}

func (c *SCTPConn) SetPpid(ppid uint32) error {
	if !c.ok() {
		return syscall.EINVAL
	}
	c.sinfo.Ppid = ppid
	return nil
}

func (c *SCTPConn) SetContext(context uint32) error {
	if !c.ok() {
		return syscall.EINVAL
	}
	c.sinfo.Context = context
	return nil
}

func (c *SCTPConn) SetAssocId(assocId uint32) error {
	if !c.ok() {
		return syscall.EINVAL
	}
	c.sinfo.Assoc_id = assocId
	return nil
}

// SCTPAddr represents the address of a SCTP end point
type SCTPAddr struct {
	IP   IP
	Port int
	Zone string
}

func (a *SCTPAddr) family() int {
	if a == nil || len(a.IP) <= IPv4len {
		return syscall.AF_INET
	}
	if a.IP.To4() != nil {
		return syscall.AF_INET
	}
	return syscall.AF_INET6
}

func (a *SCTPAddr) opAddr() Addr {
	if a == nil {
		return nil
	}
	return a
}

func (a *SCTPAddr) Network() string { return "sctp" }

func (a *SCTPAddr) String() string {
	if a == nil {
		return "<nil>"
	}
	ip := ipEmptyString(a.IP)
	if a.Zone != "" {
		return JoinHostPort(ip+"%"+a.Zone, itoa(a.Port))
	}
	return JoinHostPort(ip, itoa(a.Port))
}

func (a *SCTPAddr) isWildcard() bool {
	if a == nil || a.IP == nil {
		return true
	}
	return a.IP.IsUnspecified()
}

func (a *SCTPAddr) toLocal(net string) sockaddr {
	return &SCTPAddr{loopbackIP(net), a.Port, a.Zone}
}

func DialSCTP(ctx context.Context, net string, laddr, raddr *SCTPAddr) (*SCTPConn, error) {
	switch net {
	case "sctp", "sctp4", "sctp6":
	default:
		return nil, &OpError{Op: "dial", Net: net, Source: laddr.opAddr(), Addr: raddr.opAddr(), Err: UnknownNetworkError(net)}
	}
	if raddr == nil {
		return nil, &OpError{Op: "dial", Net: net, Source: laddr.opAddr(), Addr: nil, Err: errMissingAddress}
	}
	return dialSCTP(ctx, net, laddr, raddr)
}

func dialSCTP(ctx context.Context, net string, laddr, raddr *SCTPAddr) (*SCTPConn, error) {
	// TODO syscall.SOCK_SEQPACKET can also be syscall.SOCK_STREAM
	fd, err := internetSocket(ctx, net, laddr, raddr, syscall.SOCK_SEQPACKET, 0, "dial")
	if err != nil {
		return nil, &OpError{Op: "dial", Net: net, Source: laddr.opAddr(), Addr: raddr.opAddr(), Err: err}
	}
	return newSCTPConn(fd), nil
}

func ResolveSCTPAddr(net, addr string) (*SCTPAddr, error) {
	switch net {
	case "sctp", "sctp4", "sctp6":
	case "":
		net = "sctp"
	default:
		return nil, UnknownNetworkError(net)
	}
	addrs, err := DefaultResolver.internetAddrList(context.Background(), net, addr)
	if err != nil {
		return nil, err
	}
	return addrs.first(isIPv4).(*SCTPAddr), nil
}

//
// Implement PacketConn interface
//

func (c *SCTPConn) ReadFrom(b []byte) (n int, addr Addr, err error) {
	if !c.ok() {
		return 0, nil, syscall.EINVAL
	}
	//	oobn int, flags int,
	n, _, _, addr, err = c.ReadFromSCTP(b)
	if err != nil {
		return
	}
	return
}

func (c *SCTPConn) ReadFromSCTP(b []byte) (n int, oobn int, flags int, addr *SCTPAddr, err error) {
	if !c.ok() {
		return 0, 0, 0, nil, syscall.EINVAL
	}
	var sa syscall.Sockaddr
	n, oobn, flags, sa, c.rinfo, err = c.fd.ReadFromSCTP(b)

	if err != nil {
		return
	}
	switch sa := sa.(type) {
	case *syscall.SockaddrInet4:
		addr = &SCTPAddr{IP: sa.Addr[0:], Port: sa.Port}
	case *syscall.SockaddrInet6:
		addr = &SCTPAddr{IP: sa.Addr[0:], Port: sa.Port, Zone: zoneToString(int(sa.ZoneId))}
	}
	return
}

func (c *SCTPConn) WriteTo(b []byte, addr Addr) (n int, err error) {
	if !c.ok() {
		return 0, syscall.EINVAL
	}
	a, ok := addr.(*SCTPAddr)
	if !ok {
		return 0, &OpError{Op: "write", Net: c.fd.net, Source: c.fd.laddr, Addr: addr, Err: syscall.EINVAL}
	}
	return c.WriteToSCTP(b, a)
}

func (c *SCTPConn) Close() error {
	return nil
}

func (c *SCTPConn) LocalAddr() Addr {
	return nil
}

func (c *SCTPConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *SCTPConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *SCTPConn) SetWriteDeadline(t time.Time) error {
	return nil
}

//
// SCTP specific implementations
//

func (a *SCTPAddr) sockaddr(family int) (syscall.Sockaddr, error) {
	if a == nil {
		return nil, nil
	}
	return ipToSockaddr(family, a.IP, a.Port, a.Zone)
}

func (c *SCTPConn) WriteToSCTP(b []byte, addr *SCTPAddr) (int, error) {
	if !c.ok() {
		return 0, syscall.EINVAL
	}
	if addr == nil {
		return 0, &OpError{Op: "write", Net: c.fd.net, Source: c.fd.laddr, Addr: nil, Err: errMissingAddress}
	}
	sa, err := addr.sockaddr(c.fd.family)
	if err != nil {
		return 0, &OpError{Op: "write", Net: c.fd.net, Source: c.fd.laddr, Addr: addr.opAddr(), Err: err}
	}
	n, err := c.fd.writeToSCTP(b, &c.sinfo, sa)
	if err != nil {
		err = &OpError{Op: "write", Net: c.fd.net, Source: c.fd.laddr, Addr: addr.opAddr(), Err: err}
	}
	return n, err
}

func ListenSCTP(network string, laddr *SCTPAddr) (*SCTPConn, error) {
	fd, err := internetSocket(context.Background(), network, laddr, nil, syscall.SOCK_SEQPACKET, syscall.IPPROTO_SCTP, "listen")
	if err != nil {
		return nil, err
	}
	return newSCTPConn(fd), nil
}

// Initialize with a specific SCTP Init message instead of defaults
func ListenSCTPInit(net string, laddr *SCTPAddr, sim syscall.SCTPInitMsg) (*SCTPConn, error) {
	switch net {
	case "sctp", "sctp4", "sctp6":
	default:
		return nil, &OpError{Op: "listen", Net: net, Source: nil, Addr: laddr.opAddr(), Err: UnknownNetworkError(net)}
	}
	if laddr == nil {
		laddr = &SCTPAddr{}
	}
	fd, err := internetSocket(context.Background(), net, laddr, nil, syscall.SOCK_SEQPACKET, 0, "listen")
	if err != nil {
		return nil, &OpError{Op: "listen", Net: net, Source: nil, Addr: laddr, Err: err}
	}
	return newSCTPConnInitMsg(fd, sim), nil
}

