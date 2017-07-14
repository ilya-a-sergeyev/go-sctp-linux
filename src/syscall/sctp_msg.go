// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package syscall

import "unsafe"


type SCTPSndInfo struct {
	Sid      uint16
	Flags    uint16
	Ppid     uint32
	Context  uint32
	Assoc_id uint32
}

type SCTPInitMsg struct {
	Num_ostreams   uint16
	Max_instreams  uint16
	Max_attempts   uint16
	Max_init_timeo uint16
}

type SCTPRcvInfo struct {
	Sid       uint16
	Ssn       uint16
	Flags     uint16
	Pad_cgo_0 [2]byte
	Ppid      uint32
	Tsn       uint32
	Cumtsn    uint32
	Context   uint32
	Assoc_id  uint32
}

const (
	SizeofSCTPSndInfo      = 0x10
	SizeofSCTPInitMsg      = 0x8
	SizeofSCTPRcvInfo      = 0x1c
)

func SetsockoptSCTPInitMsg(fd, level, opt int, sinit *SCTPInitMsg) (err error) {
	return setsockopt(fd, level, opt, unsafe.Pointer(sinit), unsafe.Sizeof(*sinit))
}

func SCTPSendMsg(fd int, p []byte, sinfo *SCTPSndInfo, to Sockaddr, flags int) (length int, err error) {
	var ptr unsafe.Pointer
	var salen _Socklen
	if to != nil {
		var err error
		ptr, salen, err = to.sockaddr()
		if err != nil {
			return 0, err
		}
	}
	var msg Msghdr
	msg.Name = (*byte)(unsafe.Pointer(ptr))
	msg.Namelen = uint32(salen)
	var iov Iovec
	if len(p) > 0 {
		iov.Base = (*byte)(unsafe.Pointer(&p[0]))
		iov.SetLen(len(p))
	}
	var dummy byte
	if len(p) == 0 {
		iov.Base = &dummy
		iov.SetLen(1)
	}
	controlBuffer := make([]byte, SizeofCmsghdr+SizeofSCTPSndInfo)

	cdata := (controlBuffer[:])
	var cmsg *Cmsghdr
	cmsg = (*Cmsghdr)(unsafe.Pointer(&cdata[0]))
	cmsg.Level = IPPROTO_SCTP
	cmsg.Type = SCTP_SNDINFO
	cmsg.SetLen(CmsgLen(SizeofSCTPSndInfo))

	var bsinfo *SCTPSndInfo
	data := (controlBuffer[cmsgAlignOf(SizeofCmsghdr):])
	bsinfo = (*SCTPSndInfo)(unsafe.Pointer(&data[0]))
	bsinfo.Sid = sinfo.Sid

	msg.Control = (*byte)(unsafe.Pointer(&controlBuffer[0]))
	msg.SetControllen(len(controlBuffer))

	msg.Iov = &iov
	msg.Iovlen = 1
	if length, err = sendmsg(fd, &msg, flags); err != nil {
		return
	}
	return
}

func SCTPReceiveMessage(fd int, p []byte, flags int) (n int, oobn int, from Sockaddr, rinfo *SCTPRcvInfo, recvflags int, err error) {

	// Message header
	var msg Msghdr
	var rsa RawSockaddrAny
	msg.Name = (*byte)(unsafe.Pointer(&rsa))
	msg.Namelen = uint32(SizeofSockaddrAny)
	// Create struct for message
	var iov Iovec
	if len(p) > 0 {
		iov.Base = (*byte)(unsafe.Pointer(&p[0]))
		iov.SetLen(len(p))
	}
	msg.Iov = &iov
	msg.Iovlen = 1

	// Message control header
	var cmsg *Cmsghdr

	controlBuffer := make([]byte, SizeofCmsghdr+SizeofSCTPRcvInfo)
	cdata := (controlBuffer[:])
	cmsg = (*Cmsghdr)(unsafe.Pointer(&cdata[0]))
	msg.Control = (*byte)(unsafe.Pointer(&controlBuffer[0]))
	msg.SetControllen(len(controlBuffer))

	flags = 0
	if n, err = recvmsg(fd, &msg, flags); err != nil {
		return
	}
	oobn = int(msg.Controllen)
	recvflags = int(msg.Flags)

	if cmsg.Type == SCTP_RCVINFO {
		data := (controlBuffer[cmsgAlignOf(SizeofCmsghdr):])
		rinfo = (*SCTPRcvInfo)(unsafe.Pointer(&data[0]))
	}

	if err != nil {
		return
	}
	from, err = anyToSockaddr(&rsa)
	return
}

