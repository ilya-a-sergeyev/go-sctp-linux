// +build darwin freebsd linux

package net
import (
	"os"
	"syscall"
)

func setNoDelaySCTP(fd *netFD, noDelay bool) error {
	if err := fd.incref(); err != nil {
		return err
	}
	defer fd.decref()
	return os.NewSyscallError("setsockopt", syscall.SetsockoptInt(fd.sysfd, syscall.IPPROTO_SCTP, syscall.SCTP_NODELAY, boolint(noDelay)))
}

func setReceiveReceiveInfo(fd *netFD, info bool) error {
	if err := fd.incref(); err != nil {
		return err
	}
	defer fd.decref()
	return os.NewSyscallError("setsockopt", syscall.SetsockoptInt(fd.sysfd, syscall.IPPROTO_SCTP, syscall.SCTP_RECVRCVINFO, boolint(!info)))
}

func setSCTPInitMsg(fd *netFD, sim *syscall.SCTPInitMsg) error {
	if err := fd.incref(); err != nil {
		return err
	}
	defer fd.decref()
	err := syscall.SetsockoptSCTPInitMsg(fd.sysfd, syscall.IPPROTO_SCTP, syscall.SCTP_INITMSG, sim)

	if err != nil {
		return os.NewSyscallError("setsockopt", err)
	}
	return nil
}
