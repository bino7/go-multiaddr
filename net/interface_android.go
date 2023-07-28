package manet

import (
	"bytes"
	"net"
	"os"
	"syscall"
	"unsafe"
)

type ifReq [40]byte

func InterfaceAddrs() ([]net.Addr, error) {
	ifat, err := interfaceAddrTable(nil)
	if err != nil {
		err = &net.OpError{Op: "route", Net: "ip+net", Source: nil, Addr: nil, Err: err}
	}
	return ifat, err
}

func interfaceAddrTable(ifi *net.Interface) ([]net.Addr, error) {
	tab, err := syscall.NetlinkRIB(syscall.RTM_GETADDR, syscall.AF_UNSPEC)
	if err != nil {
		return nil, os.NewSyscallError("netlinkrib", err)
	}
	msgs, err := syscall.ParseNetlinkMessage(tab)
	if err != nil {
		return nil, os.NewSyscallError("parsenetlinkmessage", err)
	}
	var ift []net.Interface
	if ifi == nil {
		var err error
		ift, err = interfaceTableAndroid(0)
		if err != nil {
			return nil, err
		}
	}
	ifat, err := addrTable(ift, ifi, msgs)
	if err != nil {
		return nil, err
	}
	return ifat, nil
}

func newAddr(ifam *syscall.IfAddrmsg, attrs []syscall.NetlinkRouteAttr) net.Addr {
	var ipPointToPoint bool
	// Seems like we need to make sure whether the IP interface
	// stack consists of IP point-to-point numbered or unnumbered
	// addressing.
	for _, a := range attrs {
		if a.Attr.Type == syscall.IFA_LOCAL {
			ipPointToPoint = true
			break
		}
	}
	for _, a := range attrs {
		if ipPointToPoint && a.Attr.Type == syscall.IFA_ADDRESS {
			continue
		}
		switch ifam.Family {
		case syscall.AF_INET:
			return &net.IPNet{IP: net.IPv4(a.Value[0], a.Value[1], a.Value[2], a.Value[3]), Mask: net.CIDRMask(int(ifam.Prefixlen), 8*net.IPv4len)}
		case syscall.AF_INET6:
			ifa := &net.IPNet{IP: make(net.IP, net.IPv6len), Mask: net.CIDRMask(int(ifam.Prefixlen), 8*net.IPv6len)}
			copy(ifa.IP, a.Value[:])
			return ifa
		}
	}
	return nil
}

func addrTable(ift []net.Interface, ifi *net.Interface, msgs []syscall.NetlinkMessage) ([]net.Addr, error) {
	var ifat []net.Addr
loop:
	for _, m := range msgs {
		switch m.Header.Type {
		case syscall.NLMSG_DONE:
			break loop
		case syscall.RTM_NEWADDR:
			ifam := (*syscall.IfAddrmsg)(unsafe.Pointer(&m.Data[0]))
			if len(ift) != 0 || ifi.Index == int(ifam.Index) {
				if len(ift) != 0 {
					var err error
					ifi, err = interfaceByIndex(ift, int(ifam.Index))
					if err != nil {
						return nil, err
					}
				}
				attrs, err := syscall.ParseNetlinkRouteAttr(&m)
				if err != nil {
					return nil, os.NewSyscallError("parsenetlinkrouteattr", err)
				}
				ifa := newAddr(ifam, attrs)
				if ifa != nil {
					ifat = append(ifat, ifa)
				}
			}
		}
	}
	return ifat, nil
}

func interfaceByIndex(ift []net.Interface, index int) (*net.Interface, error) {
	for _, ifi := range ift {
		if index == ifi.Index {
			return &ifi, nil
		}
	}
	return nil, nil
}

// Starting from Android 11, it is no longer possible to retrieve network card information
// using the RTM_GETLINK method.
// As a result, alternative methods need to be employed.
// After considering the Android NetworkInterface.getNetworkInterfaces() method,
// I opted to utilize the RTM_GETADDR + ioctl approach to obtain network card information.
// However, it appears that retrieving the
// HWAddr (hardware address) of the network card is currently not achievable.
func interfaceTableAndroid(ifindex int) ([]net.Interface, error) {
	tab, err := syscall.NetlinkRIB(syscall.RTM_GETADDR, syscall.AF_UNSPEC)
	if err != nil {
		return nil, os.NewSyscallError("netlinkrib", err)
	}
	msgs, err := syscall.ParseNetlinkMessage(tab)
	if err != nil {
		return nil, os.NewSyscallError("parsenetlinkmessage", err)
	}

	var ift []net.Interface
	im := make(map[uint32]struct{})
loop:
	for _, m := range msgs {
		switch m.Header.Type {
		case syscall.NLMSG_DONE:
			break loop
		case syscall.RTM_NEWADDR:
			ifam := (*syscall.IfAddrmsg)(unsafe.Pointer(&m.Data[0]))
			if _, ok := im[ifam.Index]; ok {
				continue
			} else {
				im[ifam.Index] = struct{}{}
			}

			if ifindex == 0 || ifindex == int(ifam.Index) {
				ifi := newLinkAndroid(ifam)
				if ifi != nil {
					ift = append(ift, *ifi)
				}
				if ifindex == int(ifam.Index) {
					break loop
				}
			}
		}
	}

	return ift, nil
}

// According to the network card Index, get the Name, MTU and Flags of the network card through ioctl
func newLinkAndroid(ifam *syscall.IfAddrmsg) *net.Interface {
	ift := &net.Interface{Index: int(ifam.Index)}

	name, err := indexToName(ifam.Index)
	if err != nil {
		return nil
	}
	ift.Name = name

	mtu, err := nameToMTU(name)
	if err != nil {
		return nil
	}
	ift.MTU = mtu

	flags, err := nameToFlags(name)
	if err != nil {
		return nil
	}
	ift.Flags = flags
	return ift
}

func ioctl(fd int, req uint, arg unsafe.Pointer) error {
	_, _, e1 := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(arg))
	if e1 != 0 {
		return e1
	}
	return nil
}

func indexToName(index uint32) (string, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	defer syscall.Close(fd)

	var ifr ifReq
	*(*uint32)(unsafe.Pointer(&ifr[syscall.IFNAMSIZ])) = index
	err = ioctl(fd, syscall.SIOCGIFNAME, unsafe.Pointer(&ifr[0]))
	if err != nil {
		return "", err
	}

	return string(bytes.Trim(ifr[:syscall.IFNAMSIZ], "\x00")), nil
}

func nameToMTU(name string) (int, error) {
	// Leave room for terminating NULL byte.
	if len(name) >= syscall.IFNAMSIZ {
		return 0, syscall.EINVAL
	}

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	defer syscall.Close(fd)

	var ifr ifReq
	copy(ifr[:], name)
	err = ioctl(fd, syscall.SIOCGIFMTU, unsafe.Pointer(&ifr[0]))
	if err != nil {
		return 0, err
	}

	return int(*(*int32)(unsafe.Pointer(&ifr[syscall.IFNAMSIZ]))), nil
}

func nameToFlags(name string) (net.Flags, error) {
	// Leave room for terminating NULL byte.
	if len(name) >= syscall.IFNAMSIZ {
		return 0, syscall.EINVAL
	}

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	defer syscall.Close(fd)

	var ifr ifReq
	copy(ifr[:], name)
	err = ioctl(fd, syscall.SIOCGIFFLAGS, unsafe.Pointer(&ifr[0]))
	if err != nil {
		return 0, err
	}

	return linkFlags(*(*uint32)(unsafe.Pointer(&ifr[syscall.IFNAMSIZ]))), nil
}

func linkFlags(rawFlags uint32) net.Flags {
	var f net.Flags
	if rawFlags&syscall.IFF_UP != 0 {
		f |= net.FlagUp
	}
	if rawFlags&syscall.IFF_RUNNING != 0 {
		f |= net.FlagRunning
	}
	if rawFlags&syscall.IFF_BROADCAST != 0 {
		f |= net.FlagBroadcast
	}
	if rawFlags&syscall.IFF_LOOPBACK != 0 {
		f |= net.FlagLoopback
	}
	if rawFlags&syscall.IFF_POINTOPOINT != 0 {
		f |= net.FlagPointToPoint
	}
	if rawFlags&syscall.IFF_MULTICAST != 0 {
		f |= net.FlagMulticast
	}
	return f
}
