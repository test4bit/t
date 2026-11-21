// File: internal/network/netns.go
package network

import (
	"errors"
	"fmt"
	"log"
	"os"
	"runtime"
	"syscall"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"vpn-runner/internal/config"
)

func EnsureNetNS(name string) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	origns, err := netns.Get()
	if err != nil {
		return fmt.Errorf("get current netns: %w", err)
	}
	defer origns.Close()
	defer netns.Set(origns)

	existingNs, err := netns.GetFromName(name)
	if err == nil {
		existingNs.Close()
		return nil
	}

	newns, err := netns.NewNamed(name)
	if err != nil {
		return fmt.Errorf("create netns %s: %w", name, err)
	}
	defer newns.Close()

	nlHandle, err := netlink.NewHandleAt(newns)
	if err != nil {
		return fmt.Errorf("netlink handle at %s: %w", name, err)
	}
	defer nlHandle.Close()

	if lo, err := nlHandle.LinkByName("lo"); err == nil {
		if err := nlHandle.LinkSetUp(lo); err != nil {
			return fmt.Errorf("bring up lo in %s: %w", name, err)
		}
	}

	vethHost := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: config.VethHost},
		PeerName:  config.VethNS,
	}

	if err := netns.Set(origns); err != nil {
		return fmt.Errorf("switch to original ns: %w", err)
	}
	if err := netlink.LinkAdd(vethHost); err != nil {
		return fmt.Errorf("add veth link: %w", err)
	}

	if err := setupVethHost(); err != nil {
		return err
	}

	nsLinkTemp, err := netlink.LinkByName(config.VethNS)
	if err != nil {
		return fmt.Errorf("find veth peer %s: %w", config.VethNS, err)
	}
	if err := netlink.LinkSetNsFd(nsLinkTemp, int(newns)); err != nil {
		return fmt.Errorf("move %s to netns: %w", config.VethNS, err)
	}

	if err := netns.Set(newns); err != nil {
		return fmt.Errorf("switch to new ns: %w", err)
	}
	if err := setupVethNS(nlHandle); err != nil {
		return err
	}

	dir := fmt.Sprintf("/etc/netns/%s", name)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create netns config dir %s: %w", dir, err)
	}
	resolv := fmt.Sprintf("%s/resolv.conf", dir)
	dns := "nameserver 1.1.1.1\nnameserver 8.8.8.8\n"
	if err := os.WriteFile(resolv, []byte(dns), 0644); err != nil {
		return fmt.Errorf("write resolv.conf for %s: %w", name, err)
	}

	return nil
}

func setupVethHost() error {
	hostLink, err := netlink.LinkByName(config.VethHost)
	if err != nil {
		return fmt.Errorf("find %s: %w", config.VethHost, err)
	}
	hostAddr, err := netlink.ParseAddr(config.VethHostIP)
	if err != nil {
		return fmt.Errorf("parse host addr: %w", err)
	}
	if err := netlink.AddrAdd(hostLink, hostAddr); err != nil && !errors.Is(err, syscall.EEXIST) {
		return fmt.Errorf("add addr to %s: %w", config.VethHost, err)
	}
	if err := netlink.LinkSetUp(hostLink); err != nil {
		return fmt.Errorf("bring up %s: %w", config.VethHost, err)
	}
	return nil
}

func setupVethNS(nlHandle *netlink.Handle) error {
	nsLink, err := nlHandle.LinkByName(config.VethNS)
	if err != nil {
		return fmt.Errorf("find %s: %w", config.VethNS, err)
	}
	nsAddr, err := netlink.ParseAddr(config.VethNSIP)
	if err != nil {
		return fmt.Errorf("parse ns addr: %w", err)
	}
	if err := nlHandle.AddrAdd(nsLink, nsAddr); err != nil && !errors.Is(err, syscall.EEXIST) {
		return fmt.Errorf("add addr to %s: %w", config.VethNS, err)
	}
	if err := nlHandle.LinkSetUp(nsLink); err != nil {
		return fmt.Errorf("bring up %s: %w", config.VethNS, err)
	}
	return nil
}

func DeleteInterface(nsName, ifaceName string) {
	nsFd, err := netns.GetFromName(nsName)
	if err != nil {
		log.Printf("warning: get netns %s for cleanup: %v", nsName, err)
		return
	}
	defer nsFd.Close()

	nlHandle, err := netlink.NewHandleAt(nsFd)
	if err != nil {
		log.Printf("warning: netlink handle at %s: %v", nsName, err)
		return
	}
	defer nlHandle.Close()

	if link, err := nlHandle.LinkByName(ifaceName); err == nil {
		if err := nlHandle.LinkDel(link); err != nil {
			log.Printf("warning: delete link %s: %v", ifaceName, err)
		}
	}
}

func FullTeardown(name string) {
	if err := netns.DeleteNamed(name); err != nil {
		log.Printf("warning: delete netns %s: %v", name, err)
	}
	if link, err := netlink.LinkByName(config.VethHost); err == nil {
		if err := netlink.LinkDel(link); err != nil {
			log.Printf("warning: delete %s: %v", config.VethHost, err)
		}
	}
}
