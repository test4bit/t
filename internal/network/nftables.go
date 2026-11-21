// File: internal/network/nftables.go
package network

import (
	"fmt"
	"log"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netlink"
)

// Use application-scoped table names to avoid destroying system firewall rules.
const (
	nftNatTable    = "vpn-runner-nat"
	nftFilterTable = "vpn-runner-filter"
)

func SetupNftablesInNetNS(nsFd int, outIface string) error {
	c, err := nftables.New(nftables.WithNetNSFd(nsFd))
	if err != nil {
		return fmt.Errorf("nftables handle: %w", err)
	}

	// Only manage our application-scoped tables, leave system tables untouched.
	c.DelTable(&nftables.Table{Family: nftables.TableFamilyIPv4, Name: nftNatTable})
	c.DelTable(&nftables.Table{Family: nftables.TableFamilyIPv4, Name: nftFilterTable})
	if err := c.Flush(); err != nil {
		log.Printf("warning: flush existing vpn-runner nftables tables: %v", err)
	}

	c, err = nftables.New(nftables.WithNetNSFd(nsFd))
	if err != nil {
		return fmt.Errorf("nftables handle after flush: %w", err)
	}

	nat := c.AddTable(&nftables.Table{Family: nftables.TableFamilyIPv4, Name: nftNatTable})
	post := c.AddChain(&nftables.Chain{
		Name:     "POSTROUTING",
		Table:    nat,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityNATSource,
	})
	c.AddRule(&nftables.Rule{
		Table: nat, Chain: post,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: append([]byte(outIface), 0)},
			&expr.Masq{},
		},
	})
	filter := c.AddTable(&nftables.Table{Family: nftables.TableFamilyIPv4, Name: nftFilterTable})
	forward := c.AddChain(&nftables.Chain{
		Name:     "FORWARD",
		Table:    filter,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityFilter,
	})
	c.AddRule(&nftables.Rule{
		Table: filter, Chain: forward,
		Exprs: []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}},
	})
	return c.Flush()
}

func SetupNftablesHost(outIface string) error {
	c, err := nftables.New()
	if err != nil {
		return fmt.Errorf("nftables handle: %w", err)
	}

	// Only delete our own application-scoped tables — never touch system "nat" or "filter".
	c.DelTable(&nftables.Table{Family: nftables.TableFamilyIPv4, Name: nftNatTable})
	c.DelTable(&nftables.Table{Family: nftables.TableFamilyIPv4, Name: nftFilterTable})
	if err := c.Flush(); err != nil {
		log.Printf("warning: flush existing vpn-runner nftables tables: %v", err)
	}

	c, err = nftables.New()
	if err != nil {
		return fmt.Errorf("nftables handle after flush: %w", err)
	}

	nat := c.AddTable(&nftables.Table{Family: nftables.TableFamilyIPv4, Name: nftNatTable})
	post := c.AddChain(&nftables.Chain{
		Name:     "POSTROUTING",
		Table:    nat,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityNATSource,
	})

	if outIface != "" {
		c.AddRule(&nftables.Rule{
			Table: nat, Chain: post,
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: append([]byte(outIface), 0)},
				&expr.Masq{},
			},
		})
	} else {
		c.AddRule(&nftables.Rule{
			Table: nat, Chain: post,
			Exprs: []expr.Any{&expr.Masq{}},
		})
	}

	filter := c.AddTable(&nftables.Table{Family: nftables.TableFamilyIPv4, Name: nftFilterTable})
	forward := c.AddChain(&nftables.Chain{
		Name:     "FORWARD",
		Table:    filter,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityFilter,
	})
	c.InsertRule(&nftables.Rule{
		Table: filter, Chain: forward,
		Exprs: []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}},
	})
	return c.Flush()
}

func GetDefaultOutboundInterface() (string, error) {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		return "", fmt.Errorf("list routes: %w", err)
	}
	for _, r := range routes {
		if r.Dst == nil || r.Dst.String() == "0.0.0.0/0" {
			if link, err := netlink.LinkByIndex(r.LinkIndex); err == nil {
				return link.Attrs().Name, nil
			}
		}
	}
	return "", fmt.Errorf("no default route found")
}
