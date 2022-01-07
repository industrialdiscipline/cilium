// SPDX-License-Identifier: Apache-2.0
// Copyright 2020-2021 Authors of Cilium

//go:build privileged_tests
// +build privileged_tests

package bpfprogtester

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/sirupsen/logrus"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// Generate an ICMP Error packet
func packetIn(packetOrig gopacket.SerializeBuffer) gopacket.SerializeBuffer {
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	packetIn := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(packetIn, options,
		&layers.Ethernet{
			SrcMAC:       net.HardwareAddr{1, 0, 0, 3, 0, 10},
			DstMAC:       net.HardwareAddr{1, 0, 0, 3, 0, 20},
			EthernetType: layers.EthernetTypeIPv4,
		},
		&layers.IPv4{
			Version: 4,
			// The router (0.0.0.0) is responding with an ICMP need to
			// Frag.
			SrcIP:    net.IP{0, 0, 0, 0},
			DstIP:    net.IP{3, 3, 3, 1},
			Protocol: layers.IPProtocolICMPv4,
		},
		&layers.ICMPv4{
			TypeCode: layers.CreateICMPv4TypeCode(
				layers.ICMPv4TypeDestinationUnreachable,
				layers.ICMPv4CodeFragmentationNeeded),
		},
		gopacket.Payload(packetOrig.Bytes()),
	)
	return packetIn
}

// Add in input an ICMP Error packet generated from an ICMP ECHO
// message sent by POD IP(1.1.1.1).
func testNAT4ICMPFragNeededICMP(spec *ebpf.Collection) error {
	prog := spec.Programs["test_nat4_icmp_frag_needed_icmp"]
	if prog == nil {
		return errors.New("did not find test_nat4_icmp_frag_needed program")
	}
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// Generate an embedded packet type ICMP from Host to Dest. It is
	// supposed that the packet have been NATed.
	packetOrig := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(packetOrig, options,
		&layers.IPv4{
			Version:  4,
			SrcIP:    net.IP{3, 3, 3, 1},
			DstIP:    net.IP{2, 2, 2, 1},
			Protocol: layers.IPProtocolICMPv4,
			IHL:      5,
		},
		&layers.ICMPv4{
			TypeCode: layers.CreateICMPv4TypeCode(
				layers.ICMPv4TypeEchoRequest,
				0),
			Id: 32768,
		})

	packetIn := packetIn(packetOrig)
	bpfRet, packetOut, err := prog.Test(packetIn.Bytes())
	if err != nil {
		return fmt.Errorf("test run failed: %v", err)
	}

	// Validating the output packet
	if err := assertICMPErrorOutputPacketv4(packetOut); err != nil {
		return err
	}

	if bpfRet != 0 { // CT_ACT_OK
		return errors.New("unexpected return value")
	}

	return nil
}

// Add in input an ICMP Error packet generated from a TCP packet
// message sent by POD IP(1.1.1.1).
func testNAT4ICMPFragNeededTCP(spec *ebpf.Collection) error {
	prog := spec.Programs["test_nat4_icmp_frag_needed_tcp"]
	if prog == nil {
		return errors.New("did not find test_nat4_icmp_frag_needed_tcp program")
	}

	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// Generate an embedded packet type TCP from Host to Dest. It is
	// supposed that the packet have been NATed.
	packetOrig := gopacket.NewSerializeBuffer()
	ip4 := &layers.IPv4{
		Version:  4,
		SrcIP:    net.IP{3, 3, 3, 1},
		DstIP:    net.IP{2, 2, 2, 1},
		Protocol: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{
		SrcPort: 32768,
		DstPort: 8080,
		SYN:     true,
	}
	tcp.SetNetworkLayerForChecksum(ip4)
	gopacket.SerializeLayers(packetOrig, options, ip4, tcp)

	packetIn := packetIn(packetOrig)
	bpfRet, packetOut, err := prog.Test(packetIn.Bytes())
	if err != nil {
		return fmt.Errorf("test run failed: %v", err)
	}

	// Validating the output packet
	if err := assertICMPErrorOutputPacketv4(packetOut); err != nil {
		return err
	}

	if bpfRet != 0 { // CT_ACT_OK
		return errors.New("unexpected return value")
	}

	return nil
}

// Add in input an ICMP Error packet generated from a UDP packet
// message sent by POD IP(1.1.1.1).
func testNAT4ICMPFragNeededUDP(spec *ebpf.Collection) error {
	prog := spec.Programs["test_nat4_icmp_frag_needed_udp"]
	if prog == nil {
		return errors.New("did not find test_nat4_icmp_frag_needed_udp program")
	}

	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// Generate an embedded packet type UDP from Host to Dest. It is
	// supposed that the packet have been NATed.
	packetOrig := gopacket.NewSerializeBuffer()
	ip4 := &layers.IPv4{
		Version:  4,
		SrcIP:    net.IP{3, 3, 3, 1},
		DstIP:    net.IP{2, 2, 2, 1},
		Protocol: layers.IPProtocolUDP,
	}

	udp := &layers.UDP{
		SrcPort: 32768,
		DstPort: 8080,
	}
	udp.SetNetworkLayerForChecksum(ip4)
	gopacket.SerializeLayers(packetOrig, options, ip4, udp)

	packetIn := packetIn(packetOrig)
	bpfRet, packetOut, err := prog.Test(packetIn.Bytes())
	if err != nil {
		return fmt.Errorf("test run failed: %v", err)
	}

	// Validating the output packet
	if err := assertICMPErrorOutputPacketv4(packetOut); err != nil {
		return err
	}

	if bpfRet != 0 { // CT_ACT_OK
		return errors.New("unexpected return value")
	}

	return nil
}

func assertICMPErrorOutputPacketv4(packetOut []byte) error {
	packet := gopacket.NewPacket(
		packetOut, layers.LayerTypeEthernet, gopacket.Default)

	// Validating IP headers
	iplayer := packet.Layer(layers.LayerTypeIPv4)
	if iplayer == nil {
		return fmt.Errorf("the output packet should have IP headers")
	}
	iphdr, _ := iplayer.(*layers.IPv4)
	if iphdr.Protocol != layers.IPProtocolICMPv4 {
		return fmt.Errorf("the protocol should be ICMPv4, returned %d",
			iphdr.Protocol)
	}
	if !iphdr.SrcIP.Equal(net.IP{0, 0, 0, 0}) {
		return fmt.Errorf(
			"the src ip should be of the networking equipement 0.0.0.0, returned %s",
			iphdr.SrcIP.String())
	}
	if !iphdr.DstIP.Equal(net.IP{1, 1, 1, 1}) {
		return fmt.Errorf("the dst ip should be of the Pod 1.1.1.1, returned %s",
			iphdr.DstIP.String())
	}

	// Validating ICMP headers
	icmplayer := packet.Layer(layers.LayerTypeICMPv4)
	if icmplayer == nil {
		return fmt.Errorf("the output packet should have ICMP headers")
	}
	icmphdr, _ := icmplayer.(*layers.ICMPv4)
	if icmphdr.TypeCode.Type() != layers.ICMPv4TypeDestinationUnreachable {
		return fmt.Errorf("the ICMP type should be DEST UNREACH, returned %d",
			icmphdr.TypeCode.Type())
	}
	if icmphdr.TypeCode.Code() != layers.ICMPv4CodeFragmentationNeeded {
		return fmt.Errorf("the ICMP code should be FRAG NEEDED, returned %d",
			icmphdr.TypeCode.Code())
	}

	// Validating embedded packet from ICMP Err.

	errpacket := gopacket.NewPacket(icmphdr.Payload, layers.LayerTypeIPv4, gopacket.Default)
	errlayer := errpacket.Layer(layers.LayerTypeIPv4)
	if errlayer == nil {
		return fmt.Errorf("the embedded packet should have IP headers")
	}

	// Validating IP headers
	erriphdr, _ := errlayer.(*layers.IPv4)
	if !erriphdr.SrcIP.Equal(net.IP{1, 1, 1, 1}) {
		return fmt.Errorf(
			"the src ip of embedded should be the Pod 1.1.1.1 , returned %s",
			erriphdr.SrcIP.String())
	}
	if !erriphdr.DstIP.Equal(net.IP{2, 2, 2, 1}) {
		return fmt.Errorf("the dst ip of embedded should be of the Dest 2.2.2.1, returned %s",
			erriphdr.DstIP.String())
	}

	// Validating ICMP
	switch erriphdr.Protocol {
	case layers.IPProtocolICMPv4:
		erricmplayer := errpacket.Layer(layers.LayerTypeICMPv4)
		if erricmplayer == nil {
			return fmt.Errorf("the embedded packet should have ICMP headers")
		}
		erricmphdr, _ := erricmplayer.(*layers.ICMPv4)
		if erricmphdr.TypeCode.Type() != layers.ICMPv4TypeEchoRequest {
			return fmt.Errorf("the embedded ICMP type should be ECHO, returned %d",
				erricmphdr.TypeCode.Type())
		}
		if erricmphdr.TypeCode.Code() != 0 {
			return fmt.Errorf("the ICMP code should be 0, returned %d",
				erricmphdr.TypeCode.Code())
		}
		if erricmphdr.Id != 123 {
			return fmt.Errorf("the ICMP ID should be 123, returned %d",
				erricmphdr.Id)
		}
		break
	case layers.IPProtocolUDP:
		errudplayer := errpacket.Layer(layers.LayerTypeUDP)
		if errudplayer == nil {
			return fmt.Errorf("the embedded packet should have UDP headers")
		}
		errudphdr, _ := errudplayer.(*layers.UDP)
		if errudphdr.SrcPort != 3030 {
			return fmt.Errorf("the embedded UDP source port should be 3030, returned %d",
				errudphdr.SrcPort)
		}
		if errudphdr.DstPort != 8080 {
			return fmt.Errorf("the embedded UDP dest port should be 8080, returned %d",
				errudphdr.DstPort)
		}
	case layers.IPProtocolTCP:
		errtcplayer := errpacket.Layer(layers.LayerTypeTCP)
		if errtcplayer == nil {
			return fmt.Errorf("the embedded packet should have TCP headers")
		}
		errtcphdr, _ := errtcplayer.(*layers.TCP)
		if errtcphdr.SrcPort != 3030 {
			return fmt.Errorf("the embedded TCP source port should be 3030, returned %d",
				errtcphdr.SrcPort)
		}
		if errtcphdr.DstPort != 8080 {
			return fmt.Errorf("the embedded TCP dest port should be 8080, returned %d",
				errtcphdr.DstPort)
		}

	default:
		fmt.Errorf("the embedded packet protocol should be ICMPv4, TCP or UDP, returned %d",
			erriphdr.Protocol)
	}

	return nil
}

func modifyMapSpecs(spec *ebpf.CollectionSpec) {
	for _, m := range spec.Maps {
		// Clear pinning flag on all Maps, keep this test self-contained.
		m.Pinning = 0

		// Drain Extra section of legacy bpf_elf_map definitions. The library
		// rejects any bytes left over in Extra on load.
		if m.Extra != nil {
			io.Copy(io.Discard, m.Extra)
		}
	}
}

// TestCt checks connection tracking
func TestCt(t *testing.T) {
	spec, err := ebpf.LoadCollectionSpec("../bpf_nat_tests.o")
	if err != nil {
		t.Fatalf("failed to load spec: %s", err)
	}

	modifyMapSpecs(spec)

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("failed to load collection: %s", err)
	}

	t.Run("ICMP4 Frag Needed ICMP", func(t *testing.T) {
		err := testNAT4ICMPFragNeededICMP(coll)
		if err != nil {
			t.Fatalf("test failed: %s", err)
		}
	})

	t.Run("ICMP4 Frag Needed TCP", func(t *testing.T) {
		err := testNAT4ICMPFragNeededTCP(coll)
		if err != nil {
			t.Fatalf("test failed: %s", err)
		}
	})

	t.Run("ICMP4 Frag Needed UDP", func(t *testing.T) {
		err := testNAT4ICMPFragNeededUDP(coll)
		if err != nil {
			t.Fatalf("test failed: %s", err)
		}
	})

}

func TestMain(m *testing.M) {
	if err := rlimit.RemoveMemlock(); err != nil {
		logrus.Fatalf("setrlimit: %v", err)
	}
	os.Exit(m.Run())
}
