package main

import (
	"fmt"
	"log"
	"os/exec"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var scanTracker = make(map[string]struct {
	count     int
	timestamp time.Time
})

const (
	blockThreshold = 5               // Number of SYN packets to trigger a block
	blockDuration  = 10 * time.Minute // Duration to block an IP
)

func main() {

	go unblockExpiredIPs() 
	capturePackets()
}

func capturePackets() {
	device := "eth0" // Replace with your actual network interface
	snapLen := int32(65535) // Maximum bytes to capture per packet
	promiscuous := false    // Don't capture packets not meant for the interface
	timeout := pcap.BlockForever

	handle, err := pcap.OpenLive(device, snapLen, promiscuous, timeout)
	if err != nil {
		log.Fatalf("Error opening device %s: %v", device, err)
	}
	defer handle.Close()

	filter := "tcp[tcpflags] & tcp-syn != 0"
	if err := handle.SetBPFFilter(filter); err != nil {
		log.Fatalf("Error setting BPF filter: %v", err)
	}
	fmt.Println("Capturing TCP SYN packets...")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		processPacket(packet) // Process each captured packet
	}
}

func processPacket(packet gopacket.Packet) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	tcpLayer := packet.Layer(layers.LayerTypeTCP)

	if ipLayer != nil && tcpLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		tcp, _ := tcpLayer.(*layers.TCP)

		fmt.Printf("SYN Packet: SrcIP: %s, DstIP: %s, SrcPort: %d, DstPort: %d\n",
			ip.SrcIP, ip.DstIP, tcp.SrcPort, tcp.DstPort)

		handleScan(ip.SrcIP.String())
	}
}

func handleScan(ip string) {
	currentTime := time.Now()

	if entry, exists := scanTracker[ip]; exists && currentTime.Sub(entry.timestamp) > blockDuration {
		scanTracker[ip] = struct {
			count     int
			timestamp time.Time
		}{count: 0, timestamp: time.Time{}}
	}

	scanTracker[ip] = struct {
		count     int
		timestamp time.Time
	}{
		count: scanTracker[ip].count + 1,
		timestamp: currentTime,
	}

	if scanTracker[ip].count > blockThreshold {
		fmt.Printf("Blocking IP: %s\n", ip)
		blockIP(ip)
	}
}

func blockIP(ip string) {
	cmd := exec.Command("sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP")
	err := cmd.Run()
	if err != nil {
		log.Printf("Error blocking IP %s: %v", ip, err)
	}
}

func unblockExpiredIPs() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		for ip, entry := range scanTracker {
			if now.Sub(entry.timestamp) > blockDuration {
				unblockIP(ip)
				delete(scanTracker, ip)
			}
		}
	}
}

func unblockIP(ip string) {
	cmd := exec.Command("sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP")
	err := cmd.Run()
	if err != nil {
		log.Printf("Error unblocking IP %s: %v", ip, err)
	}
}

