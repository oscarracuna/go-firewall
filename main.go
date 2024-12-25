package main

import (
	"fmt"
	"log"
	"os/exec"
	"strings"
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
	blockThreshold = 5               
	blockDuration  = 10 * time.Minute
)

func main() {

	go unblockExpiredIPs() 
	capturePackets()
}

func capturePackets() {
	device := "enp8s0" //Change this with the name of your device 
	snapLen := int32(65535) 
	promiscuous := false    
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
	fmt.Println("Capturing packets...")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		processPacket(packet)
	}
}

func processPacket(packet gopacket.Packet) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	tcpLayer := packet.Layer(layers.LayerTypeTCP)

		if ipLayer != nil && tcpLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		tcp, _ := tcpLayer.(*layers.TCP)

		fmt.Printf("Source IP: %s, Destination IP: %s, Source Port: %d, Destination Port: %d\n",
			ip.SrcIP, ip.DstIP, tcp.SrcPort, tcp.DstPort)

		handleScan(ip.SrcIP.String())
	}
  /*if ipLayer != nil && tcpLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		tcp, _ := tcpLayer.(*layers.TCP)

    if tcp.SYN && !tcp.ACK {
			SrcIP := ip.SrcIP.String()
			DstIP := ip.DstIP.String()

				if !strings.HasPrefix(SrcIP, "192.168.") && !strings.HasPrefix(SrcIP, "10.") && !strings.HasPrefix(SrcIP, "127.0.0.1") {
		    fmt.Printf("SYN Packet: SrcIP: %s, DstIP: %s, SrcPort: %d, DstPort: %d\n", ip.SrcIP, ip.DstIP, tcp.SrcPort, tcp.DstPort)
        fmt.Println(DstIP)
		    
      handleScan(ip.SrcIP.String())
      }
		}
	}*/
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
		fmt.Printf("Trying to block IP: %s...\n", ip)
		blockIP(ip)
	}
}

func blockIP(ip string) {
	if ip == "127.0.0.1" || strings.HasPrefix(ip, "192.168.") || strings.HasPrefix(ip, "10.") {
    fmt.Println("Skipping block for localhost/private IP.")
    return
  }


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

