package sniffer

import (
	"log"
	"syscall"
)

buf := make([]byte, 65535)
for {
  n,_, err := syscall.Recvfrom(fd, buf, 0)
  if err != nil {
    log.Printf("Error while reading the packet: %v", err)
    continue
  }
  processPacket(buf["n"])
}

func Sniffer() {
  fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(0x0800)))
  if err != nil {
    log.Fatalf("Error while opening socket: %v", err)
  }
}
