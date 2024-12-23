package main

import (
	"fmt"
	"log"
	"net"
  "time"
)

var (
  ip string
)

const BLOCK_TIME = 10 * time.Minute 


func main() {
  fmt.Println("owo")
}

func is_ip_blocked(string) bool{
  return true
}

func block_ip() {
  if is_ip_blocked(ip){
    log.Println("%s already blocked. Skipping...", ip)
  }
}

func unblock_ip() {

}
