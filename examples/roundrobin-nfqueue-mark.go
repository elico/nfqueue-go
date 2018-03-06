package main

/*
license note
Copyright (c) 2018, Eliezer Croitoru
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

import (
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/elico/nfqueue-go/nfqueue"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
)

var marksMax uint64
var logpkt bool
var logmark bool
var queueNum int

var counter = uint64(1)

func real_callback(payload *nfqueue.Payload) int {

	// Gather TCP packet data such as src and dst ip:port
	packet := gopacket.NewPacket(payload.Data, layers.LayerTypeIPv4, gopacket.Default)
	// Get the TCP layer from this packet
	dstIP := ""
	srcIP := ""

	for _, layer := range packet.Layers() {
		if layer.LayerType() == layers.LayerTypeIPv4 {
			ipv4 := layer.(*layers.IPv4)
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				// fmt.Println("This is a TCP packet!")
				// Get actual TCP data from this layer
				tcp, _ := tcpLayer.(*layers.TCP)
				dstIP = ipv4.DstIP.String() + ":" + fmt.Sprintf("%d", tcp.DstPort)
				srcIP = ipv4.SrcIP.String() + ":" + fmt.Sprintf("%d", tcp.SrcPort)
			}

		}

	}

	if logpkt {
		fmt.Println("Real callback")
		fmt.Printf("  id: %d\n", payload.Id)
		fmt.Printf("  mark: %d\n", payload.GetNFMark())
		fmt.Printf("  in  %d      out  %d\n", payload.GetInDev(), payload.GetOutDev())
		fmt.Printf("  Φin %d      Φout %d\n", payload.GetPhysInDev(), payload.GetPhysOutDev())
		fmt.Println(hex.Dump(payload.Data))
		fmt.Println("-- ")
		if len(dstIP) > 0 && len(srcIP) > 0 {
			fmt.Println("Src=>", srcIP, ", Dst=>", dstIP)
		}

		fmt.Println("-- ")

	}
	val := (atomic.AddUint64(&counter, 1) % marksMax) + 1
	if val == uint64(0) {
		val++
	}
	if logmark {
		if logpkt {
			fmt.Println("The selected Mark =>", val, "For packet =>", payload)
		} else {
			fmt.Println("The selected Mark =>", val)
		}
	}
	payload.SetVerdictMark(nfqueue.NF_REPEAT, uint32(val))
	// payload.SetVerdict(nfqueue.NF_ACCEPT)

	return 0
}

func main() {
	flag.BoolVar(&logpkt, "log-packet", false, "Log the packet to stdout (works with log-mark option only)")
	flag.BoolVar(&logmark, "log-mark", false, "Log the mark selection to stdout")

	flag.Uint64Var(&marksMax, "high-mark", uint64(3), "The number of the highest queue number")
	flag.IntVar(&queueNum, "queue-num", 0, "The NFQUEQUE number")

	flag.Parse()

	q := new(nfqueue.Queue)

	q.SetCallback(real_callback)

	q.Init()
	defer q.Close()

	q.Unbind(syscall.AF_INET)
	q.Bind(syscall.AF_INET)

	q.CreateQueue(queueNum)
	q.SetMode(nfqueue.NFQNL_COPY_PACKET)
	fmt.Println("The queue is active, add an iptables rule to use it, for example: ")
	fmt.Println("\tiptables -t mangle -I PREROUTING 1 [-i eth0] -m conntrack --ctstate NEW -j NFQUEUE --queue-num", queueNum)

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for sig := range c {
			// sig is a ^C, handle it
			_ = sig
			q.Close()
			os.Exit(0)
			// XXX we should break gracefully from loop
		}
	}()

	// XXX Drop privileges here

	// XXX this should be the loop
	q.TryRun()

}
