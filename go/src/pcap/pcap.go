package main

// Use tcpdump to create a test file
// tcpdump -w test.pcap
// or use the example above for writing pcap files

import (
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	//pcapFile string = "/Volumes/SANDISK256/PCap_Data/2018-10-30.00.pcap"
	pcapFile string = "/Volumes/SANDISK256/PCap_Data/2018-10-30.00.pcap"
	handle   *pcap.Handle
	err      error
)

func main() {
	// Open file instead of device
	handle, err = pcap.OpenOffline(pcapFile)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Loop through packets in file
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	//var(i int = 0)
	for packet := range packetSource.Packets() {

		fmt.Println("======PACKET LAYERS======")
		for _, layer := range packet.Layers() {
			fmt.Println(layer.LayerType())
		}

		fmt.Println("=====================")

		//Get IPv4 Layer
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer != nil {
			fmt.Println("IPv4 Layer Detected.")
			ip, _ := ipLayer.(*layers.IPv4)

			//IP layer variables:
			//Version (Either 4 or 6)
			//IHL (IP Header Length in 32-bit words)
			//TOS, Length, ID, Flages, FragOffset, TTL, Protocol (TCP?, etc.),
			//Checksum, SrcIP, DstIP
			fmt.Printf("Source IP: %s\n", ip.SrcIP)
			fmt.Printf("Destin IP: %s\n", ip.DstIP)
			fmt.Printf("Protocol: %s\n", ip.Protocol)

			println()
		}

		//i += 1
		//if (i == 4) {break}
	}
}

/*
   PossibleOthers = Set<unique identifier>
   portscan, oneflow: map<(src, dest), map<port, #packs in that port> >
   networkscan: map<(ipsrc, portdest), map<ipdest, numpackets>>,
   backscatter: map<ipsrc, numpackets(*with checks)>
           checks: TCP: if flag is SA, A, R, RA
                   UDP: if port == 53, 123, 137, 161
                   ICMP: if (Type, code) = (0, 0), (11, 0) or Type == 3
   TCP packets need to check for "scanflagpktratio"

   Algorithm
   for each packet:
       create (ipsrc, ipdest), add to map
       create (ipsrc, destport) add to map
       add ipsrc to map (with checks)
   for each key in port map:
       check for conditions
       if no conditions match, add to "PossibleOthers"
   for each key in network map:
       repeat
   for each key backscatter map:
       repeat


   In each step we need to remove a packet from possibleOthers if it is classified
   then we should have only nonclassified packets (with exception of small syns and small udps...)
*/
