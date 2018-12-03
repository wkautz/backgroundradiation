package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
        //"github.com/fatih/set"
)

var (
	//pcapFile string = "/Volumes/SANDISK256/PCap_Data/2018-10-30.00.pcap"
	pcapFile string = "/Volumes/SANDISK256/PCap_Data/2018-10-30.00.pcap"
	handle   *pcap.Handle
	err      error
	count    int
)
/*
func stringifyNot(srcIP net.IP, dstIP net.IP, dPort uint16, ...) string {
        return string(srcIP) + ";" + string(dstIP) + ";" + string(dPort)
}
*/
func stringify(srcIP net.IP, dstIP net.IP, dPort uint16) string {
	return string(srcIP) + ";" + string(dstIP) + ";" + string(dPort)
}

func getSrcIP(packetInfo string) string {
	return strings.Split(packetInfo, ";")[0]
}

func getDstIP(packetInfo string) string {
	return strings.Split(packetInfo, ";")[1]
}

func getDPortIP(packetInfo string) string {
	return strings.Split(packetInfo, ";")[2]
}

var portMap map[string]map[uint16]int //Do we need another for UDP ports?
var netMap map[string]map[uint16]int
var backscatterMap map[uint16]int

/* ===================== Port Scans & One Flow ====================== */
func testPortScanTCP(srcIP net.IP, dstIP net.IP, dstPort layers.TCPPort, FIN bool, ACK bool) bool {

	count++
	//fmt.Printf("FIN: %t\n", FIN)
	//fmt.Printf("ACK: %t\n", ACK)

	if count%1000000 == 0 {
		fmt.Printf("%d packets\n", count)
	}
	if !FIN && !ACK {
		return false
	}
	packetInfo := stringify(srcIP, dstIP, 0)

	if portMap[packetInfo] == nil {
		m := make(map[uint16]int)
		m[uint16(dstPort)] = 1
		portMap[packetInfo] = m
	} else {
		portMap[packetInfo][uint16(dstPort)]++
	}
	return true
}
func testPortScanUDP(srcIP net.IP, dstIP net.IP, dstPort layers.TCPPort, FIN bool, ACK bool) bool {
	//any UDP checks would go here
	packetInfo := stringify(srcIP, dstIP, 0)
	portMap[packetInfo][uint16(dstPort)]++
	return true
}

func printPortScanStats() bool {
	fmt.Printf("Number of PossibleScanners: %d\n", len(portMap))
	for k, v := range portMap {
		fmt.Printf("SrcIP, DestIP Pair: (%s, %s)\n", getSrcIP(k), getDstIP(k)) //can we print this way?
		fmt.Printf("\t Has %d dPorts.\n", len(v))
		countPackets := 0
		for _, v1 := range v {
			countPackets += v1
		}
		fmt.Printf("\t and %d packets\n", countPackets)
	}
	return true
}

/* =================== Network Scans ==================== */
//pull out features of UDP and TCP packets
func testNetworkScanTCP(srcIP net.IP, dstIP net.IP, dstPort layers.TCPPort, FIN bool, ACK bool) bool {
	count++
	//fmt.Printf("FIN: %t\n", FIN)
	//fmt.Printf("ACK: %t\n", ACK)

	if count%1000000 == 0 {
		fmt.Printf("%d packets\n", count)
	}

	if !FIN && !ACK {
		//fmt.Println("NETWORK SCAN = FALSE")
		return false
	}
	//fmt.Println("NETWORK SCAN = TRUE")
	packetInfo := stringify(srcIP, nil, uint16(dstPort))
	if netMap[packetInfo] == nil {
		m := make(map[uint16]int)
		m[binary.LittleEndian.Uint16(dstIP)] = 1
		netMap[packetInfo] = m
	} else {
		netMap[packetInfo][binary.LittleEndian.Uint16(dstIP)]++
	}
	return true
}

func testNetworkScanUDP(srcIP net.IP, dstIP net.IP, dstPort layers.UDPPort) bool {
	packetInfo := stringify(srcIP, nil, uint16(dstPort))
	netMap[packetInfo][binary.LittleEndian.Uint16(dstIP)]++
	return true
}

func testNetworkScanICMP(srcIP net.IP, dstIP net.IP, dstPort layers.TCPPort) bool {
	//if type != 8 || code != 0 {return false}
	packetInfo := stringify(srcIP, nil, uint16(dstPort))
	netMap[packetInfo][binary.LittleEndian.Uint16(dstIP)]++
	return true
}

func printNetScanStats() bool {
	fmt.Printf("Number of PossibleScanners: %d\n", len(netMap))
	for k, v := range netMap {
		fmt.Printf("SrcIP, DestIP Pair: (%s, %s)\n", getSrcIP(k), getDstIP(k)) //can we print this way?
		fmt.Printf("\t Has %d ipDsts.\n", len(v))
		count := 0
		for _, v1 := range v {
			count += v1
		}
		fmt.Printf("\t and %d packets\n", count)
	}
	return true
}

/* ==================== Backscatter ========================= */

func testBackscatterTCP(srcIP net.IP) bool {
	//must pass the flags into this method and check here
	//only accept: SA, A, R, RA
	fmt.Println(srcIP)
	backscatterMap[binary.LittleEndian.Uint16(srcIP)]++
	return true
}

//TODO: NEED TO PASS IN PORTSRC
func testBackscatterUDP(srcIP net.IP) bool {
	//if portSrc != 53 && portSrc != 123 && portSrc != 137 && portSrc != 161 { return false }
	backscatterMap[binary.LittleEndian.Uint16(srcIP)]++
	return true
}

//TODO: NEED TO PASS IN CODE AND TYPE FOR ICMP
func testBackscatterICMP(srcIP net.IP) bool {
	/*if code != 0 || type != 0 {
		if code != 0 || type != 11 {
			if type != 3 {
				return false
			}
		}
	}*/
	backscatterMap[binary.LittleEndian.Uint16(srcIP)]++
	return true
}

func printBackscatterStats() bool {
	fmt.Printf("Number of backscatters: %d\n", len(backscatterMap))
	for k, v := range backscatterMap {
		fmt.Printf("ipSrc: %d sent %d packets\n", k, v)
	}
	return true
}

/* ========================= Main Loop ========================== */

func main() {
	count = 0
	netMap = make(map[string]map[uint16]int)
	portMap = make(map[string]map[uint16]int)
	backscatterMap = make(map[uint16]int)
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

		//fmt.Println("======PACKET LAYERS======")
		/*for _, layer := range packet.Layers() {
			//fmt.Println(layer.LayerType())
		}*/

		//fmt.Println("=====================")

		//Get IPv4 Layer
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		var ipSrc net.IP
		var ipDst net.IP
		if ipLayer != nil {
			//fmt.Println("IPv4 Layer Detected.")
			ip, _ := ipLayer.(*layers.IPv4)

			//IP layer variables:
			//Version (Either 4 or 6)
			//IHL (IP Header Length in 32-bit words)
			//TOS, Length, ID, Flages, FragOffset, TTL, Protocol (TCP?, etc.),
			//Checksum, SrcIP, DstIP
			//fmt.Printf("Source IP: %s\n", ip.SrcIP)
			//fmt.Printf("Destin IP: %s\n", ip.DstIP)
			//fmt.Printf("Protocol: %s\n", ip.Protocol)

			ipSrc = ip.SrcIP
			ipDst = ip.DstIP
		}

		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			//fmt.Println("TCP Layer Detected.")
			tcp, _ := tcpLayer.(*layers.TCP)

			var dstTCPPort = tcp.DstPort

			testPortScanTCP(ipSrc, ipDst, dstTCPPort, tcp.FIN, tcp.ACK)
			//fmt.Println("==================================")
			//fmt.Println("Testing for network scan")
			//testNetworkScanTCP(ipSrc, ipDst, dstTCPPort, tcp.FIN, tcp.ACK)
			//fmt.Println("Done testing network scan")
			//fmt.Println("==================================")
			//testBackscatterTCP(ipSrc, backscatterMap)
			/*
				type TCP struct {
				BaseLayer
				SrcPort, DstPort                           TCPPort
				Seq                                        uint32
				Ack                                        uint32
				DataOffset                                 uint8
				FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS bool
				Window                                     uint16
				Checksum                                   uint16
				Urgent                                     uint16
				sPort, dPort                               []byte
				Options                                    []TCPOption
				Padding                                    []byte
				opts                                       [4]TCPOption
				tcpipchecksum
			*/

		}

		/*udpLayer := packet.Layer(layers.LayerTypeUDP)
		if udpLayer != nil {
			fmt.Println("UDP layer detected.")

			udp, _ := udpLayer.(*layers.UDP)

			dstUDPPort := udp.DstPort

			//testPortScanUDP(ipSrc, ipDst, dstPort, tcp.FIN, tcp.ACK)
			testNetworkScanUDP(ipSrc, ipDst, dstUDPPort)
			testBackscatterUDP(ipSrc)
		}*/

		//i += 1
		//if (i == 4) {break}
	}
	//printBackscatterStats()
	printPortScanStats()
        //printNetworkScanStats()
        /*
        nonPortScan := set.New(set.NonThreadSafe)
        nonNetworkScan := set.New(set.NonThreadSafe)
        nonBackscatter := set.New(set.NonThreadSafe)
        /* Filter Port */
        for k, v := range portMap {
            if len(v) < PORT_SCAN_CUTOFF {
               for key, val := range v {
                   //create packet info with key, val
                   //newPacketInfo := stringifyNon(...)
                   nonPortScan.Add(newPacketInfo)
                }
            }
        }
        /* Network Scan Filter */
        for k, v := range networkMap {
            if len(v) < NET_SCAN_CUTOFF {
               for key, val := range v {
                   //could check networkscans
                   //create packet info with key, val
                   //newPacketInfo := stringifyNon(...)
                   nonNetworkScan.Add(newPacketInfo)
                }
            }
        }
        /* Backscatter Filter */
        for k, v := range backscatterMap {
            if v < BACKSCATTER_CUTOFF {
               //newPacketINfo := stringifyNon(...)
               nonBackscatter.Add(newPacketInfo)
            }
        }
        intermediate = set.Intersection(nonPortScan, nonNetworkScan)
        finalSet = set.Intersection(intermediate, nonBackscatter)
        f, err := os.Create("otherPacks.txt")
        defer f.Close()
        while (!finalSet.IsEmpty()) {
            item := finalSet.Pop()
            length, err := f.WriteString(item)
            if length != len(item) {fmt.Println("BAD\n")}
            length2, err2 := f.WriteString("\n")
            if length2 != 1 {fmt.Println("BAD2\n")}
        }
        */
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
