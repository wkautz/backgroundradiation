package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"

	//"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	//"github.com/fatih/set"
)

var (
	//pcapFile string = "/Volumes/SANDISK256/PCap_Data/2018-10-30.00.pcap"
	pcapFile string = "/Volumes/SANDISK256/PCap_Data/2018-10-30.00.pcap"
	//pcapFile string = "/home/wkautz/pcap_file"
	handle *pcap.Handle
	err    error
	count  int
)

func stringifyNot(srcIP string, dstIP string, dPort string) string {
	return srcIP + ";" + dstIP + ";" + dPort
}

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
var portMapUnique map[string]uint16
var netMap map[string]map[uint16]int

//var backscatterMap map[uint16]int

var backscatterMap map[uint16]map[string]int

/* ===================== Port Scans & One Flow ====================== */
func testPortScanTCP(srcIP net.IP, dstIP net.IP, dstPort layers.TCPPort, FIN bool, ACK bool, SYN bool) bool {

	count++
	//fmt.Printf("FIN: %t\n", FIN)
	//fmt.Printf("ACK: %t\n", ACK)

	if count%1000000 == 0 {
		fmt.Printf("%d packets\n", count)
	}
	/* Accept: (FINACK),(SYN), (FIN), (NULL)  */
	if (FIN && ACK) || (SYN) || (FIN) {
		//do nothing. I just didnt want to deal with the logic of
		//trying to negate that
	} else {
		return false
	}
	/*if !FIN && !ACK {
		return false
	}*/
	packetInfo := stringify(srcIP, dstIP, 0)

	//portMapUnique
	if portMapUnique[packetInfo] == 0 {
		portMapUnique[packetInfo] = uint16(dstPort)
	} else {

		if portMap[packetInfo] == nil {
			m := make(map[uint16]int)
			m[uint16(dstPort)] = 1
			portMap[packetInfo] = m
			dstPort2 := portMapUnique[packetInfo]
			if dstPort2 == uint16(dstPort) {
				portMap[packetInfo][uint16(dstPort)]++
			} else {
				portMap[packetInfo][uint16(dstPort2)] = 1
			}
		} else {
			//if it passes checks, just remove it here to save memory
			portMap[packetInfo][uint16(dstPort)]++
		}
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
		if len(v) >= 5 {

			fmt.Printf("SrcIP, DestIP Pair: (%s, %s)\n", getSrcIP(k), getDstIP(k)) //can we print this way?
			fmt.Printf("\t Has %d ipDsts.\n", len(v))
			count := 0
			for _, v1 := range v {
				count += v1
			}
			fmt.Printf("\t and %d packets\n", count)

		}
	}
	return true
}

/* ==================== Backscatter ========================= */

func testBackscatterTCP(srcIP net.IP, dstIP net.IP, dPort uint16) bool {
	//must pass the flags into this method and check here
	//only accept: SA, A, R, RA
	//fmt.Println(srcIP)
	packetInfo := stringify(srcIP, dstIP, dPort)

	if backscatterMap[binary.LittleEndian.Uint16(srcIP)] == nil {
		m := make(map[string]int)
		m[packetInfo] = 1
		backscatterMap[binary.LittleEndian.Uint16(srcIP)] = m
	} else {
		backscatterMap[binary.LittleEndian.Uint16(srcIP)][packetInfo]++
	}
	/*
	        packetInfo := stringify(srcIP, dstIP, dPort)
		backscatterMap[binary.LittleEndian.Uint16(srcIP)]++*/
	return true
}

//TODO: NEED TO PASS IN PORTSRC
func testBackscatterUDP(srcIP net.IP, dstIP net.IP, dPort uint16) bool {
	//if portSrc != 53 && portSrc != 123 && portSrc != 137 && portSrc != 161 { return false; }
	packetInfo := stringify(srcIP, dstIP, dPort)

	if backscatterMap[binary.LittleEndian.Uint16(srcIP)] == nil {
		m := make(map[string]int)
		m[packetInfo] = 1
		backscatterMap[binary.LittleEndian.Uint16(srcIP)] = m
	} else {
		backscatterMap[binary.LittleEndian.Uint16(srcIP)][packetInfo]++
	}

	/*packetInfo := stringify(srcIP, dstIP, dPort)
	  backscatterMap[binary.LittleEndian.Uint16(srcIP)]++*/
	return true
}

//TODO: NEED TO PASS IN CODE AND TYPE FOR ICMP
func testBackscatterICMP(srcIP net.IP, dstIP net.IP, dPort uint16) bool {
	/*if code != 0 || type != 0 {
		if code != 0 || type != 11 {
			if type != 3 {
				return false
			}
		}
	}*/

	packetInfo := stringify(srcIP, dstIP, dPort)

	if backscatterMap[binary.LittleEndian.Uint16(srcIP)] == nil {
		m := make(map[string]int)
		m[packetInfo] = 1
		backscatterMap[binary.LittleEndian.Uint16(srcIP)] = m
	} else {
		backscatterMap[binary.LittleEndian.Uint16(srcIP)][packetInfo]++
	}

	/*packetInfo := stringify(srcIP, dstIP, dPort)
	        //change backscattermap to be from src to packetInfo
		backscatterMap[binary.LittleEndian.Uint16(srcIP)]++*/
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
	portMapUnique = make(map[string]uint16)
	//backscatterMap = make(map[uint16]int)
	backscatterMap = make(map[uint16]map[string]int)
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

			testPortScanTCP(ipSrc, ipDst, dstTCPPort, tcp.FIN, tcp.ACK, tcp.SYN)
			//fmt.Println("==================================")
			//fmt.Println("Testing for network scan")
			//testNetworkScanTCP(ipSrc, ipDst, dstTCPPort, tcp.FIN, tcp.ACK)
			//fmt.Println("Done testing network scan")
			//fmt.Println("==================================")
			//testBackscatterTCP(ipSrc, ipDst, uint16(dstTCPPort))
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
			//testNetworkScanUDP(ipSrc, ipDst, dstUDPPort)
			//testBackscatterUDP(ipSrc)
		}*/

		//i += 1
		//if (i == 4) {break}
	}
	//printBackscatterStats()
	printPortScanStats()
	//printNetScanStats()
	/*
	   nonPortScan := set.New(set.NonThreadSafe)
	   nonNetworkScan := set.New(set.NonThreadSafe)
	   nonBackscatter := set.New(set.NonThreadSafe)
	*/ /* Filter Port */
	/*for k, v := range portMap {
	    if len(v) < 10 PORT_SCAN_CUTOFF  {
	       for key, _ := range v {
	           //create packet info with key, val
	           portsrcIP := getSrcIP(k)
	           portdestIP := getDstIP(k)
	           portdestPort := key
	           newPacketInfo := stringifyNot(portsrcIP, portdestIP, string(portdestPort))
	           nonPortScan.Add(newPacketInfo) //does it need a type declared
	        }
	    }
	}*/
	/* Network Scan Filter */
	/*for k, v := range netMap {
	    if len(v) < 10 NET_SCAN_CUTOFF {
	       for key, _ := range v {
	           //could check networkscans
	           portsrcIP := getSrcIP(k)
	           portdestIP := key
	           portdestPort := getDPortIP(k)
	           //create packet info with key, val
	           newPacketInfo := stringifyNot(portsrcIP, string(portdestIP), string(portdestPort))
	           nonNetworkScan.Add(newPacketInfo)
	        }
	    }
	}*/
	/* Backscatter Filter */
	/*for k, v := range backscatterMap {
	      //maybe write a count(v) function
	      if len(v) < 10 BACKSCATTER_CUTOFF {
	         //len(v) might not be right if you use multiple identical packets.
	         for key, _ := range v {
	             portsrcIP := k
	             portdestIP := getDstIP(key)
	             portdestPort := getDPortIP(key)
	             newPacketInfo := stringifyNot(string(portsrcIP), string(portdestIP), portdestPort)
	             nonBackscatter.Add(newPacketInfo)
	         }
	         //nonBackscatter.Add(newPacketInfo)
	      }
	  }
	  intermediate := set.Intersection(nonPortScan, nonNetworkScan)
	  finalSet := set.Intersection(intermediate, nonBackscatter)
	  f, _ := os.Create("otherPacks.txt")
	  defer f.Close()
	  for !finalSet.IsEmpty() {
	      item := finalSet.Pop().(string)
	      length, _ := f.WriteString(item) //need error checking
	      if length != 0 {fmt.Println("MEH\n")}
	      length2, _ := f.WriteString("\n")
	      if length2 != 1 {fmt.Println("BAD2\n")}
	  } */
}
