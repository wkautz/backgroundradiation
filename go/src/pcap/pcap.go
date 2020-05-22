package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/fatih/set"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	pcapFile  string = "/Volumes/SANDISK256/PCap_Data/2018-10-30.00.pcap"
	pcapFile1 string = "/Volumes/SANDISK256/PCap_Data/2018-10-30.01.pcap"
	pcapFile2 string = "/Volumes/SANDISK256/PCap_Data/2018-10-30.02.pcap"
	pcapFile3 string = "/Volumes/SANDISK256/PCap_Data/2018-10-30.03.pcap"
	//pcapFile string = "/home/wkautz/pcap_file"
	handle *pcap.Handle
	err    error
	count  int
)

const PORT_SCAN_CUTOFF = 40
const NET_SCAN_CUTOFF = 8
const BACKSCATTER_CUTOFF = 40

func stringCounter(num uint16, count uint16) string {
	countStr := strconv.Itoa(int(count))
	return strconv.Itoa(int(num)) + ";" + countStr
}

func getData(thing string) string {
	return strings.Split(thing, ";")[0]
}

func getCount(thing string) uint16 {
	counter, _ := strconv.Atoi(strings.Split(thing, ";")[1])
	return uint16(counter)
}

func stringifyNot(srcIP string, dstIP string, dPort string) string {
	return srcIP + ";" + dstIP + ";" + dPort
}

/*
func stringifyFlags(SYN bool, FIN bool, ACK bool, RST bool) string {
     result := ""
     if SYN {
        result += "1"
     } else {
        result += "0"
     }
     if FIN {
        result += "1"
     } else {
        result += "0"
     }
     if ACK {
        result += "1"
     } else {
        result += "0"
     }
     if RST {
        result += "1"
     } else {
        result += "0"
     }
     return result
}

*/


func stringify(srcIP net.IP, dstIP net.IP, dPort uint16) string {
	dstIPint := 0
	if dstIP != nil {
		dstIPint = int(binary.LittleEndian.Uint16(dstIP))
	}

	return strconv.Itoa(int(binary.LittleEndian.Uint16(srcIP))) + ";" + strconv.Itoa(dstIPint) + ";" + strconv.Itoa(int(dPort))
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

/* ===================== Map Data Structures ====================== */

// (IPSrc, IPDest) -> Port Num -> #hits
// Maps (TCP Flow) to (Map from Port Number to Hits)
var portMap map[string]map[uint16]int

// (IPSrc, IPDest) -> Port Num
// Maps from TCP Flow to Port that is hit
// TODO: Why do we need this?
var portMapUnique map[string]string

// ()
var netMap map[string]map[uint16]int
var netMapUnique map[string]uint16
var freqMap map[int]int

// IPSrc -> array (contains # of times certain flag params have been seen)
var flagMap map[string][]uint16

var backscatterMap map[uint16]map[string]int
var backscatterUnique map[uint16]string

/* ===================== Port Scans & One Flow ====================== */
func testPortScanTCP(srcIP net.IP, dstIP net.IP, dstPort layers.TCPPort, FIN bool, ACK bool, SYN bool, RST bool) bool {

	testFlags(FIN, ACK, SYN, RST, srcIP)

	/* Accept: (FINACK),(SYN), (FIN), (NULL)  */
	if (FIN && ACK) || (SYN) || (FIN) {
		//do nothing. I just didnt want to deal with the logic of
		//trying to negate that

		//did cs103 teach you nothing??? lol
	} else {
		return false
	}
	//flagInfo := stringifyFlags(SYN, FIN, ACK, RST)
	//type := "tcp"
	packetInfo := stringify(srcIP, dstIP, 0)

	/*
		//Create new map[srcIP]arr[flagCombinations] to see which flags
	*/

	//portMapUnique
	if portMapUnique[packetInfo] == "" {
		portMapUnique[packetInfo] = stringCounter(uint16(dstPort), 1)
	} else {
		if portMap[packetInfo] == nil {
			m := make(map[uint16]int)
			m[uint16(dstPort)] = 1
			portMap[packetInfo] = m
			dstPortInt, _ := strconv.Atoi(getData(portMapUnique[packetInfo]))
			dstPort2 := uint16(dstPortInt)
			//numHits := int(getCount(portMapUnique[packetInfo]))
			if dstPort2 == uint16(dstPort) {
				portMap[packetInfo][uint16(dstPort)] += 1 //numHits
			} else {
				portMap[packetInfo][uint16(dstPort2)] = 1 //numHits
			}
		} else {
			//if it passes checks, just remove it here to save memory
			portMap[packetInfo][uint16(dstPort)]++
		}
		portMapUnique[packetInfo] = stringCounter(uint16(dstPort), 0)
	}
	return true
}

func testPortScanUDP(srcIP net.IP, dstIP net.IP, dstPort layers.TCPPort) bool {
	//any UDP checks would go here
	packetInfo := stringify(srcIP, dstIP, 0)
	if portMapUnique[packetInfo] == "" {
		portMapUnique[packetInfo] = stringCounter(uint16(dstPort), 1)
	} else {
		if portMap[packetInfo] == nil {
			m := make(map[uint16]int)
			m[uint16(dstPort)] = 1
			portMap[packetInfo] = m
			dstPortInt, _ := strconv.Atoi(getData(portMapUnique[packetInfo]))
			dstPort2 := uint16(dstPortInt)
			//numHits := int(getCount(portMapUnique[packetInfo]))
			if dstPort2 == uint16(dstPort) {
				portMap[packetInfo][uint16(dstPort)] += 1 //numHits
			} else {
				portMap[packetInfo][uint16(dstPort2)] = 1 //numHits
			}
		} else {
			//if it passes checks, just remove it here to save memory
			portMap[packetInfo][uint16(dstPort)]++
		}
		portMapUnique[packetInfo] = stringCounter(uint16(dstPort), 0)
	}
	return true
}

func printPortScanStats() bool {
	fmt.Printf("Number of PossibleScanners: %d\n", len(portMap))
	for _, v := range portMap {
		//if len(v) >= 5 {
		//fmt.Printf("SrcIP, DestIP Pair: (%s, %s)\n", getSrcIP(k), getDstIP(k)) //can we print this way?
		//fmt.Printf("\t Has %d dPorts.\n", len(v))
		countPackets := 0
		for _, v1 := range v {
			countPackets += v1
		}
		freqMap[len(v)]++ //countPackets
		//fmt.Printf("\t and %d packets\n", countPackets)
		//}
	}
	return true
}

func printFreqMap(filename string) bool {
	f, _ := os.Create(filename)
	defer f.Close()

	var keys []int
	for k := range freqMap {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	for _, k := range keys {
		item := strconv.Itoa(k) + "," + strconv.Itoa(freqMap[k]) + "\n"
		length, _ := f.WriteString(item)
		if length == 0 {
			fmt.Println("MEH\n")
		}
	}
	return true
}

/* =================== Network Scans ==================== */
//pull out features of UDP and TCP packets
func testNetworkScanTCP(srcIP net.IP, dstIP net.IP, dstPort layers.TCPPort, FIN bool, ACK bool, SYN bool, RST bool) bool {

	if (FIN && ACK) || (SYN) || (FIN) {
		//do nothing. I just didnt want to deal with the logic of
		//trying to negate that
	} else {
		return false
	}
	//flagInfo := stringifyFlags(SYN, FIN, ACK, RST)
	//type := "tcp"
	packetInfo := stringify(srcIP, nil, uint16(dstPort))
	if netMapUnique[packetInfo] == 0 {
		netMapUnique[packetInfo] = binary.LittleEndian.Uint16(dstIP)
	} else {

		if netMap[packetInfo] == nil {
			m := make(map[uint16]int)
			m[binary.LittleEndian.Uint16(dstIP)] = 1
			netMap[packetInfo] = m
			dstIP2 := netMapUnique[packetInfo]
			if dstIP2 == binary.LittleEndian.Uint16(dstIP) {
				netMap[packetInfo][binary.LittleEndian.Uint16(dstIP)]++
			} else {
				netMap[packetInfo][dstIP2] = 1
			}
		} else {
			//if it passes checks, just remove it here to save memory
			netMap[packetInfo][binary.LittleEndian.Uint16(dstIP)]++
		}
	}
	return true
}

func testNetworkScanUDP(srcIP net.IP, dstIP net.IP, dstPort layers.UDPPort) bool {
	packetInfo := stringify(srcIP, nil, uint16(dstPort))
	if netMapUnique[packetInfo] == 0 {
		netMapUnique[packetInfo] = binary.LittleEndian.Uint16(dstIP)
	} else {

		if netMap[packetInfo] == nil {
			m := make(map[uint16]int)
			m[binary.LittleEndian.Uint16(dstIP)] = 1
			netMap[packetInfo] = m
			dstIP2 := netMapUnique[packetInfo]
			if dstIP2 == binary.LittleEndian.Uint16(dstIP) {
				netMap[packetInfo][binary.LittleEndian.Uint16(dstIP)]++
			} else {
				netMap[packetInfo][dstIP2] = 1
			}
		} else {
			//if it passes checks, just remove it here to save memory
			netMap[packetInfo][binary.LittleEndian.Uint16(dstIP)]++
		}
	}
	return true
}

func testNetworkScanICMP(srcIP net.IP, dstIP net.IP, dstPort layers.TCPPort) bool {
	//if type != 8 || code != 0 {return false}
	packetInfo := stringify(srcIP, nil, uint16(dstPort))
	if netMapUnique[packetInfo] == 0 {
		netMapUnique[packetInfo] = binary.LittleEndian.Uint16(dstIP)
	} else {

		if netMap[packetInfo] == nil {
			m := make(map[uint16]int)
			m[binary.LittleEndian.Uint16(dstIP)] = 1
			netMap[packetInfo] = m
			dstIP2 := netMapUnique[packetInfo]
			if dstIP2 == binary.LittleEndian.Uint16(dstIP) {
				netMap[packetInfo][binary.LittleEndian.Uint16(dstIP)]++
			} else {
				netMap[packetInfo][dstIP2] = 1
			}
		} else {
			//if it passes checks, just remove it here to save memory
			netMap[packetInfo][binary.LittleEndian.Uint16(dstIP)]++
		}
	}
	return true
}

func printNetScanStats() bool {
	fmt.Printf("Number of PossibleScanners: %d\n", len(netMap))
	for _, v := range netMap {
		counter := 0
		for _, v1 := range v {
			counter += v1
		}
		freqMap[len(v)]++ //= counter
	}
	return true
}

/* ==================== Backscatter ========================= */

func testBackscatterTCP(srcIP net.IP, dstIP net.IP, dPort uint16, FIN bool, ACK bool, SYN bool, RST bool) bool {
	//must pass the flags into this method and check here
	if (SYN && ACK) || (ACK) || (RST) || (RST && ACK) {
		//do nothing, this is the good case
	} else {
		return false
	}
	//flagInfo := stringifyFlags(SYN, FIN, ACK, RST)
	//type := "tcp"
	packetInfo := stringify(srcIP, dstIP, dPort)
	if backscatterUnique[binary.LittleEndian.Uint16(srcIP)] == "" {
		backscatterUnique[binary.LittleEndian.Uint16(srcIP)] = packetInfo
	} else {

		if backscatterMap[binary.LittleEndian.Uint16(srcIP)] == nil {
			m := make(map[string]int)
			m[packetInfo] = 1
			backscatterMap[binary.LittleEndian.Uint16(srcIP)] = m
			packet2 := backscatterUnique[binary.LittleEndian.Uint16(srcIP)]
			if packet2 == packetInfo {
				backscatterMap[binary.LittleEndian.Uint16(srcIP)][packetInfo]++
			} else {
				backscatterMap[binary.LittleEndian.Uint16(srcIP)][packet2] = 1
			}
		} else {
			backscatterMap[binary.LittleEndian.Uint16(srcIP)][packetInfo]++
		}
	}

	return true
}

//TODO: NEED TO PASS IN PORTSRC
func testBackscatterUDP(srcIP net.IP, dstIP net.IP, dPort uint16) bool {
	//if portSrc != 53 && portSrc != 123 && portSrc != 137 && portSrc != 161 { return false; }
	packetInfo := stringify(srcIP, dstIP, dPort)

	if backscatterUnique[binary.LittleEndian.Uint16(srcIP)] == "" {
		backscatterUnique[binary.LittleEndian.Uint16(srcIP)] = packetInfo
	} else {

		if backscatterMap[binary.LittleEndian.Uint16(srcIP)] == nil {
			m := make(map[string]int)
			m[packetInfo] = 1
			backscatterMap[binary.LittleEndian.Uint16(srcIP)] = m
			packet2 := backscatterUnique[binary.LittleEndian.Uint16(srcIP)]
			if packet2 == packetInfo {
				backscatterMap[binary.LittleEndian.Uint16(srcIP)][packetInfo]++
			} else {
				backscatterMap[binary.LittleEndian.Uint16(srcIP)][packet2] = 1
			}
		} else {
			backscatterMap[binary.LittleEndian.Uint16(srcIP)][packetInfo]++
		}
	}
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
	if backscatterUnique[binary.LittleEndian.Uint16(srcIP)] == "" {
		backscatterUnique[binary.LittleEndian.Uint16(srcIP)] = packetInfo
	} else {

		if backscatterMap[binary.LittleEndian.Uint16(srcIP)] == nil {
			m := make(map[string]int)
			m[packetInfo] = 1
			backscatterMap[binary.LittleEndian.Uint16(srcIP)] = m
			packet2 := backscatterUnique[binary.LittleEndian.Uint16(srcIP)]
			if packet2 == packetInfo {
				backscatterMap[binary.LittleEndian.Uint16(srcIP)][packetInfo]++
			} else {
				backscatterMap[binary.LittleEndian.Uint16(srcIP)][packet2] = 1
			}
		} else {
			backscatterMap[binary.LittleEndian.Uint16(srcIP)][packetInfo]++
		}
	}
	return true
}

func printBackscatterStats() bool {
	fmt.Printf("Number of PossibleDoSers (the fuckers): %d\n", len(backscatterMap))
	for _, v := range backscatterMap {
		//if len(v) >= 5 {

		//fmt.Printf("SrcIP, DestIP Pair: (%s, %s)\n", getSrcIP(k), getDstPort(k)) //can we print this way?
		//fmt.Printf("\t Has %d ipDsts.\n", len(v))
		counter := 0
		for _, v1 := range v {
			counter += v1
		}
		freqMap[len(v)]++ //= counter
		//fmt.Printf("\t and %d packets\n", counter)

		//}
	}
	return true
}

/* ========================= Main Loop ========================== */

/* TODO: what is the point of this function and the flagMap at all? */
func testFlags(FIN bool, ACK bool, SYN bool, RST bool, srcIP net.IP) {
	var bitarray uint64

	/* TODO: look at this garbage. Is there no OS-based function for flipping to host order? */
	val := string(strconv.Itoa(int(binary.LittleEndian.Uint16(srcIP))))

	if FIN {
		bitarray = bitarray | (1 << 3)
	}

	if ACK {
		bitarray = bitarray | (1 << 2)
	}

	if SYN {
		bitarray = bitarray | (1 << 1)
	}

	if RST {
		bitarray = bitarray | 1
	}

	if flagMap[val] == nil {
		flagMap[val] = make([]uint16, 13)
	}

	flagMap[val][bitarray]++

}

/* TODO: 
	Document the structs for ICMP and UDP.
	Use these structs to try to build the nonTCP versions of all functions
*/

func main() {

	count = 0
	freqMap = make(map[int]int)
	netMap = make(map[string]map[uint16]int)
	portMap = make(map[string]map[uint16]int)
	portMapUnique = make(map[string]string)
	flagMap = make(map[string][]uint16)
	netMapUnique = make(map[string]uint16)
	backscatterUnique = make(map[uint16]string)
	backscatterMap = make(map[uint16]map[string]int)
	nothing := set.New(set.NonThreadSafe)
	// Open file instead of device
	//START LOOP
	for i := 0; i < 4; i++ {
		pcapFileInput := ""
		if i == 0 {
			pcapFileInput = pcapFile
		} else if i == 1 {
			pcapFileInput = pcapFile1
		} else if i == 2 {
			pcapFileInput = pcapFile2
		} else {
			pcapFileInput = pcapFile3
		}
		handle, err = pcap.OpenOffline(pcapFileInput)
		if err != nil {
			log.Fatal(err)
		}
		defer handle.Close()

		// Loop through packets in file
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

		for packet := range packetSource.Packets() {
			count++
			if count%1000000 == 0 {
				fmt.Printf("%d packets\n", count)
			}
			//if count == 10000000 {
			//   break
			//}
			//fmt.Println("======PACKET LAYERS======")
			/*for _, layer := range packet.Layers() {
				//fmt.Println(layer.LayerType())
			}*/

			//fmt.Println("=====================")

			//Get IPv4 Layer
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			var ipSrc net.IP
			var ipDst net.IP

			// HAS AN IP LAYER
			if ipLayer != nil {
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

			// TODO: Is this empty for UDP?
			if tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)

				var dstTCPPort = tcp.DstPort

				//TODO: what is b?
				//b is true if this packet was part of an attack
				b := false
				if testPortScanTCP(ipSrc, ipDst, dstTCPPort, tcp.FIN, tcp.ACK, tcp.SYN, tcp.RST) {
					b = true
				}
				if testNetworkScanTCP(ipSrc, ipDst, dstTCPPort, tcp.FIN, tcp.ACK, tcp.SYN, tcp.RST) {
					b = true
				}

				//dos, not important for this paper
				if testBackscatterTCP(ipSrc, ipDst, uint16(dstTCPPort), tcp.FIN, tcp.ACK, tcp.SYN, tcp.RST) {
					b = true
				}
				if !b {
					srcIP := strconv.Itoa(int(binary.LittleEndian.Uint16(ipSrc)))
					newPacketInfo := stringifyNot(srcIP, strconv.Itoa(int(binary.LittleEndian.Uint16(ipDst))), strconv.Itoa(int(dstTCPPort)))
					//nothing is the set of packets that were not part of an attack
					nothing.Add(newPacketInfo)
				}
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

			udpLayer := packet.Layer(layers.LayerTypeUDP)
			if udpLayer != nil {
				/* UDP Packet, TODO: what do we want to do with this? */
				udp, _ := udpLayer.(*layers.UDP)

				dstUDPPort := udp.DstPort

				//TODO: adapt TCP functions for UDP
				//testPortScanUDP(ipSrc, ipDst, dstPort)
				//testNetworkScanUDP(ipSrc, ipDst, dstUDPPort)
				//testBackscatterUDP(ipSrc)
			}

		}
	}
	//END
	//BEGINNING OF STATS PRINTING
	printBackscatterStats()
	printFreqMap("backscattercounts1.txt")

	freqMap = make(map[int]int)
	printPortScanStats()
	printFreqMap("portscancounts1.txt")

	freqMap = make(map[int]int)
	printNetScanStats()
	printFreqMap("netscancounts1.txt")


	/* Beginning of nothing stats */
	//END OF STATS PRINTING
	nonPortScan := set.New(set.NonThreadSafe)
	nonNetworkScan := set.New(set.NonThreadSafe)
	nonBackscatter := set.New(set.NonThreadSafe)
	
	/* Filter Port */
	for k, v := range portMap {
		if len(v) < PORT_SCAN_CUTOFF {
			for key, _ := range v {
				//create packet info with key, val
				portsrcIP := getSrcIP(k)
				portdestIP := getDstIP(k)
				portdestPort := key
				newPacketInfo := stringifyNot(portsrcIP, portdestIP, strconv.Itoa(int(portdestPort)))
				//fmt.Println(newPacketInfo)
				nonPortScan.Add(newPacketInfo) //does it need a type declared
			}
		}
	}
	/* Network Scan Filter */
	for k, v := range netMap {
		if len(v) < NET_SCAN_CUTOFF {
			for key, _ := range v {
				//could check networkscans
				portsrcIP := getSrcIP(k)
				portdestIP := key
				portdestPort := getDPortIP(k)
				//doesn't take into account the frequency of these packets
				newPacketInfo := stringifyNot(portsrcIP, strconv.Itoa(int(portdestIP)), portdestPort)
				//fmt.Println(newPacketInfo)
				nonNetworkScan.Add(newPacketInfo)
			}
		}
	}

	/* flagMap Printing */
	f1, _ := os.Create("flagMap.txt")
	defer f1.Close()
	for k, v := range flagMap {
		f1.WriteString(k + ",")
		for i := range v {
			f1.WriteString(strconv.FormatUint(uint64(v[i]), 10) + ",")
		}
		f1.WriteString("\n")
	}

	/* Backscatter Filter */
	for k, v := range backscatterMap {
		//maybe write a count(v) function
		if len(v) < BACKSCATTER_CUTOFF {
			//len(v) might not be right if you use multiple identical packets.
			for key, _ := range v {
				portsrcIP := k
				portdestIP := getDstIP(key)
				portdestPort := getDPortIP(key)
				//need to fix these strings
				newPacketInfo := stringifyNot(strconv.Itoa(int(portsrcIP)), portdestIP, portdestPort)
				//fmt.Println(newPacketInfo)
				nonBackscatter.Add(newPacketInfo)
			}
			//nonBackscatter.Add(newPacketInfo)
		}
	}

	//finalSet := set.Intersection(nonPortScan, nonNetworkScan, nonBackscatter, nothing)
	intermediate := set.Intersection(nonPortScan, nonNetworkScan) //Is this what we want?
	almostFinalSet := set.Intersection(intermediate, nonBackscatter)
	finalSet := set.Union(almostFinalSet, nothing)
	f, _ := os.Create("otherPacks.txt")
	defer f.Close()
	fmt.Printf("%d", finalSet.Size())
	for !finalSet.IsEmpty() {
		item := finalSet.Pop().(string)
		length, _ := f.WriteString(item) //need error checking
		if length == 0 {
			fmt.Println("MEH\n")
		}
		length2, _ := f.WriteString("\n")
		if length2 != 1 {
			fmt.Println("BAD2\n")
		}
	}

	/* End of nothing stats */

	fmt.Printf("Total packets: %d", count)
}
