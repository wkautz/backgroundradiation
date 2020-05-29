package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/set"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	pcapFile  string = "/Users/dillonfranke/Downloads/2018-10-30.00.pcap"
	// pcapFile1 string = "/Volumes/SANDISK256/PCap_Data/2018-10-30.01.pcap"
	// pcapFile2 string = "/Volumes/SANDISK256/PCap_Data/2018-10-30.02.pcap"
	// pcapFile3 string = "/Volumes/SANDISK256/PCap_Data/2018-10-30.03.pcap"
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

// IPSrc -> Port -> # hits
var scanMap map[uint16]map[int]int

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

func packetRateGood(packet1 gopacket.Packet, packet2 gopacket.Packet) (bool) {
	packetType := fmt.Sprintf("%T", packet1.Metadata().Timestamp)
	fmt.Println(packetType)

	// Type: time.Time
	start := packet1.Metadata().Timestamp
	end := packet2.Metadata().Timestamp

	difference := end.Sub(start)

	fmt.Printf("Diff: %v\n", difference)

	goalDuration, err := time.ParseDuration("100ms")
	if err != err {
		log.Fatal(err)
	}

	return difference < goalDuration
}

/* TODO: 
	Document the structs for ICMP and UDP.
	Use these structs to try to build the nonTCP versions of all functions
*/

func main() {

	fmt.Printf("hello!")

	count = 0
	var previousPacket gopacket.Packet
	freqMap = make(map[int]int)
	netMap = make(map[string]map[uint16]int)
	scanMap = make(map[uint16]map[int]int)
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
		// pcapFileInput := ""
		// if i == 0 {
		// 	pcapFileInput = pcapFile
		// // } else if i == 1 {
		// // 	pcapFileInput = pcapFile1
		// // } else if i == 2 {
		// // 	pcapFileInput = pcapFile2
		// // } else {
		// // 	pcapFileInput = pcapFile3
		// }
		pcapFileInput := pcapFile
		handle, err = pcap.OpenOffline(pcapFileInput)
		if err != nil {
			log.Fatal(err)
		}
		defer handle.Close()

		// Loop through packets in file
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

		for packet := range packetSource.Packets() {
			// We need to skip the first packet so we can calculate a timestamp
			if count == 0 {
				count++
				previousPacket = packet
				continue
			}

			// Increment packet counter
			count++

			// Nicely prints out which packet we are at in processing
			if count%1000000 == 0 {
				fmt.Printf("%d packets\n", count)
			}

			/*********** Check for Scan ***********/
			if packetRateGood(previousPacket, packet) {
				// Then we get the IP information
				fmt.Println("Packet Rate is Good")
				//Get IPv4 Layer
				ipLayer := packet.Layer(layers.LayerTypeIPv4)
				var ipSrc net.IP

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
				}

				tcpLayer := packet.Layer(layers.LayerTypeTCP)

				// Get Destination port from TCP layer
				if tcpLayer != nil {
					tcp, _ := tcpLayer.(*layers.TCP)
					var dstTCPPort = tcp.DstPort
				
					// We've found a new ipSrc, and it might be part of a new scan
					if scanMap[binary.LittleEndian.Uint16(ipSrc)] == nil {
						newIPEntry := make(map[int]int)
						newIPEntry[int(dstTCPPort)] = 1
						scanMap[binary.LittleEndian.Uint16(ipSrc)] = newIPEntry
					} else { // We're adding to scan data
						scanMap[binary.LittleEndian.Uint16(ipSrc)][int(dstTCPPort)]++
					}
				}
			} else {
				fmt.Println("Skipping...")
			}

			previousPacket = packet

			if count == 20 {
				for k, v := range scanMap {
					fmt.Println(k)
					fmt.Println(v)
				}
				return
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
	}
	//END
	//BEGINNING OF STATS PRINTING


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
