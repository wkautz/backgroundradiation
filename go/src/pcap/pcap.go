package main

import (
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	//"sync/atomic"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	pcapFile string = "/Users/dillonfranke/Downloads/2018-10-30.00.pcap"
	// pcapFile1 string = "/Volumes/SANDISK256/PCap_Data/2018-10-30.01.pcap"
	pcapFile1 string = "/Users/dillonfranke/Downloads/2018-10-30.01.pcap"
	// pcapFile3 string = "/Volumes/SANDISK256/PCap_Data/2018-10-30.03.pcap"
	// pcapFile string = "/Users/wilhemkautz/Documents/classes/cs244/2018-10-30.00.pcap"
	// pcapFile1 string = "/Users/wilhemkautz/Documents/classes/cs244/2018-10-30.01.pcap"
	// pcapFile2 string = "/Users/wilhemkautz/Documents/classes/cs244/2018-10-30.02.pcap"
	// pcapFile3 string = "/Users/wilhemkautz/Documents/classes/cs244/2018-10-30.03.pcap"
	handle *pcap.Handle
	err    error
	count  uint64
)

/* TODO: Make these more official cutoffs. Paper gives good ideas */
const PORT_SCAN_CUTOFF = 40
const NET_SCAN_CUTOFF = 8
const BACKSCATTER_CUTOFF = 40

/* "num;count" for some reason */
func stringCounter(num uint16, count uint16) string {
	countStr := strconv.Itoa(int(count))
	return strconv.Itoa(int(num)) + ";" + countStr
}

/* From "num;count" pulls out num */
func getData(thing string) string {
	return strings.Split(thing, ";")[0]
}

/* From "num;count" pulls out count */
func getCount(thing string) uint16 {
	counter, _ := strconv.Atoi(strings.Split(thing, ";")[1])
	return uint16(counter)
}

/* Takes all arguments as strings to create "srcIP;dstIP;dPort" as a string */
func stringifyNot(srcIP string, dstIP string, dPort string) string {
	return srcIP + ";" + dstIP + ";" + dPort
}

/* Serializes the flags, if needed */
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

/* Takes inputs as they are found in the packet, to create "srcIP;dstIP;dPort" */
func stringify(srcIP net.IP, dstIP net.IP, dPort uint16) string {
	dstIPint := 0
	if dstIP != nil {
		dstIPint = int(binary.LittleEndian.Uint16(dstIP))
	}

	return strconv.Itoa(int(binary.LittleEndian.Uint16(srcIP))) + ";" + strconv.Itoa(dstIPint) + ";" + strconv.Itoa(int(dPort))
}

/* String: "srcIP;dstIP;dPort" */
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

// IPSrc -> Port -> # hits w/ zMap
var zMapMap map[uint16]map[int]int

var masscanMap map[uint16]map[int]int

// TODO: add map that counts unique ip destinations as well
// This map counts port destinations, but not ip dests. need both to classify scans and scan size
//var zMapMapConcurrent sync.Map
var scanMut sync.Mutex

var mut sync.Mutex

/* ========================= Main Loop ========================== */

func packetRateGood(packet1 gopacket.Packet, packet2 gopacket.Packet) bool {
	// packetType := fmt.Sprintf("%T", packet1.Metadata().Timestamp)
	//fmt.Println(packetType)

	// Type: time.Time
	start := packet1.Metadata().Timestamp
	end := packet2.Metadata().Timestamp

	difference := end.Sub(start)

	//fmt.Printf("Diff: %v\n", difference)

	goalDuration, err := time.ParseDuration("100ms")
	if err != err {
		log.Fatal(err)
	}

	return difference < goalDuration
}

func checkZMap(ipSrc net.IP, dstTCPPort layers.TCPPort, ipId uint16) {
	if ipId == 54321 {
		// We've found a new ipSrc, and it might be part of a new scan
		scanMut.Lock()
		if zMapMap[binary.LittleEndian.Uint16(ipSrc)] == nil {
			newIPEntry := make(map[int]int)
			newIPEntry[int(dstTCPPort)] = 1
			zMapMap[binary.LittleEndian.Uint16(ipSrc)] = newIPEntry
		} else { // We're adding to scan data
			zMapMap[binary.LittleEndian.Uint16(ipSrc)][int(dstTCPPort)]++
		}
		scanMut.Unlock()
	}
}

func checkMasscan(ipSrc net.IP, ipDest net.IP, dstTCPPort layers.TCPPort, ipId uint16, tcpSeqNo uint32) {

	fingerprint := uint32(binary.LittleEndian.Uint16(ipDest)) ^ uint32(dstTCPPort)
	fingerprint = fingerprint ^ tcpSeqNo

	if ipId == uint16(fingerprint) {
		// We've found a new ipSrc, and it might be part of a new scan
		scanMut.Lock()
		if masscanMap[binary.LittleEndian.Uint16(ipSrc)] == nil {
			newIPEntry := make(map[int]int)
			newIPEntry[int(dstTCPPort)] = 1
			masscanMap[binary.LittleEndian.Uint16(ipSrc)] = newIPEntry
		} else { // We're adding to scan data
			masscanMap[binary.LittleEndian.Uint16(ipSrc)][int(dstTCPPort)]++
		}
		scanMut.Unlock()
	}
}

func handlePackets(filename string, wg *sync.WaitGroup) {
	var previousPacket gopacket.Packet
	count = 0
	pcapFileInput := filename
	handle, err = pcap.OpenOffline(pcapFileInput)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Loop through packets in file
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	local_count := 0
	for packet := range packetSource.Packets() {
		//fmt.Printf("loop")
		// We need to skip the first packet so we can calculate a timestamp
		if local_count == 0 {
			mut.Lock()
			count++
			mut.Unlock()
			local_count++
			previousPacket = packet
			continue
		}

		// Increment packet counter
		mut.Lock()
		count++
		mut.Unlock()
		local_count++

		// Nicely prints out which packet we are at in processing
		if count%1000000 == 0 {
			fmt.Printf("%d packets\n", count)
		}

		/*********** Check for Scan ***********/
		if packetRateGood(previousPacket, packet) {
			// Then we get the IP information
			// Get IPv4 Layer
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			var ipSrc net.IP
			var ipDest net.IP
			var ipId uint16

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
				ipId = ip.Id
				ipSrc = ip.SrcIP
				ipDest = ip.DstIP
			}

			tcpLayer := packet.Layer(layers.LayerTypeTCP)

			// Get Destination port from TCP layer
			if tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)
				var dstTCPPort = tcp.DstPort

				/******** zMap Check *********/
				checkZMap(ipSrc, dstTCPPort, ipId)
				checkMasscan(ipSrc, ipDest, dstTCPPort, ipId, tcp.Seq)
			}
		} else {
			fmt.Println("Skipping...")
		}

		previousPacket = packet

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
	wg.Done()
}

/* TODO:
Document the structs for ICMP and UDP.
Use these structs to try to build the nonTCP versions of all functions
*/

func main() {

	//count = 0
	//var previousPacket gopacket.Packet
	zMapMap = make(map[uint16]map[int]int)
	masscanMap = make(map[uint16]map[int]int)
	// Open file instead of device

	// if i == 0 {
	// 	pcapFileInput = pcapFile
	// // } else if i == 1 {
	// // 	pcapFileInput = pcapFile1
	// // } else if i == 2 {
	// // 	pcapFileInput = pcapFile2
	// // } else {
	// // 	pcapFileInput = pcapFile3
	var waitGroup sync.WaitGroup
	waitGroup.Add(4)

	go handlePackets(pcapFile, &waitGroup)
	go handlePackets(pcapFile1, &waitGroup)
	// go handlePackets(pcapFile2, &waitGroup)
	// go handlePackets(pcapFile3, &waitGroup)
	//START LOOP
	waitGroup.Wait()

	/* zmap map printing */
	fzmap, _ := os.Create("zMap.txt")
	defer fzmap.Close()
	for k, v := range zMapMap {
		fzmap.WriteString("SrcIP: " + strconv.Itoa(int(k)) + "\n")
		for i, j := range v {
			fzmap.WriteString("\tPort: " + strconv.Itoa(int(i)) + "-->" + strconv.Itoa(int(j)) + "\n")
		}
		fzmap.WriteString("\n")
	}

	ip := ""
	baseURL := "http://api.ipstack.com/"
	accessKey := "?access_key="
	//get access key from api.ipstack.com
	requestStr := baseURL + ip + accessKey

	response, err := http.Get(requestStr)
	if err != nil {
		fmt.Printf("The HTTP request failed with error %s\n", err)
	} else {
		data, _ := ioutil.ReadAll(response.Body)
		fmt.Println(string(data))
	}

	/* End of nothing stats */

	fmt.Printf("Total packets: %d", count)
}
