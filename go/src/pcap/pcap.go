package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
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
	//pcapFile string = "/Users/dillonfranke/Downloads/2018-10-30.00.pcap"
	// pcapFile1 string = "/Volumes/SANDISK256/PCap_Data/2018-10-30.01.pcap"
	//pcapFile1 string = "/Users/dillonfranke/Downloads/2018-10-30.01.pcap"
	// pcapFile3 string = "/Volumes/SANDISK256/PCap_Data/2018-10-30.03.pcap"
	pcapFile  string = "/Users/wilhemkautz/Documents/classes/cs244/2018-10-30.00.pcap"
	pcapFile1 string = "/Users/wilhemkautz/Documents/classes/cs244/2018-10-30.01.pcap"
	pcapFile2 string = "/Users/wilhemkautz/Documents/classes/cs244/2018-10-30.02.pcap"
	pcapFile3 string = "/Users/wilhemkautz/Documents/classes/cs244/2018-10-30.03.pcap"
	handle    *pcap.Handle
	err       error
	count     uint64
)

/* TODO: Make these more official cutoffs. Paper gives good ideas */
const SCAN_CUTOFF = 1
const SLOWEST_RATE = 0.1

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

var scanMap map[uint16]map[uint16]int
var firstPacketTime map[uint16]time.Time
var recentPacketTime map[uint16]time.Time

//ip source to scan sizes
var scansSizes map[uint16][]int

// TODO: add map that counts unique ip destinations as well
// This map counts port destinations, but not ip dests. need both to classify scans and scan size
//var zMapMapConcurrent sync.Map
var scanMut sync.Mutex
var zmapMut sync.Mutex
var massMut sync.Mutex
var mut sync.Mutex

/* ========================= Main Loop ========================== */

func packetRateCheck(recent time.Time, ipSrc uint16, ipDest uint16) {
	scanMut.Lock()
	previousPacket := recentPacketTime[ipSrc]
	//oldestPacket := firstPacketTime[ipSrc]
	allDests := scanMap[ipSrc]
	if previousPacket.IsZero() {
		//first packet for this ipSource scan
		recentPacketTime[ipSrc] = recent
		firstPacketTime[ipSrc] = recent
		newDestMap := make(map[uint16]int)
		newDestMap[ipDest] = 1
		scanMap[ipSrc] = newDestMap
		scanMut.Unlock()
		return
	}
	scanMut.Unlock()
	difference := recent.Sub(previousPacket)
	expireTime, err := time.ParseDuration("480s")
	if err != err {
		log.Fatal(err)
	}

	/*longDifference := int(recent.Sub(oldestPacket))
	numPackets := 0
	scanMut.Lock()
	for _, v := range allDests {
		numPackets += v
	}
	scanMut.Unlock()*/
	//average := float64(numPackets) / (float64(longDifference) / float64(10e9))
	//fmt.Printf("average: %e, longDifference: %d, numPackets: %d\n", average, longDifference, numPackets)
	if (float64(difference)) >= float64(expireTime) /*|| average < SLOWEST_RATE */ {
		/*if difference >= expireTime {
			fmt.Printf("480: %d\n", difference)
		}*/
		/*if average < SLOWEST_RATE {
			//fmt.Printf("average: %e\n", average)
		}*/
		// this scan is expiring
		scanMut.Lock()
		totalPackets := 0
		for range allDests {
			totalPackets++
		}
		if totalPackets >= SCAN_CUTOFF {
			scansSizes[ipSrc] = append(scansSizes[ipSrc], totalPackets)
		}
		recentPacketTime[ipSrc] = recent
		firstPacketTime[ipSrc] = recent
		newDestMap := make(map[uint16]int)
		newDestMap[ipDest] = 1
		scanMap[ipSrc] = newDestMap
	} else {
		scanMut.Lock()
		recentPacketTime[ipSrc] = recent
		scanMap[ipSrc][ipDest]++
	}
	scanMut.Unlock()
}

func checkZMap(ipSrc net.IP, dstTCPPort layers.TCPPort, ipId uint16) {
	if ipId == 54321 {
		// We've found a new ipSrc, and it might be part of a new scan
		zmapMut.Lock()
		if zMapMap[binary.LittleEndian.Uint16(ipSrc)] == nil {
			newIPEntry := make(map[int]int)
			newIPEntry[int(dstTCPPort)] = 1
			zMapMap[binary.LittleEndian.Uint16(ipSrc)] = newIPEntry
		} else { // We're adding to scan data
			zMapMap[binary.LittleEndian.Uint16(ipSrc)][int(dstTCPPort)]++
		}
		zmapMut.Unlock()
	}
}

func checkMasscan(ipSrc net.IP, ipDest net.IP, dstTCPPort layers.TCPPort, ipId uint16, tcpSeqNo uint32) {

	fingerprint := uint32(binary.LittleEndian.Uint16(ipDest)) ^ uint32(dstTCPPort)
	fingerprint = fingerprint ^ tcpSeqNo

	if ipId == uint16(fingerprint) {
		// We've found a new ipSrc, and it might be part of a new scan
		massMut.Lock()
		if masscanMap[binary.LittleEndian.Uint16(ipSrc)] == nil {
			newIPEntry := make(map[int]int)
			newIPEntry[int(dstTCPPort)] = 1
			masscanMap[binary.LittleEndian.Uint16(ipSrc)] = newIPEntry
		} else { // We're adding to scan data
			masscanMap[binary.LittleEndian.Uint16(ipSrc)][int(dstTCPPort)]++
		}
		massMut.Unlock()
	}
}

func handlePackets(filename string, wg *sync.WaitGroup) {
	count = 0
	pcapFileInput := filename
	handle, err = pcap.OpenOffline(pcapFileInput)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Loop through packets in file
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		//fmt.Printf("loop")
		// We need to skip the first packet so we can calculate a timestamp

		// Increment packet counter
		mut.Lock()
		count++
		mut.Unlock()

		// Nicely prints out which packet we are at in processing
		mut.Lock()
		if count%1000000 == 0 {
			fmt.Printf("%d packets\n", count)
		}
		mut.Unlock()

		/*********** Check for Scan ***********/
		// Then we get the IP information
		// Get IPv4 Layer
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		var ipSrc net.IP
		var ipDest net.IP
		//var ipId uint16

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
			//ipId = ip.Id
			ipSrc = ip.SrcIP
			ipDest = ip.DstIP

		} else {
			fmt.Println("I didn't want this packet anyways")
			continue
		}
		packetRateCheck(packet.Metadata().Timestamp, binary.LittleEndian.Uint16(ipSrc), binary.LittleEndian.Uint16(ipDest))

		tcpLayer := packet.Layer(layers.LayerTypeTCP)

		// Get Destination port from TCP layer
		if tcpLayer != nil {
			//tcp, _ := tcpLayer.(*layers.TCP)
			//var dstTCPPort = tcp.DstPort

			/******** zMap Check *********/
			//checkZMap(ipSrc, dstTCPPort, ipId)
			//checkMasscan(ipSrc, ipDest, dstTCPPort, ipId, tcp.Seq)
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
	wg.Done()
}

/* TODO:
Document the structs for ICMP and UDP.
Use these structs to try to build the nonTCP versions of all functions
*/

func main() {

	//count = 0
	zMapMap = make(map[uint16]map[int]int)
	masscanMap = make(map[uint16]map[int]int)
	firstPacketTime = make(map[uint16]time.Time)
	recentPacketTime = make(map[uint16]time.Time)
	// Open file instead of device
	scanMap = make(map[uint16]map[uint16]int)

	//ip source to scan sizes
	scansSizes = make(map[uint16][]int)

	// if i == 0 {
	// 	pcapFileInput = pcapFile
	// // } else if i == 1 {
	// // 	pcapFileInput = pcapFile1
	// // } else if i == 2 {
	// // 	pcapFileInput = pcapFile2
	// // } else {
	// // 	pcapFileInput = pcapFile3
	var waitGroup sync.WaitGroup
	waitGroup.Add(1)

	go handlePackets(pcapFile, &waitGroup)
	//go handlePackets(pcapFile1, &waitGroup)
	//go handlePackets(pcapFile2, &waitGroup)
	//go handlePackets(pcapFile3, &waitGroup)
	//START LOOP
	waitGroup.Wait()

	/* zmap map printing */
	/*fzmap, _ := os.Create("zMap.txt")
	defer fzmap.Close()
	for k, v := range zMapMap {
		fzmap.WriteString("SrcIP: " + strconv.Itoa(int(k)) + "\n")
		for i, j := range v {
			fzmap.WriteString("\tPort: " + strconv.Itoa(int(i)) + "-->" + strconv.Itoa(int(j)) + "\n")
		}
		fzmap.WriteString("\n")
	}*/

	/* Format of scanMap:
	ip source -> ip destination -> count

	Format of scansSizes:
		ip source -> list of scan sizes

	*/
	for k := range scanMap {
		packetRateCheck(time.Now(), k, k)
	}

	fmt.Println("got here")
	for k, v := range scansSizes {
		fmt.Printf("source: %s, count: %d\n", strconv.Itoa(int(k)), v)
	}
	fmt.Println("and got here")

	/*
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
		}*/

	/* End of nothing stats */

	fmt.Printf("Total packets: %d", count)
}
