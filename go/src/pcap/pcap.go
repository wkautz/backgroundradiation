package main

// Use tcpdump to create a test file
// tcpdump -w test.pcap
// or use the example above for writing pcap files

import (
    "fmt"
    "github.com/google/gopacket"
    "github.com/google/gopacket/pcap"
    "github.com/google/gopacket/layers"
    "log"
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
    if err != nil { log.Fatal(err) }
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