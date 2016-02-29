package main

import (
	"flag"
	"github.com/ChrisRx/gopacket"
	"github.com/ChrisRx/gopacket/layers"
	"github.com/ChrisRx/gopacket/pcap"
	"github.com/ChrisRx/gopacket/tcpassembly"
	elastigo "github.com/mattbaird/elastigo/lib"
	"github.com/oschwald/geoip2-golang"
	"log"
	"time"
)

const Version = "0.0.0"

var iface = flag.String("i", "eth0", "Interface to get packets from")
var fname = flag.String("r", "", "Filename to read from, overrides -i")
var output = flag.String("w", "", "Filename to write pcap output")
var outputDir = flag.String("o", "data", "Output directory")
var snaplen = flag.Int("S", 65535, "SnapLen for pcap packet capture")
var filter = flag.String("f", "tcp or udp", "BPF filter for pcap")
var verbose = flag.Bool("v", false, "Logs every packet in great detail")
var debugLog = flag.Bool("d", false, "Log debug information")
var eshost = flag.String("h", "localhost", "Elasticsearch ip/host")
var rollover = flag.Uint64("s", 100*1024*1024, "Number of bytes capture in each file (default: 100MB)")

type MongooseStruct struct {
	sniffer   *pcap.Handle
	writer    *PcapWriter
	assembler *tcpassembly.Assembler
	indexer   *elastigo.Conn
	gi        *geoip2.Reader
}

var Mongoose MongooseStruct

type Packet struct {
	Index              string    `json:"index"`
	Timestamp          time.Time `json:"ts"`
	File               string    `json:"file"`
	Position           int64     `json:"pos"`
	Length             int       `json:"length"`
	CaptureLength      int       `json:"capture_length"`
	NetworkLayerType   string    `json:"l2type"`
	TransportLayerType string    `json:"l3type"`
	SrcIP              string    `json:"srcip"`
	DstIP              string    `json:"dstip"`
	SrcPort            string    `json:"sport"`
	DstPort            string    `json:"dport"`
}

func (p *Packet) CaptureInfo() gopacket.CaptureInfo {
	return gopacket.CaptureInfo{
		Timestamp:     p.Timestamp,
		Length:        p.Length,
		CaptureLength: p.CaptureLength,
	}
}

func handlePacket(packet gopacket.Packet) error {
	pos, dir := Mongoose.writer.Tell()

	data := Packet{
		Index:            Hash(packet.String()),
		Timestamp:        packet.Metadata().Timestamp,
		File:             dir,
		Position:         pos,
		Length:           packet.Metadata().Length,
		CaptureLength:    packet.Metadata().CaptureLength,
		NetworkLayerType: packet.NetworkLayer().LayerType().String(),
	}
	if packet.TransportLayer() == nil {
		if *debugLog {
			log.Printf("Packet %v does not have layer 3\n", data.Index)
		}
	}
	data.TransportLayerType = packet.TransportLayer().LayerType().String()
	data.SrcIP = packet.NetworkLayer().NetworkFlow().Src().String()
	data.DstIP = packet.NetworkLayer().NetworkFlow().Dst().String()
	switch packet.TransportLayer().LayerType() {
	case layers.LayerTypeUDP:
		udp := packet.TransportLayer().(*layers.UDP)
		data.SrcPort = udp.SrcPort.String()
		data.DstPort = udp.DstPort.String()
	case layers.LayerTypeTCP:
		tcp := packet.TransportLayer().(*layers.TCP)
		Mongoose.assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp,
			data.Index, packet.Metadata().Timestamp)
		data.SrcPort = tcp.SrcPort.String()
		data.DstPort = tcp.DstPort.String()
	default:
		if *debugLog {
			log.Println("Unknown Layer 3")
		}
	}
	// log.Printf("App Layer: %v", packet.ApplicationLayer())

	_ = Mongoose.writer.WritePacket(data.CaptureInfo(), packet.Data())

	res, err := Mongoose.indexer.Index("mongoose", "packet", data.Index, nil, data)

	if err != nil {
		log.Println("Elasticsearch Error: ", err)
	}
	if *debugLog {
		log.Println("Response: ", res.Id)
	}
	return nil
}

func main() {
	flag.Parse()
	var handle *pcap.Handle
	var err error

	if *fname != "" {
		log.Printf("Reading from pcap dump %q", *fname)
		handle, err = pcap.OpenOffline(*fname)
	} else {
		log.Printf("Starting capture on interface %q", *iface)
		// handle, err = pcap.OpenLive(*iface, int32(*snaplen), true, pcap.BlockForever)
		handle, err = pcap.OpenLive(*iface, int32(*snaplen), true, pcap.BlockForever)
	}

	if err != nil {
		log.Fatal(err)
	}

	if err := handle.SetBPFFilter(*filter); err != nil {
		log.Fatal(err)
	}

	Mongoose.writer = &PcapWriter{
		Path:               *outputDir,
		Name:               *output,
		RolloverEveryBytes: *rollover,
	}
	defer Mongoose.writer.Close()

	err = Mongoose.writer.Rollover()
	if err != nil {
		log.Println("Writer error: ", err)
	}

	Mongoose.gi, err = geoip2.Open("GeoLite2-City.mmdb")
	if err != nil {
		log.Fatal(err)
	}
	defer Mongoose.gi.Close()

	if err != nil {
		log.Printf("Error: %s\n", err.Error())
	}

	streamFactory := tcpStreamFactory{}
	streamPool := tcpassembly.NewStreamPool(&streamFactory)
	Mongoose.assembler = tcpassembly.NewAssembler(streamPool)

	Mongoose.indexer = elastigo.NewConn()
	Mongoose.indexer.Domain = *eshost

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()
	ticker := time.Tick(time.Minute)
	for {
		select {
		case packet := <-packets:
			if packet == nil {
				Mongoose.assembler.FlushAll()
				return
			}

			if *verbose {
				log.Println(packet)
			}

			if packet.NetworkLayer() == nil {
				log.Println("Packet does not have layer 2")
				continue
			}

			_ = handlePacket(packet)

		case <-ticker:
			Mongoose.assembler.FlushOlderThan(time.Now().Add(time.Minute * -1))
		}
	}
}
