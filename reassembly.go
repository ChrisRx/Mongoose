package main

import (
    "log"
    "time"
    "net"
    "strings"
    "github.com/ChrisRx/gopacket"
    "github.com/ChrisRx/gopacket/tcpassembly"
    "github.com/oschwald/geoip2-golang"
)

type Stream struct {
    Index               string                `json:"index"`
    FirstTimestamp      time.Time             `json:"startts"`
    LastTimestamp       time.Time             `json:"endts"`
    FirstPacket         string                `json:"first"`
    LastPacket          string                `json:"last"`
    Type                string                `json:"type"`
    PacketCount         int64                 `json:"npackets"`
    Bytes               int                   `json:"bytes"`
    SrcIP               string                `json:"srcip"`
    DstIP               string                `json:"dstip"`
    SrcPort             string                `json:"sport"`
    DstPort             string                `json:"dport"`
    Payload             []byte                `json:"payload"`
}

type tcpStreamFactory struct{}

type tcpStream struct {
    net, transport                      gopacket.Flow
    bytes, npackets, outOfOrder, skipped int64
    start, end                          time.Time
    sawStart, sawEnd                    bool
    payload	                            []byte
    first, last                         string
    previous string
    packets []string
}

func (factory *tcpStreamFactory) New(net, transport gopacket.Flow, index string) tcpassembly.Stream {
    s := &tcpStream{
        net:       net,
        transport: transport,
        start:     time.Now(),
    }
    s.first = index
    s.last = s.first
    s.previous = s.last
    s.end = s.start
    s.packets = append(s.packets, index)
    return s
}

func (s *tcpStream) Reassembled(reassemblies []tcpassembly.Reassembly) {
    for _, reassembly := range reassemblies {
        index := reassembly.Index
        if *debugLog {
            log.Println("Previous: ", s.previous)
            log.Println("Current: ", index)
        }
        s.packets = append(s.packets, index)
        // Mongoose.indexer.Index("mongoose", "packet", s.previous, map[string]interface{} {"next": reassembly.Index})
        s.last = index
        s.previous = s.last
        if reassembly.Seen.Before(s.end) {
            s.outOfOrder++
        } else {
            s.end = reassembly.Seen
        }
        s.bytes += int64(len(reassembly.Bytes))
        s.payload = append(s.payload, reassembly.Bytes...)
        s.npackets += 1
        if reassembly.Skip > 0 {
            s.skipped += int64(reassembly.Skip)
        }
        s.sawStart = s.sawStart || reassembly.Start
        s.sawEnd = s.sawEnd || reassembly.End
    }
}

func GeoIPLookupFromString(s string) (*geoip2.City, error) {
    ip := net.ParseIP(s)
    record, err := Mongoose.gi.City(ip)
    if err != nil {
        return nil, err
    }
    return record, nil
}

var HTTPMethods = []string {
    "GET",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
}
var HTTPVerions = []string {
    "HTTP/1.0",
    "HTTP/1.1",
    "HTTP/2",
}
func (s *tcpStream) ReassemblyComplete() {
    if *debugLog {
        log.Printf("Reassembled: %v:%v", s.net, s.transport)
        log.Printf("Stream finished: %v -> %v", s.first, s.last)
    }

    for _, method := range HTTPMethods {
        if strings.HasPrefix(string(s.payload[0:6]), method) {
            s.IndexHttpStream()
            return
        }
    }
    for _, version := range HTTPVerions {
        if strings.HasPrefix(string(s.payload[0:8]), version) {
            s.IndexHttpStream()
            return
        }
    }
    s.IndexStream()
}

func (s *tcpStream) IndexStream() {
    sport, dport := s.transport.Endpoints()
    // log.Println("Type: ", s.net.EndpointType())
    streamIndex := Hash(s.first, s.last)
    stream := Stream{
        Index: streamIndex,
        FirstTimestamp: s.start,
        LastTimestamp: s.end,
        FirstPacket: s.first,
        LastPacket: s.last,
        PacketCount: s.npackets,
        Bytes: len(s.payload),
        SrcIP: s.net.Src().String(),
        DstIP: s.net.Dst().String(),
        SrcPort: sport.String(),
        DstPort: dport.String(),
    }
    Mongoose.indexer.Index("mongoose", "stream", streamIndex, nil, stream)
    recordSrc, err := GeoIPLookupFromString(s.net.Src().String())
    if err != nil {
        log.Fatal(err)
    }
    if recordSrc != nil {
        if *debugLog {
            log.Printf("Country: %s (%s)\n", recordSrc.Country.Names["en"], recordSrc.Country.IsoCode)
            log.Printf("City: %s\n", recordSrc.City.Names["en"])
            for _, s := range recordSrc.Subdivisions {
                log.Printf("Subdivision: %v\n", s.Names["en"])
            }
            log.Printf("Postal Code: %s\n", recordSrc.Postal.Code)
            log.Printf("Lat/Long: %v, %v\n", recordSrc.Location.Latitude, recordSrc.Location.Longitude)
        }
    }

    recordDst, err := GeoIPLookupFromString(s.net.Dst().String())
    if err != nil {
        log.Fatal(err)
    }
    if recordDst != nil {
        if *debugLog {
            log.Printf("Country: %s (%s)\n", recordDst.Country.Names["en"], recordDst.Country.IsoCode)
            log.Printf("City: %s\n", recordDst.City.Names["en"])
            for _, s := range recordDst.Subdivisions {
                log.Printf("Subdivision: %v\n", s.Names["en"])
            }
            log.Printf("Postal Code: %s\n", recordDst.Postal.Code)
            log.Printf("Lat/Long: %v, %v\n", recordDst.Location.Latitude, recordDst.Location.Longitude)
        }
    }
}

func (s *tcpStream) IndexHttpStream() {
    sport, dport := s.transport.Endpoints()
    // log.Println("Type: ", s.net.EndpointType())
    streamIndex := Hash(s.first, s.last)
    stream := Stream{
        Index: streamIndex,
        FirstTimestamp: s.start,
        LastTimestamp: s.end,
        FirstPacket: s.first,
        LastPacket: s.last,
        Type: "HTTP",
        PacketCount: s.npackets,
        Bytes: len(s.payload),
        SrcIP: s.net.Src().String(),
        DstIP: s.net.Dst().String(),
        SrcPort: sport.String(),
        DstPort: dport.String(),
        Payload: s.payload,
    }
    Mongoose.indexer.Index("mongoose", "stream", streamIndex, nil, stream)
    recordSrc, err := GeoIPLookupFromString(s.net.Src().String())
    if err != nil {
        log.Fatal(err)
    }
    if recordSrc != nil {
        if *debugLog {
            log.Printf("Country: %s (%s)\n", recordSrc.Country.Names["en"], recordSrc.Country.IsoCode)
            log.Printf("City: %s\n", recordSrc.City.Names["en"])
            for _, s := range recordSrc.Subdivisions {
                log.Printf("Subdivision: %v\n", s.Names["en"])
            }
            log.Printf("Postal Code: %s\n", recordSrc.Postal.Code)
            log.Printf("Lat/Long: %v, %v\n", recordSrc.Location.Latitude, recordSrc.Location.Longitude)
        }
    }

    recordDst, err := GeoIPLookupFromString(s.net.Dst().String())
    if err != nil {
        log.Fatal(err)
    }
    if recordDst != nil {
        if *debugLog {
            log.Printf("Country: %s (%s)\n", recordDst.Country.Names["en"], recordDst.Country.IsoCode)
            log.Printf("City: %s\n", recordDst.City.Names["en"])
            for _, s := range recordDst.Subdivisions {
                log.Printf("Subdivision: %v\n", s.Names["en"])
            }
            log.Printf("Postal Code: %s\n", recordDst.Postal.Code)
            log.Printf("Lat/Long: %v, %v\n", recordDst.Location.Latitude, recordDst.Location.Longitude)
        }
    }
}
