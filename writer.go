package main

import (
	"fmt"
	"strconv"
	"os"
	"path/filepath"
	"log"
	"time"
	"github.com/ChrisRx/gopacket"
	"github.com/ChrisRx/gopacket/layers"
	"github.com/ChrisRx/gopacket/pcapgo"
)

type PcapWriter struct {
	Path                  string
	Name                  string
	OutputFile            *os.File
	Writer                *pcapgo.Writer
	RolloverEveryBytes    uint64

	currentFile           string
	currentSize           uint64
}


func (w *PcapWriter) checkSize() bool {
	if w.currentSize >= w.RolloverEveryBytes {
		return true
	}
	return false
}

func (w *PcapWriter) Tell() (int64, string){
	pos, err := w.Writer.Seek(0, 1)
	if err != nil {
		log.Println("Seek didn't work")
	}
	dir, _ := filepath.Abs(w.currentFile)
	return pos, dir
}

func (w *PcapWriter) WritePacket(ci gopacket.CaptureInfo, data []byte) error {
	if w.checkSize() {
		err := w.Rollover()
		if err != nil {
			return err
		}
	}
	w.currentSize += uint64(len(data))
	w.Writer.WritePacket(ci, data)
	return nil
}

func (w *PcapWriter) Exists(path string) bool {
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return true
}

func (w *PcapWriter) Rollover() error{
	if w.OutputFile != nil {
		if err := w.Close(); err != nil {
			return err
		}
	}
	if w.Path != "" {
		dir, _ := filepath.Abs(w.Path)
		if !w.Exists(dir) {
			log.Printf("Making directory %v", w.Path)
			if err := os.Mkdir(dir, 0755); err != nil {
				return err
			}
		}
	}
	currentTime := time.Now().UnixNano()
	fileName := fmt.Sprintf("%s.%s.pcap", w.Name, strconv.FormatInt(currentTime, 10))
	filePath := filepath.Join(w.Path, fileName)
	w.currentFile = filePath
	log.Printf("Writing pcap to %q", filePath)
	f, err := os.Create(filePath)
	if err != nil {
		return err
	}
	writer := pcapgo.NewWriter(f)
	writer.WriteFileHeader(65535, layers.LinkTypeEthernet)
	w.Writer = writer
	w.OutputFile = f
	w.currentSize = 0
	return nil
}

func (w *PcapWriter) Close() error {
	if err := w.OutputFile.Close(); err != nil {
		return err
	}
	return nil
}
