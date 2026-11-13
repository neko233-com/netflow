//go:build ignore

// Build the application's square PNGs and MSI icon from the source artwork.
package main

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/png"
	"log"
	"os"

	"golang.org/x/image/draw"
)

func main() {
	f, err := os.Open("design/netflow-logo-source.png")
	if err != nil {
		log.Fatal(err)
	}
	src, err := png.Decode(f)
	if err != nil {
		log.Fatal(err)
	}
	_ = f.Close()
	bounds := src.Bounds()
	minX, minY, maxX, maxY := bounds.Max.X, bounds.Max.Y, bounds.Min.X, bounds.Min.Y
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			_, _, _, alpha := src.At(x, y).RGBA()
			if alpha > 0x2000 {
				if x < minX {
					minX = x
				}
				if x > maxX {
					maxX = x
				}
				if y < minY {
					minY = y
				}
				if y > maxY {
					maxY = y
				}
			}
		}
	}
	if maxX <= minX || maxY <= minY {
		log.Fatal("logo contains no visible pixels")
	}
	width, height := maxX-minX+1, maxY-minY+1
	size := width
	if height > size {
		size = height
	}
	size = size * 115 / 100
	cx, cy := (minX+maxX)/2, (minY+maxY)/2
	crop := image.Rect(cx-size/2, cy-size/2, cx-size/2+size, cy-size/2+size)
	for _, target := range []struct {
		path string
		size int
	}{{"resources/icon.png", 1024}, {"internal/app/assets/tray.png", 64}, {"internal/ui/assets/netflow.png", 64}} {
		img := image.NewNRGBA(image.Rect(0, 0, target.size, target.size))
		draw.CatmullRom.Scale(img, img.Bounds(), src, crop, draw.Over, nil)
		out, err := os.Create(target.path)
		if err != nil {
			log.Fatal(err)
		}
		if err := png.Encode(out, img); err != nil {
			log.Fatal(err)
		}
		_ = out.Close()
	}
	img := image.NewNRGBA(image.Rect(0, 0, 256, 256))
	draw.CatmullRom.Scale(img, img.Bounds(), src, crop, draw.Over, nil)
	var data bytes.Buffer
	if err := png.Encode(&data, img); err != nil {
		log.Fatal(err)
	}
	out, err := os.Create("resources/icon.ico")
	if err != nil {
		log.Fatal(err)
	}
	defer out.Close()
	for _, value := range []uint16{0, 1, 1} {
		_ = binary.Write(out, binary.LittleEndian, value)
	}
	_, _ = out.Write([]byte{0, 0, 0, 0})
	_ = binary.Write(out, binary.LittleEndian, uint16(1))
	_ = binary.Write(out, binary.LittleEndian, uint16(32))
	_ = binary.Write(out, binary.LittleEndian, uint32(data.Len()))
	_ = binary.Write(out, binary.LittleEndian, uint32(22))
	_, _ = data.WriteTo(out)
}
