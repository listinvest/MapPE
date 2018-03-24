package main

import "path/filepath"
import "encoding/hex"
import "io/ioutil"
import "debug/pe"
import "strconv"
import "runtime"
import "errors"
import "bytes"
import "flag"
import "fmt"
import "os"

type ARGS struct {
	scrape 	bool
	verbose bool
	help 	bool
	ignore 	bool
}

type OptionalHeader struct {
	Magic                       uint16
	MajorLinkerVersion          uint8
	MinorLinkerVersion          uint8
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectory               [16]DataDirectory
}

type DataDirectory struct {
	VirtualAddress uint32
	Size           uint32
}

var args ARGS

func main() {

	runtime.GOMAXPROCS(runtime.NumCPU()) // Run faster !
	BANNER()

	flag.BoolVar(&args.scrape, "s", false, "Scrape PE headers.")
	flag.BoolVar(&args.verbose, "v", false, "Verbose output mode.")
	flag.BoolVar(&args.ignore, "ignore", false, "Ignore integrity check errors.")
	flag.BoolVar(&args.help, "h", false, "Display this message")
	flag.Parse()

	if len(os.Args) == 1 || args.help {
		flag.PrintDefaults()
		os.Exit(1)
	} 

	target := flag.Args()
	// Get the absolute path of the file
	abs, abs_err := filepath.Abs(target[0])
	ParseError(abs_err)
	file, err := pe.Open(abs)
	ParseError(err)
	verbose("\n[*] Valid \"PE\" signature.\n\n",0)

	RawFile, err2 := ioutil.ReadFile(abs)
	ParseError(err2)

	var opt OptionalHeader

	if file.Machine == 0x8664 {
		_opt := (file.OptionalHeader.(*pe.OptionalHeader64))
		opt.Magic = _opt.Magic
		opt.Subsystem = _opt.Subsystem
		opt.ImageBase = _opt.ImageBase
		opt.SizeOfImage =  _opt.SizeOfImage
		opt.SizeOfHeaders = _opt.SizeOfHeaders
		for i:=0; i<16; i++ {
			opt.DataDirectory[i].VirtualAddress = _opt.DataDirectory[i].VirtualAddress
			opt.DataDirectory[i].Size = _opt.DataDirectory[i].Size
		}
	}else{
		_opt := file.OptionalHeader.((*pe.OptionalHeader32))
		opt.Magic = _opt.Magic
		opt.Subsystem = _opt.Subsystem
		opt.ImageBase = uint64(_opt.ImageBase)
		opt.SizeOfImage =  _opt.SizeOfImage
		opt.SizeOfHeaders = _opt.SizeOfHeaders
		for i:=0; i<16; i++ {
			opt.DataDirectory[i].VirtualAddress = _opt.DataDirectory[i].VirtualAddress
			opt.DataDirectory[i].Size = _opt.DataDirectory[i].Size
		}
	}

	verbose("[-------------------------------------]\n",0)	
	verbose("[*] File Size: "+strconv.Itoa(len(RawFile))+" byte\n", 0)
	verbose("Machine:", uint64(file.FileHeader.Machine))
	verbose("Magic:", uint64(opt.Magic))
	verbose("Subsystem:", uint64(opt.Subsystem))
	verbose("Image Base:", uint64(opt.ImageBase))
	verbose("Size Of Image:", uint64(opt.SizeOfImage))
	verbose("Export Table:", uint64(opt.DataDirectory[0].VirtualAddress)+opt.ImageBase)
	verbose("Import Table:", uint64(opt.DataDirectory[1].VirtualAddress)+opt.ImageBase)
	verbose("Base Relocation Table:", uint64(opt.DataDirectory[5].VirtualAddress)+opt.ImageBase)
	verbose("Import Address Table:", uint64(opt.DataDirectory[12].VirtualAddress)+opt.ImageBase)
	verbose("[-------------------------------------]\n\n\n",0)

	var offset uint64 = opt.ImageBase
	Map := bytes.Buffer{}
	// Map the PE headers
	Map.Write(RawFile[0:int(opt.SizeOfHeaders)])
	offset += uint64(opt.SizeOfHeaders)

	for i := 0; i < len(file.Sections); i++ {
		// Append null bytes if there is a gap between sections or PE header
		for offset < (uint64(file.Sections[i].VirtualAddress)+opt.ImageBase) {
			Map.WriteString(string(0x00))
			offset += 1
		}
		// Map the section
		SectionData, err := file.Sections[i].Data()
		ParseError(err)
		Map.Write(SectionData)
		offset += uint64(file.Sections[i].Size)
		// Append null bytes until reaching the end of the virtual address of the section
		for offset < (uint64(file.Sections[i].VirtualAddress)+uint64(file.Sections[i].VirtualSize)+opt.ImageBase) {
			Map.WriteString(string(0x00))
			offset += 1
		}

	}

	for (offset-uint64(opt.ImageBase)) < uint64(opt.SizeOfImage) {
		Map.WriteString(string(0x00))
		offset += 1
	}
	verbose("[+] File mapping completed !\n",0)
	verbose("[*] Starting integrity checks...\n",0)

	// Perform integrity checks...
	verbose("[*] Checking image size ------------------------------>",0)
	if int(opt.SizeOfImage) != Map.Len() {
		if !args.ignore {
			ParseError(errors.New("Integrity check failed (Mapping size does not match the size of image header)\n[!] Try -ignore parameter."))
		}
		verbose(" [FAILED]\n",0)
	}else{
		verbose(" [OK]\n",0)
	}

	verbose("[*] Checking section alignment ----------------------->",0)
	for i:=0; i<len(file.Sections); i++ {
		for j:=0; j<int(file.Sections[i].Size/10); j++ {
			Buffer := Map.Bytes()
			if RawFile[int(int(file.Sections[i].Offset)+j)] != Buffer[int(int(file.Sections[i].VirtualAddress)+j)] {
				if !args.ignore {
					ParseError(errors.New("Integrity check failed (Broken section alignment)\n[!] Try -ignore parameter."))
				}
				verbose(" [FAILED]\n",0)
				i = len(file.Sections)+1
				break
			}	
		}
		if i == (len(file.Sections)-1) {
			verbose(" [OK]\n",0)
		} 
	}

	verbose("[*] Writing map file "+abs+".map\n",0)
	MapFile, MapFileErr := os.Create(abs+".map")
	ParseError(MapFileErr)
	if args.scrape {
		MapFile.Write(scrape(Map.Bytes()))
	}else{
		MapFile.Write(Map.Bytes())
	}
	MapFile.Close()

	fmt.Println("[+] File mapped into -> "+abs+".map")
}


func scrape(Map []byte) ([]byte){

	verbose("\n\n[*] Scraping PE headers...\n",0)

	if string(Map[:2]) == "MZ" {
		verbose(hex.Dump(Map[:2]),0)
		Map[0] = byte(0x00)
		Map[1] = byte(0x00)
	}

	if string(Map[64:66]) == "PE" {
		verbose(hex.Dump(Map[64:66]),0)
		Map[64] = byte(0x00)
		Map[65] = byte(0x00)
	}
	
	if string(Map[78:117]) == "This program cannot be run in DOS mode." {
		verbose(hex.Dump(Map[78:117]),0)
		for i:=0; i<40; i++ {
			Map[78+i] = byte(0x00)
		}
	}

	if string(Map[128:130]) == "PE" {
		verbose(hex.Dump(Map[128:130]),0)
		Map[128] = byte(0x00)
		Map[129] = byte(0x00)
	}

	for i:=66; i<0x1000; i++{
		if Map[i] == 0x2e && Map[i+1] < 0x7e && Map[i+1] > 0x21 {
			verbose(hex.Dump(Map[i:i+7]),0)
			for j:=0; j<7; j++{
				Map[i+j] = byte(0x00)
			}
		}
	}

	verbose("[+] Done scraping headers !\n\n",0)

	return Map
}


func ParseError(err error){
	if err != nil {
		fmt.Print("\n[!] ERROR: ",err,"\n")
		os.Exit(1)
	}
}

func verbose(str string, value uint64) {
	if args.verbose {

		if value == 0 {
			fmt.Print(str)
		}else {
			fmt.Printf("[*] "+str+" 0x%X\n", value)
		}
	}
}


func BANNER(){

	var banner = `                      _____________________
   _____ _____  ______\______   \_   _____/
  /     \\__  \ \____ \|     ___/|    __)_ 
 |  Y Y  \/ __ \|  |_> >    |    |        \
 |__|_|  (____  /   __/|____|   /_______  /
       \/     \/|__|                    \/ 
Author: Ege Balcı
Github: github.com/egebalci/mappe
`
	fmt.Println(banner)
}