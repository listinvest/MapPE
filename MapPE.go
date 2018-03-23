package main

import "path/filepath"
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

	integrity bool
}

type ImportDirectory struct {
	OriginalFirstThunk uint32
	TimeDateStamp      uint32
	ForwarderChain     uint32
	Name               uint32
	FirstThunk         uint32
	// contains filtered or unexported fields
}

var args ARGS

func main() {


	runtime.GOMAXPROCS(runtime.NumCPU()) // Run faster !
	flag.BoolVar(&args.scrape, "s", false, "Scrape PE headers.")
	flag.BoolVar(&args.verbose, "v", false, "Verbose output mode.")
	flag.BoolVar(&args.verbose,"verbose", false, "Verbose output mode.")
	flag.BoolVar(&args.ignore, "ignore", false, "Ignore integrity check errors.")
	flag.BoolVar(&args.help, "h", false, "Display this message")
	flag.Parse()

	if len(os.Args) == 1 || args.help {
		HELP()
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

	opt := file.OptionalHeader.(*pe.OptionalHeader32)
	
	// if file.Machine == 0x8664 {
	// 	opt = file.OptionalHeader.(*pe.OptionalHeader64)
	// }

	verbose("[-------------------------------------]\n",0)	
	verbose("[*] File Size: "+strconv.Itoa(len(RawFile))+" byte\n", 0)
	verbose("Machine:", uint32(file.FileHeader.Machine))
	verbose("Magic:", uint32(opt.Magic))
	verbose("Subsystem:", uint32(opt.Subsystem))
	verbose("Image Base:", uint32(opt.ImageBase))
	verbose("Size Of Image:", uint32(opt.SizeOfImage))
	verbose("Export Table:", uint32(opt.DataDirectory[0].VirtualAddress+opt.ImageBase))
	verbose("Import Table:", uint32(opt.DataDirectory[1].VirtualAddress+opt.ImageBase))
	verbose("Base Relocation Table:", uint32(opt.DataDirectory[5].VirtualAddress+opt.ImageBase))
	verbose("Import Address Table:", uint32(opt.DataDirectory[12].VirtualAddress+opt.ImageBase))
	verbose("[-------------------------------------]\n\n\n",0)

	var offset uint32 = opt.ImageBase
	Map := bytes.Buffer{}
	// Map the PE headers
	Map.Write(RawFile[0:int(opt.SizeOfHeaders)])
	offset += opt.SizeOfHeaders

	for i := 0; i < len(file.Sections); i++ {
		// Append null bytes if there is a gap between sections or PE header
		for offset < (file.Sections[i].VirtualAddress + opt.ImageBase) {
			Map.WriteString(string(0x00))
			offset += 1
		}
		// Map the section
		SectionData, err := file.Sections[i].Data()
		ParseError(err)
		Map.Write(SectionData)
		offset += file.Sections[i].Size
		// Append null bytes until reaching the end of the virtual address of the section
		for offset < (file.Sections[i].VirtualAddress + file.Sections[i].VirtualSize + opt.ImageBase) {
			Map.WriteString(string(0x00))
			offset += 1
		}

	}

	for (offset - opt.ImageBase) < opt.SizeOfImage {
		Map.WriteString(string(0x00))
		offset += 1
	}
	verbose("[+] File mapping completed !\n",0)
	verbose("[*] Starting integrity checks...\n",0)

	// Perform integrity checks...
	args.integrity = true 

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

	verbose("[*] Writing map file "+abs+".map",0)
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
	
	verbose("[>] "+string(Map[0])+string(Map[1])+"\n",0)
	Map[0] = byte(0x00)
	Map[1] = byte(0x00)
	verbose("[>] "+string(Map[64])+string(Map[65])+"\n",0)
	Map[64] = byte(0x00)
	Map[65] = byte(0x00)
	
	for i:=66; i<0x1000; i++{
		if Map[i] == 0x2e && Map[i+1] < 0x7e && Map[i+1] > 0x21 {
			verbose("[>] "+string(Map[i:i+7])+"\n",0)
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

func verbose(str string, value uint32) {
	if args.verbose {

		if value == 0 {
			fmt.Print(str)
		}else {
			fmt.Printf("[*] "+str+" 0x%X\n", value)
		}
	}
}


func HELP(){

	var banner = `
                      _____________________
   _____ _____  ______\______   \_   _____/
  /     \\__  \ \____ \|     ___/|    __)_ 
 |  Y Y  \/ __ \|  |_> >    |    |        \
 |__|_|  (____  /   __/|____|   /_______  /
       \/     \/|__|                    \/ 
Author: Ege Balcı
Github: github.com/egebalci/mappe

Usage of `+os.Args[0]+`:
-ignore
	Ignore integrity check errors.
-s	Scrape PE headers.
-v	Verbose output mode.
-verbose
	Verbose output mode.

	`
	fmt.Println(banner)
}