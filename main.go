package main

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type MEMORY_BASIC_INFORMATION struct {
	BaseAddress       uint64
	AllocationBase    uint64
	AllocationProtect uint32
	Allignment        uint32
	RegionSize        uint64
	State             uint32
	Protect           uint32
	Type              uint32
	Allignment2       uint32
}

type SystemInfo struct {
	ProcessorArchitecture     ProcessorArchitecture
	Reserved                  uint16
	PageSize                  uint32
	MinimumApplicationAddress uintptr
	MaximumApplicationAddress uintptr
	ActiveProcessorMask       uint64
	NumberOfProcessors        uint32
	ProcessorType             ProcessorType
	AllocationGranularity     uint32
	ProcessorLevel            uint16
	ProcessorRevision         uint16
}

type ProcessorArchitecture uint16
type ProcessorType uint32

type memblock struct {
	prochandle uintptr
	baseaddr   uint64
	blocksize  uint64
	membytes   []byte
}

type MemLoc struct {
	prochandle uintptr
	address    uintptr
	searchstr  string
}

func main() {
	input := bufio.NewReader(os.Stdin)
	var prochandle uintptr
	var blocks []memblock
	var memlocs []MemLoc
	for {
		fmt.Printf("> ")
		instring, err := input.ReadString('\n')
		if err != nil {
			log.Println(err)
		}
		splitter := strings.Split(instring, " ")
		switch strings.TrimSpace(splitter[0]) {
		case "open":
			if len(splitter) == 2 {
				prochandle = opentarget(strings.TrimSpace(splitter[1]))
			} else {
				fmt.Println("usage: open procname.exe")
			}
		case "search":
			if len(splitter) == 3 {
				switch strings.TrimSpace(splitter[2]) {
				case "unicode":
					memlocs = append(memlocs, SearchMemoryUnicode(prochandle, blocks, splitter[1])...)
				}
			}
		case "readmem":
			blocks = readmemory(prochandle)
		case "writemem":
			if len(splitter) == 3 {
				locindex, _ := strconv.Atoi(splitter[1])
				EditBytes(prochandle, memlocs[locindex], []byte(strings.TrimSpace(splitter[2])))
			}
		case "list":
			switch strings.TrimSpace(splitter[1]) {
			case "locations":
				fmt.Println(memlocs)
			}
		}
	}
}

func SearchMemoryUnicode(prochandle uintptr, blocks []memblock, target string) (foundlocs []MemLoc) {
	uniform := []byte(target)
	var unicodebytes []byte
	for x := range uniform {
		unicodebytes = append(unicodebytes, uniform[x])
		unicodebytes = append(unicodebytes, 0)
	}

	var scanlocs []MemLoc
	for j := range blocks {
		for h := 0; h < (len(blocks[j].membytes) - len(unicodebytes)); h++ {
			if bytes.Compare((blocks[j].membytes[h:h+len(unicodebytes)]), unicodebytes) == 0 {
				newloc := MemLoc{
					prochandle: prochandle,
					address:    uintptr(blocks[j].baseaddr + uint64(h)),
					searchstr:  target,
				}
				scanlocs = append(scanlocs, newloc)
				fmt.Printf("found %s at address: %#0x \n", unicodebytes, blocks[j].baseaddr+uint64(h))
			}
		}
	}
	return scanlocs
}

func readmemory(prochandle uintptr) (blocks []memblock) {
	k32 := syscall.NewLazyDLL("Kernel32.dll")

	GetSystenInfo := k32.NewProc("GetSystemInfo")
	retsysinfo := SystemInfo{}
	_, _, err := GetSystenInfo.Call(uintptr(unsafe.Pointer(&retsysinfo)))
	if err != nil {
		if err.Error() != "The operation completed successfully." {
			log.Println(err)
		}
	}

	VirtualQueryEx := k32.NewProc("VirtualQueryEx")
	ReadProcessMemory := k32.NewProc("ReadProcessMemory")

	maxaddr := retsysinfo.MaximumApplicationAddress
	var queryaddr uintptr = 0
	blocks = []memblock{}
	for queryaddr < maxaddr {
		var meminfo MEMORY_BASIC_INFORMATION = MEMORY_BASIC_INFORMATION{}

		_, _, err := VirtualQueryEx.Call(uintptr(prochandle), queryaddr, uintptr(unsafe.Pointer(&meminfo)), uintptr(unsafe.Sizeof(meminfo)))
		if err != nil {
			if err.Error() != "The operation completed successfully." {
				log.Println(err)
			}
		}
		if meminfo.State == windows.MEM_COMMIT {
			switch meminfo.Protect {
			case windows.PAGE_WRITECOPY, windows.PAGE_READWRITE, windows.PAGE_EXECUTE_READWRITE, windows.PAGE_EXECUTE_WRITECOPY:
				retbuf := make([]byte, meminfo.RegionSize)
				var retsize uintptr = 0
				_, _, err := ReadProcessMemory.Call(uintptr(prochandle), uintptr(meminfo.BaseAddress), uintptr(unsafe.Pointer(&retbuf[0])), uintptr(meminfo.RegionSize), uintptr(unsafe.Pointer(&retsize)))
				if err != nil {
					if err.Error() != "The operation completed successfully." {
						log.Println(err)
					}
				}
				newblock := memblock{
					prochandle: uintptr(prochandle),
					baseaddr:   meminfo.BaseAddress,
					blocksize:  meminfo.RegionSize,
					membytes:   retbuf,
				}
				blocks = append(blocks, newblock)
			}
		}
		queryaddr += uintptr(meminfo.RegionSize)

	}
	fmt.Println(len(blocks))
	return blocks
}

func EditBytes(prochandle uintptr, loc MemLoc, overwrite []byte) {

	var unicodebytes []byte
	for x := range overwrite {
		unicodebytes = append(unicodebytes, overwrite[x])
		unicodebytes = append(unicodebytes, 0)
	}

	k32 := syscall.NewLazyDLL("Kernel32.dll")
	WriteProcessMemory := k32.NewProc("WriteProcessMemory")
	var retbytes uint64
	writeret, _, err := WriteProcessMemory.Call(prochandle, loc.address, uintptr(unsafe.Pointer(&unicodebytes[0])), uintptr(unsafe.Sizeof(unicodebytes)), uintptr(unsafe.Pointer(&retbytes)))
	if err != nil {
		log.Println(err)
	}
	fmt.Println(writeret)
}

func opentarget(procname string) (prochandle uintptr) {
	snaphandle, err := windows.CreateToolhelp32Snapshot(2, 0)
	if err != nil {
		log.Println(err)
	}
	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	err = windows.Process32First(snaphandle, &entry)
	if err != nil {
		log.Println(err)
	}
	var targpid uint32 = 0
	for {
		entry = windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
		err = windows.Process32Next(snaphandle, &entry)
		if err == windows.ERROR_NO_MORE_FILES {
			break
		}
		if windows.UTF16ToString(entry.ExeFile[:]) == procname {
			targpid = entry.ProcessID
			break
		}

	}
	if targpid != 0 {
		fmt.Printf("Found %s at pid: %d\n", procname, targpid)
	} else {
		fmt.Println("none found!")
	}
	winprochandle, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ|windows.PROCESS_VM_WRITE|windows.PROCESS_VM_OPERATION, false, targpid)
	if err != nil {
		log.Println(err)
	}
	return uintptr(winprochandle)
}
