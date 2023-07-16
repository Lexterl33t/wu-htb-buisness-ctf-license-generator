from pdb import pm
from miasm.jitter.csts import PAGE_READ, PAGE_WRITE
from miasm.analysis.sandbox import Sandbox_Win_x86_32
from miasm.core.locationdb import LocationDB
from miasm.os_dep.common import get_win_str_a, get_win_str_w
import os, time, sys, crcmod
# Insert here user defined methods

# Parse arguments
parser = Sandbox_Win_x86_32.parser(description="PE sandboxer")
parser.add_argument("filename", help="PE Filename")
parser.add_argument("shellcode", help="Shellcode file")
options = parser.parse_args()

def hashfunc(function, print_hash=True ):
  crc32_func = crcmod.mkCrcFun(0x11EDC6F41, initCrc=0, xorOut=0)
  h = crc32_func((function).encode('utf-8'))
  return h

def NtAllocateVirtualMemory(jitter):
	print("ok")
	jitter.cpu.EAX = 0

def ws2_32_connect(jitter):
	jitter.cpu.EAX = 0

def ws2_32_recv(jitter):
	jitter.cpu.EAX = 1
	print("recv")

def recv1(jitter):
	print(jitter.cpu.EAX)
	jitter.cpu.EAX = 8
	print("recv1")
	return True

def recv2(jitter):
	print(hex(jitter.cpu.EDX))
	jitter.vm.set_mem(jitter.cpu.EDX, b"\x13\x37\xCA\xFE\xBA\xBE\x04\x20")
	print("recv2")
	return True

def recv3(jitter):
	jitter.cpu.EAX = 538
	print("recv3")
	return True

def recvshellcode(jitter):
	jitter.vm.set_mem(jitter.cpu.EDX, b"\xe7\xac\xbf\x87\xc2\xd1\xb4\x0a\x9e\x40\xbf\x86\xc2\xb5\xd2\x7f\x66\x40\xbf\x0d\x82\xdd\xf8\x0f\x72\xcb\xff\x96\x4b\x94\x83\xc4\x2e\x7c\x34\xca\xca\xa9\x72\x8e\xef\x0d\x53\x0d\x9b\xf1\x72\x8c\xef\x81\x8e\x79\x49\xe5\xc8\x4e\xa8\x71\x6d\xb7\x02\x7d\x72\x8d\x5a\x40\xca\x7f\x43\x2b\x82\x46\x66\x40\xcb\x85\x85\x3a\x96\xc4\x23\xb0\x34\xf3\x2e\x5a\x05\x6b\x67\x86\xb0\x31\xf6\xaf\xf8\x02\x8a\xcb\xf6\x9a\xc3\x10\xf8\x7b\xd7\x41\x79\x0f\x2b\x52\x9a\x6f\x37\xc9\x56\x05\x2b\xf5\x22\xb0\xb0\xf8\x99\xe0\xad\xad\x23\xf7\x6c\x76\x86\xe3\x92\x69\x15\x6e\x47\x6c\xef\x3e\xa4\xdb\x56\x68\x36\xf8\x9f\x8c\xa3\xf6\x23\xf7\x47\x4a\x93\xe3\x92\x69\x5f\x45\x51\x60\xef\x3e\xc8\xb7\x12\x69\x36\xf8\x9e\xbb\xa3\xf0\x23\xf7\x5d\x25\x9e\x8c\x92\x69\x17\x6e\x06\x4a\xef\x3f\xc2\xd1\x73\x4f\xdc\x6c\xbf\x86\xc2\x51\x47\x43\x33\xc3\x7e\x87\xfb\x00\x06\xba\xef\x25\x6f\xec\xee\x58\x16\x83\xa1\x05\x7f\x86\xc2\xd1\x73\x88\x23\xfc\xbf\x86\xc2\xd1\xb4\x0a\xde\x40\xbf\x86\xc2\x5a\x0e\x93\xef\xae\x3c\x68\x86\x5a\x3e\xaf\xdd\x40\xbf\x86\xc2\x58\xab\x7e\xb4\x11\x06\x8e\xc2\xd1\x73\xb8\x97\x19\x36\x56\xc3\x21\xf9\x4f\xef\xba\xbe\x5c\x48\xc3\x43\x9f\xef\xba\xbe\x5c\x4a\xd3\x30\x76\xad\x34\xbd\x6d\x1a\x69\x78\x53\x3d\x4c\xef\x3e\xd8\x89\x6f\x14\x36\xf8\xe6\x9d\xf5\xc9\x23\xf7\x7e\x77\xa3\x86\x92\x69\x44\x4c\x3d\x1b\xef\x3e\xd8\x8a\x77\x5e\x36\xf8\xbb\xb1\xd9\xcc\x23\xf7\x51\x5f\xe6\x82\x92\x69\x6f\x4f\x3f\x5b\xef\x3f\xc2\xd1\x73\x4f\xdc\x64\xbf\x86\xc2\x51\x47\x43\x0e\xc3\x7e\x87\xfb\x00\x06\xba\xef\x25\x3f\xec\xe6\x58\xd6\x33\x99\xbf\x40\x0d\xbf\x0d\xfa\xa1\xe7\xae\x3f\x86\xc2\xd1\xf8\x79\xed\x0d\x5f\x3d\xc2\xd1\x73\x4f\xef\x98\x8e\x54\x93\x68\x57\x4f\x66\x40\x48\x77\x9b\x58\xa3\x4e\x96\xca\xbf\x0f\x38\xd0\xa9\xc5\x74\x40\x6f\x0f\x38\xd0\xa9\xc7\x64\x03\x86\x4d\xb6\xd3\x98\x97\xed\x3d\x63\x0d\xb7\x01\xf8\x02\x86\xfb\xbf\x86\xc2\xd1\xfa\x97\x57\x92\xee\x3f\xee\xd1\x73\x4f\x91\xb1\xe6\x0f\x12\xd0\x83\xc5\x66\xc9\x45\x87\x18\x5b\x61\x7f\xb6\xc9\x45\x87\x18\x59\x71\x0c\x5f\x8b\xcb\x84\x29\x09\x19\x4f\x0c\x44\x36\x6e\x41\x39\x53\x1f\xed\x05\x47\xd6\x49\x84\xcb\xb0\xb4\x2a\xbf\x0d\x87\x31\x23\xc4\x23\x9c\xef\x0d\x87\x29\x23\xc4\x33\xf8\x40\x54\x43\x15\x73\x4e\x66\x40")
	return True

def ws2_32_send(jitter):
	jitter.cpu.EAX = 1
	print("send")

def ws2_32_socket(jitter):
	jitter.cpu.EAX = 0x3

def ws2_32_gethostbyname(jitter):
	jitter.vm.add_memory_page(0x11111111,PAGE_READ | PAGE_WRITE, b"\x00"*100)
	jitter.vm.set_mem(0x11111111+0x14, b"\x7f\x00\x00\x01")
	jitter.cpu.EAX = 0x11111111
	print(hex(jitter.cpu.EAX))

def code_sentinelleCRC32(jitter):
	#print(get_win_str_a(jitter, jitter.cpu.ESI, 0x40))
	if jitter.cpu.ESI > 0:
		jitter.cpu.EDX = hashfunc(chr(jitter.cpu.EAX)+get_win_str_a(jitter, jitter.cpu.ESI, 0x40))
		if jitter.cpu.EDX == 0xB128F4E7 or jitter.cpu.EDX == 0xF3596BDF or jitter.cpu.EDX == 0x95B93110 or jitter.cpu.EDX == 0x6C81586F:
			print(hex(jitter.cpu.EDX),get_win_str_a(jitter, jitter.cpu.ESI, 0x40))
	#print(hex(jitter.cpu.EDX))
	return True 


def code_sentinelle1(jitter):
	jitter.cpu.EAX = 0x11111111
	return True

def saveshellcode(jitter):
	f = open("shellcodeFinal.bin", "wb")
	f.write(jitter.vm.get_mem(jitter.cpu.ECX, 65535))
	f.close()
	print("Extraction done.")
	return True

def code_sentinelle(jitter):
	#print(jitter.cpu.ECX)
	#print(hex(jitter.cpu.ESI))
	#print(chr(jitter.cpu.EAX))
	#print(jitter.libs.fad2cname[jitter.cpu.EDX])
	#print(hex(jitter.cpu.EAX))
	print(jitter.vm.get_mem(jitter.cpu.ECX, 65535))

	#print(get_win_str_a(jitter, jitter.cpu.ESP + jitter.cpu.ECX, 0x1), end='')
	#print(get_win_str_a(jitter, jitter.cpu.ESI, 0x40), end='')
	#ree-windows-license.uwu
	#hellgen
	#print(get_win_str_a(jitter, 0x40000e8, 40))
	return False


# Create sandbox
loc_db = LocationDB()
sb = Sandbox_Win_x86_32(loc_db, options.filename, options, globals())

data = open(options.shellcode,'rb').read()
run_addr  = 0x4000000

#print(sb.jitter.user_globals)
sb.jitter.user_globals['ws2_32_WSAStartup']= sb.jitter.user_globals['wsock32_WSAStartup']
sb.jitter.user_globals['ntdll_NtAllocateVirtualMemory']= NtAllocateVirtualMemory
sb.jitter.user_globals['ws2_32_socket'] = ws2_32_socket
sb.jitter.user_globals['ws2_32_gethostbyname'] = ws2_32_gethostbyname
sb.jitter.user_globals['ws2_32_connect'] = ws2_32_connect
sb.jitter.user_globals['ws2_32_send'] = ws2_32_send
sb.jitter.user_globals['ws2_32_recv'] = ws2_32_recv
sb.jitter.vm.add_memory_page(run_addr, PAGE_READ | PAGE_WRITE, data)
sb.jitter.vm.add_memory_page(sb.jitter.cpu.EBP+0xffffff00, PAGE_READ | PAGE_WRITE, b"\x00"*0x1000)
#sb.jitter.vm.add_memory_page(run_addr+0x186, PAGE_READ | PAGE_WRITE, b"\x00"*0x1000)
#sb.jitter.vm.add_memory_page(0x7FFDF000+0x64, PAGE_READ | PAGE_WRITE,  b"\x00\x00\x00\x03")
#sb.jitter.add_breakpoint(run_addr+0x274, code_sentinelle)
#sb.jitter.add_breakpoint(run_addr+0x280, code_sentinelle)
sb.jitter.add_breakpoint(run_addr+0x1df, code_sentinelle1)
#sb.jitter.add_breakpoint(run_addr+0x1f8, code_sentinelle)
sb.jitter.vm.add_memory_page(0x100007f, PAGE_READ | PAGE_WRITE, b"\x90"*4)
sb.jitter.vm.add_memory_page(0x140000, PAGE_READ | PAGE_WRITE, b"\x90"*100000)
sb.jitter.vm.add_memory_page(0x7ffdf002, PAGE_READ | PAGE_WRITE, b"\x90"*4)
sb.jitter.vm.set_mem(run_addr+0x3b5,b"\x90"*7)
sb.jitter.add_breakpoint(run_addr+0x3bc, code_sentinelleCRC32)
sb.jitter.add_breakpoint(run_addr+0x238, recv1)
sb.jitter.add_breakpoint(run_addr+0x239, recv2)
sb.jitter.add_breakpoint(run_addr+0x302, recv3)
sb.jitter.add_breakpoint(run_addr+0x31B, recvshellcode)
sb.jitter.add_breakpoint(run_addr+0x4B2, saveshellcode)
#sb.jitter.add_breakpoint(run_addr+0x35F, saveshellcode)
#sb.jitter.add_breakpoint(run_addr+0x4A2, saveshellcode)

# Run
sb.run(run_addr)

