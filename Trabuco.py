import pty, sys, subprocess, os, re, argparse

# Colors to use in print
RED = "\033[31m"
GREEN = "\x1b[38;5;83m"
YELLOW = "\x1b[38;5;226m"
ORANGE = "\033[38;5;208m"
BLUE = "\033[34m"
PURPLE = "\x1b[38;5;93m"
RESET = "\033[0m"

def banner():
    

    print( ORANGE + """
        ,________________________________       
        |__________,----------._ [____]  ""-,__  __...-----==="
                (_(||||||||||||)___________/   ""             |
                `----------'           [ ))"-,    <TRABUCO>   |
                                        ""     `,  _,--...___ |
                                                `/          ""'                                                     
     """ + RED + "by @Slayer0x \n"+ RESET) 

def check_root():
    if os.geteuid() != 0:
        print( RED + "\n [!] This script must be run as root. Exiting." + RESET)
        sys.exit(1)

def validate_network(network):
    # Check if the user supplied a correct CDIR
    ip_network_pattern = r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
    if not re.match(ip_network_pattern, network):
        raise argparse.ArgumentTypeError( RED +"\n\n [!] Invalid network format. Please use format like 192.168.0.0/24" + RESET)
    return network

def execute_command(file,command):
    try:
            # Open the output file in write mode
            dir = (network[:-3])
            with open(str(dir + '/'+ file), "a") as file_write:
                # Create a pseudo-terminal to capture the output with color codes
                master_fd, slave_fd = pty.openpty()
                
                # Run the command in the pseudo-terminal
                netshares = subprocess.Popen(
                    command, 
                    stdout=slave_fd,
                    stderr=subprocess.STDOUT,
                    text=True
                )
                
                # Close the slave_fd as it's now being used by the child process
                os.close(slave_fd)
                
                # Read the output from the master_fd in a loop and print the output, also write to file.
                while True:
                    try:
                        output = os.read(master_fd, 1024).decode()  # Adjust buffer size as needed
                        if not output:
                            break
                        print(output, end='')  
                        file_write.write(output)   
                        file_write.flush()         
                    except OSError:
                        break

                # Wait for the process to complete
                netshares.wait()
                
                # Close the master_fd
                os.close(master_fd)
    except Exception as e:
        print( RED + f"\n\n [!] An error occurred: {e}" + RESET)
    except KeyboardInterrupt: 
        print( YELLOW + "\n\n [!] Moving to next target" + RESET)

def nmap_scans(nmap):
    result = subprocess.run(nmap, capture_output=True, text=True, check=True) #Nmap scan to check for servers  
    output = result.stdout
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'# IPs Pattern 
    ips = re.findall(ip_pattern, output) #Extract IPs
    return ips  


def cme_check(i):
        match i:
            case 0: #All checks  
                command =['netexec', 'smb', network, '--shares'] 
                file = f"{network[:-3]}_shares"
                print(ORANGE + "\n [+] NetExec is looking for Unrestricted Accessible Network Resources\n" + RESET)
                execute_command(file,command)

                command = ['netexec', 'smb', network, '--users'] 
                file = f"{network[:-3]}_users"
                print(ORANGE + "\n [+] NetExec is trying to enumerate Users \n" + RESET)
                execute_command(file,command)

                command = ['netexec', 'smb', network, '--rid-brute'] 
                file = f"{network[:-3]}_users"
                print(ORANGE + "\n [+] NetExec is trying to bruteforce RIDs \n"+ RESET)
                execute_command(file,command)

                command = ['netexec', 'smb', network, '--pass-pol'] 
                file = f"{network[:-3]}_passpol"
                print(ORANGE + "\n [+] NetExec is trying to enumerate password policies \n"+ RESET)
                execute_command(file,command)

            case 1: #Enum Shares  
                command =['netexec', 'smb', network, '--shares'] 
                file = f"{network[:-3]}_shares"
                print(ORANGE + "\n [+] NetExec is looking for Unrestricted Accessible Network Resources\n"+ RESET)
                execute_command(file,command)
        
            case 2: #Enum Users 
                command = ['netexec', 'smb', network, '--users'] 
                file = f"{network[:-3]}_users"
                print(ORANGE + "\n [+] NetExec is trying to enumerate Users \n"+ RESET)
                execute_command(file,command)

                command = ['netexec', 'smb', network, '--rid-brute'] 
                file = f"{network[:-3]}_users"
                print(ORANGE + "\n [+] NetExec is trying to bruteforce RIDs \n"+ RESET)
                execute_command(file,command)

            case 3: #Enum Pass-Pol 
                command = ['netexec', 'smb', network, '--pass-pol'] 
                file = f"{network[:-3]}_passpol"
                print(ORANGE + "\n [+] NetExec is trying to enumerate password policies \n" + RESET)
                execute_command(file,command)
                

def dump_snmp():
    
    print("\n [+] Scanning for SNMP Servers...")
    # Run nmap and check if there are available servers  
    command=['nmap', '-p', '191', '--open', '-sS', '-n', '-Pn', '--min-rate', '1000', network]
    ips = nmap_scans(command)
    
    if not ips: # Check if they were no servers detected.  
        print("\n [!] No SNMP Servers Found") 
    file = f"{network[:-3]}_SNMP_Full_Output"

    for i in ips: # Extract info from each server and save it to a file 
        command = ['snmpwalk', '-v2c', '-c', 'public', i, '.1'] 
        print("\n [+] snmpwalk is trying to dump the information at " + i + "\n")
        execute_command(file,command)


def ssh_bruteforce():

    print(YELLOW + "\n [+] Scanning for SSH Servers..." + RESET)
    # Run nmap and check if there are available servers  
    command=['nmap', '-p', '22', '--open', '-sS', '-n', '-Pn', '--min-rate', '1000', network]
    ips = nmap_scans(command)
    
    if not ips: # Check if they were no servers detected.  
        print(RED + "\n[!] No SSH Servers Found" + RESET) 
    file = f"{network[:-3]}_SSH_Servers_Bruteforce_Output"

    for i in ips: # Extract info from each server and save it to a file 
        command = ['hydra', '-S', '-C', './resources/ssh-betterdefaultpasslist.txt', i, 'ssh'] 
        print(ORANGE +"\n [+] Hydra is checking common SSH credentials at" + i + "\n" + RESET)
        execute_command(file,command)


def ftp_bruteforce():

    print( YELLOW + "\n [+] Scanning for FTP Servers..." + RESET)
    # Run nmap and check if there are available servers  
    command=['nmap', '-p', '21', '--open', '-sS', '-n', '-Pn', '--min-rate', '1000', network]
    ips = nmap_scans(command)
    
    if not ips: # Check if they were no servers detected.  
        print(RED +"\n [!] No FTP Servers Found" + RESET) 
    file = f"{network[:-3]}_FTP_Bruteforce_Output"

    for i in ips: # Extract info from each server and save it to a file 
        command = ['hydra', '-C', './resources/ftp-betterdefaultpasslist.txt', i, 'ftp'] 
        print(ORANGE + "\n [+] Hydra is checking common FTP credentials at " + i + "\n" + RESET)
        execute_command(file,command)

def telnet_bruteforce():

    print(YELLOW + "\n [+] Scanning for Telent Servers..." + RESET)
    # Run nmap and check if there are available servers  
    command=['nmap', '-p', '23', '--open', '-sS', '-n', '-Pn', '--min-rate', '1000', network]
    ips = nmap_scans(command)
    
    if not ips: # Check if they were no servers detected.  
        print( RED + "\n [!] No Telnet Servers Found" + RESET) 
    file = f"{network[:-3]}_Telnet_Bruteforce_Output"

    for i in ips: # Extract info from each server and save it to a file 
        command = ['hydra', '-C', './resources/telnet-betterdefaultpasslist.txt', i, 'telnet'] 
        print(ORANGE + "\n [+] Hydra is checking common Telnet credentials at " + i + "\n" + RESET)
        execute_command(file,command)

if __name__ == "__main__":
   # Check if the user has root privileges. 
    subprocess.run(['clear'])
    banner()
    check_root()

    parser = argparse.ArgumentParser(
        description="Trabuco Help Menu",
        epilog="""Examples:
         1. python3 Trabuco.py -a 192.168.1.0/24 -> Run all checks
         2. python3 Trabuco.py -usp 192.168.1.0/24 -> Run only AD Checks
         3. python3 Trabuco.py -df 192.168.0.0/16 -> Runs checks for FTP/SSH Default Creds""",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("-a", action="store_true", help="Run all Trabuco checks")
    parser.add_argument("-b", action="store_true", help="Check for SNMP default servers")
    parser.add_argument("-u", action="store_true", help="Check for Users + RID Brute")
    parser.add_argument("-s", action="store_true", help="Check for Shares")
    parser.add_argument("-p", action="store_true", help="Check for Password Policies")
    parser.add_argument("-d", action="store_true", help="Check for default SSH credentials")
    parser.add_argument("-f", action="store_true", help="Check for default FTP credentials")
    parser.add_argument("-t", action="store_true", help="Check for default Telnet credentials")
    parser.add_argument("Network", type=validate_network, help="Network range to scan (e.g., 192.168.0.0/24)")
    
    if len(sys.argv) == 1: # Avoid error message only when 1 argument detected. 
        parser.print_help()
        print(GREEN + "\n [V] Exiting Trabuco..." + RESET)
        sys.exit(1)

    args = parser.parse_args()
    network = args.Network # Save the network range 
    
   # Go to function and create the directory 
    if not (args.a or args.b or args.u or args.s or args.p or args.d or args.f or args.t):
        parser.print_help()
    else:
        subprocess.run(['mkdir', network[:-3]],stderr=subprocess.DEVNULL)
        print(PURPLE + "\n [i] Output will be saved at " + './'+ str(network[:-3]) + RESET)
        if args.a:
            cme_check(0)
            dump_snmp()
            ssh_bruteforce()
            ftp_bruteforce()
            telnet_bruteforce()
        if args.b:
            dump_snmp()
        if args.u:
            cme_check(2)
        if args.s:
            cme_check(1)     
        if args.p:
            cme_check(3)
        if args.d:
            ssh_bruteforce()
        if args.f:
            ftp_bruteforce()
        if args.t:
            telnet_bruteforce()

    subprocess.run(['rm', 'hydra.restore'],stderr=subprocess.DEVNULL)
    print(GREEN + "\n [V] Exiting Trabuco..." + RESET)    
