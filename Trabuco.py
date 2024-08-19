import pty, sys, subprocess, os, re, argparse
from tqdm import tqdm

# Colors to use in print.
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
        print( RED + "\n [!] This script must be run as root. Exiting. \n" + RESET)
        sys.exit(1)


def validate_network(network):
    # Check if the user supplied a correct CDIR.
    ip_network_pattern = r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
    if not re.match(ip_network_pattern, network):
        raise argparse.ArgumentTypeError( RED +"\n\n [!] Invalid network format. Please use format like 192.168.0.0/24 \n" + RESET)
    return network


def execute_command(command,file=None):
    
    try:
        # Create a pseudo-terminal to capture the output with color codes.
        master_fd, slave_fd = pty.openpty()
        
        # Run the command in the pseudo-terminal
        netshares = subprocess.Popen(
            command, 
            stdout=slave_fd,
            stderr=subprocess.STDOUT,
            text=True
        )
        
        # Close the slave_fd as it's now being used by the child process.
        os.close(slave_fd)
        
        if file is not None:
            # Open the output file in append mode
            dir = f'{current_path}/{network[:-3]}'
            with open(str(dir + '/' + file), "a") as file_write:
                # Read the output from the master_fd in a loop and print the output, also write to file.
                while True:
                    try:
                        output = os.read(master_fd, 1024).decode()  # Adjust buffer size as needed.
                        if not output:
                            break
                        print(output, end='')  
                        file_write.write(output)   
                        file_write.flush()         
                    except OSError:
                        break
        else:
            # Read the output from the master_fd in a loop and print the output.
            while True:
                try:
                    output = os.read(master_fd, 1024).decode()  # Adjust buffer size as needed.
                    if not output:
                        break
                    print(output, end='')  
                except OSError:
                    break

        # Wait for the process to complete.
        netshares.wait()
        
        # Close the master_fd
        os.close(master_fd)

    except Exception as e:
        print( RED + f"\n\n [!] An error occurred: {e}" + RESET)
    except KeyboardInterrupt: 
        print( YELLOW + "\n\n [!] Moving to next target \n" + RESET)


def nmap_scans(nmap):
       try: 
        result = subprocess.run(nmap, capture_output=True, text=True, check=True) #Nmap scan to check for servers.  
        output = result.stdout
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'# IPs Pattern. 
        ips = re.findall(ip_pattern, output) #Extract IPs.
        return ips
       
       except Exception as e:
        print( RED + f"\n\n [!] An error occurred while scanning: {e}" + RESET)

       except KeyboardInterrupt: 
        print( YELLOW + "\n\n [!] Stopping the scanner \n" + RESET)


def cme_check(i):
        
        directory_path = f'{current_path}/{network[:-3]}/CME'
        if not os.path.exists(directory_path):
            subprocess.run(['mkdir', '-p', directory_path], check=True, stderr=subprocess.DEVNULL)

        match i:
            case 0: #All checks.  
                command =['netexec', 'smb',  network, '-u', '', '-p', '', '--shares'] 
                file = f"CME/{network[:-3]}_Shares"
                print(ORANGE + "\n [+] NetExec is looking for Unrestricted Accessible Network Resources \n" + RESET)
                execute_command(command,file)

                command = ['netexec', 'smb', network, '-u', '', '-p', '', '--users'] 
                file = f"CME/{network[:-3]}_Users"
                print(ORANGE + "\n [+] NetExec is trying to enumerate Users \n" + RESET)
                execute_command(command,file)

                command = ['netexec', 'smb', network, '-u', '', '-p', '', '--rid-brute'] 
                file = f"CME/{network[:-3]}_Users"
                print(ORANGE + "\n [+] NetExec is trying to bruteforce RIDs \n"+ RESET)
                execute_command(command,file)

                command = ['netexec', 'smb', network, '-u', '', '-p', '', '--pass-pol'] 
                file = f"CME/{network[:-3]}_PassPol"
                print(ORANGE + "\n [+] NetExec is trying to enumerate password policies \n"+ RESET)
                execute_command(command,file)

            case 1: #Enum Shares  
                command =['netexec', 'smb', network, '-u', '', '-p', '', '--shares'] 
                file = f"CME/{network[:-3]}_Shares"
                print(ORANGE + "\n [+] NetExec is looking for Unrestricted Accessible Network Resources \n"+ RESET)
                execute_command(command,file)
        
            case 2: #Enum Users 
                command = ['netexec', 'smb', network, '-u', '', '-p', '', '--users'] 
                file = f"CME/{network[:-3]}_Users"
                print(ORANGE + "\n [+] NetExec is trying to enumerate Users \n"+ RESET)
                execute_command(command,file)

                command = ['netexec', 'smb', network, '-u', '', '-p', '', '--rid-brute'] 
                file = f"CME/{network[:-3]}_Users"
                print(ORANGE + "\n [+] NetExec is trying to bruteforce RIDs \n"+ RESET)
                execute_command(command,file)

            case 3: #Enum Pass-Pol 
                command = ['netexec', 'smb', network, '-u', '', '-p', '', '--pass-pol'] 
                file = f"CME/{network[:-3]}_PassPol"
                print(ORANGE + "\n [+] NetExec is trying to enumerate password policies \n" + RESET)
                execute_command(command,file)
                

def dump_snmp():
    
    #Paths to create dirs  
    directory_path = f'{current_path}/{network[:-3]}/SNMP'
    file = f"SNMP/{network[:-3]}_SNMP_Servers_Output" 

    print(YELLOW + "\n [+] Scanning for SNMP Servers... \n" + RESET)
    # Run nmap and check if there are available servers.  
    command=['nmap', '-p', '191', '--open', '-sS', '-n', '-Pn', '--min-rate', '1000', network]
    ips = nmap_scans(command)
    
    if not ips: # Check if they were no servers detected.  
        print(RED + "\n [!] No SNMP Servers Found \n" + RESET) 
    
    else:
        if not os.path.exists(directory_path):
            subprocess.run(['mkdir', '-p', directory_path], check=True, stderr=subprocess.DEVNULL)
    
        for i in ips: # Extract info from each server and save it to a file. 
            command = ['snmpwalk', '-v2c', '-c', 'public', i, '.1'] 
            print(ORANGE + "\n [+] snmpwalk is trying to dump the information at " + i + "\n" + RESET)
            execute_command(command,file)


def ssh_bruteforce():

    #Paths to create dirs  
    directory_path = f'{current_path}/{network[:-3]}/Bruteforce'
    file = f"Bruteforce/{network[:-3]}_SSH_Servers_Bruteforce_Output"    

    print(YELLOW + "\n [+] Scanning for SSH Servers... \n" + RESET)
    # Run nmap and check if there are available servers.  
    command=['nmap', '-p', '22', '--open', '-sS', '-n', '-Pn', '--min-rate', '1000', network]
    ips = nmap_scans(command)
    
    if not ips: # Check if they were no servers detected.  
        print(RED + "\n [!] No SSH Servers Found \n" + RESET) 
    
    else:
        if not os.path.exists(directory_path):
            subprocess.run(['mkdir', '-p', directory_path], check=True, stderr=subprocess.DEVNULL)
        
        for i in ips: # Extract info from each server and save it to a file. 
            command = ['hydra', '-C', '/usr/share/seclists/Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt', i, 'ssh'] 
            print(ORANGE +"\n [+] Hydra is checking common SSH credentials at " + i + "\n" + RESET)
            execute_command(command,file)


def ftp_bruteforce():

    #Paths to create dirs  
    directory_path = f'{current_path}/{network[:-3]}/Bruteforce'
    file = f"Bruteforce/{network[:-3]}_FTP_Servers_Bruteforce_Output"


    print( YELLOW + "\n [+] Scanning for FTP Servers... \n" + RESET)
    # Run nmap and check if there are available servers.  
    command=['nmap', '-p', '21', '--open', '-sS', '-n', '-Pn', '--min-rate', '1000', network]
    ips = nmap_scans(command)
    
    if not ips: # Check if they were no servers detected.  
        print(RED +"\n [!] No FTP Servers Found \n" + RESET) 

    else:
        if not os.path.exists(directory_path):
            subprocess.run(['mkdir', '-p', directory_path], check=True, stderr=subprocess.DEVNULL)

        for i in ips: # Extract info from each server and save it to a file. 
            command = ['hydra', '-C', '/usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt', i, 'ftp'] 
            print(ORANGE + "\n [+] Hydra is checking common FTP credentials at \n " + i + "\n" + RESET)
            execute_command(command,file)


def telnet_bruteforce():

    #Paths to create dirs  
    directory_path = f'{current_path}/{network[:-3]}/Bruteforce'
    file = f"Bruteforce/{network[:-3]}_Telnet_Servers_Bruteforce_Output"

    print(YELLOW + "\n [+] Scanning for Telent Servers... \n" + RESET)
    # Run nmap and check if there are available servers.
    command=['nmap', '-p', '23', '--open', '-sS', '-n', '-Pn', '--min-rate', '1000', network]
    ips = nmap_scans(command)
    
    if not ips: # Check if they were no servers detected.  
        print(RED + "\n [!] No Telnet Servers Found \n" + RESET) 
    
    else:
        if not os.path.exists(directory_path):
            subprocess.run(['mkdir', '-p', directory_path], check=True, stderr=subprocess.DEVNULL)
        
        for i in ips: # Extract info from each server and save it to a file.
            command = ['hydra', '-C', '/usr/share/seclists/Passwords/Default-Credentials/telnet-betterdefaultpasslist.txt', i, 'telnet'] 
            print(ORANGE + "\n [+] Hydra is checking common Telnet credentials at " + i + "\n" + RESET)
            execute_command(command,file)


def go_witness():

    #Paths to create dirs  
    directory_path = f'{current_path}/{network[:-3]}/GoWitness'
    file = f"GoWitness/{network[:-3]}_GoWitness_Command_Output"

    print(YELLOW + "\n [+] Scanning for Web Servers... This might take a while, don´t exit [+] \n" + RESET)
    # Run nmap and check if there are available servers.
    filename = f"{network[:-3]}/{network[:-3]}_scan"
    command=['nmap', '-p-', '--open', '-sS', '-n', '-Pn', '--min-rate', '5000', '-T', '5', network, '-oA', filename]
    ips = nmap_scans(command)
    
    if not ips: # Check if they were no servers detected.  
        print(RED + "\n [!] No Web Servers Found \n" + RESET)

    else:
        if not os.path.exists(directory_path):
            subprocess.run(['mkdir', '-p', directory_path], check=True, stderr=subprocess.DEVNULL)
            subprocess.run(['mkdir', '-p', directory_path + '/Nmap'], check=True, stderr=subprocess.DEVNULL)

        print(GREEN + "\n [V] Possible Web Servers Found \n" + RESET)   
        subprocess.run(['mv', filename + '.xml',filename + '.gnmap',filename + '.nmap', directory_path + '/Nmap/'], check=True, stderr=subprocess.DEVNULL)
        command = ['gowitness', 'nmap', '-f', directory_path + '/Nmap/' + str(network[:-3]) + '_scan' + '.xml', '-P', f"{directory_path}/WebServers"] 
        print(ORANGE + "\n [+] GoWitness is checking for accessible Web Servers \n" + RESET)
        execute_command(command,file)
        subprocess.run(['chmod', '755', '-R', f"{directory_path}/WebServers"]) #We need to change rights cause the script is executed as root. 
        subprocess.run(['rm', './gowitness.sqlite3']) #Remove SQLite DB generated by gowitness. 


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
         3. python3 Trabuco.py -df 192.168.0.0/16 -> Runs checks for FTP/SSH Default Creds
         4. python3 Trabuco.py -g 192.168.0.0/16 -> Scans and saves Screenshots from Web Servers""",
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
    parser.add_argument("-g", action="store_true", help="Screenshot available Web Servers")
    parser.add_argument("Network", type=validate_network, help="Network range to scan (e.g., 192.168.0.0/24)")
    
    if len(sys.argv) == 1: # Avoid error message only when 1 argument detected. 
        parser.print_help()
        print(GREEN + "\n [V] Exiting Trabuco... \n" + RESET)
        sys.exit(1)

    args = parser.parse_args()
    options = ['a','b','u','s','p','d','f','t','g']
    network = args.Network # Save the network range 
    
    if not any(getattr(args, opt) for opt in options):
        parser.print_help()
    else:
        # Go to function and create the directory 
        result_pwd  = subprocess.run(['pwd'], capture_output=True, text=True)
        current_path = result_pwd.stdout.strip()
        subprocess.run(['mkdir', '-p', f'{current_path}/{network[:-3]}'],stderr=subprocess.DEVNULL)
        print(PURPLE + "\n [i] Output will be saved at " + './'+ str(network[:-3]) + RESET)

        if args.a:
            cme_check(0)
            dump_snmp()
            ssh_bruteforce()
            ftp_bruteforce()
            telnet_bruteforce()
            go_witness()
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
        if args.g:
            go_witness()

    subprocess.run(['rm', 'hydra.restore'],stderr=subprocess.DEVNULL)
    print(GREEN + "\n [V] Exiting Trabuco... \n" + RESET)    
