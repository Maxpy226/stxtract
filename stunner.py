#stun protocol destination ip logger
#made with pyshark
#windows and linux compatible

from pyparsing import col
import pyshark
import colorama
import requests
import os
import socket
import psutil
import tqdm
import json
import datetime

colorama.init()

debug = True #set to true to print debug information about the local device's public and private IPs for comparison


with open("conf.json", "r") as f:
    config = json.load(f)
    ip_whitelist = config.get("ip_whitelist", [])

#set the title of the console window
os.system("title stunner - static_one") if os.name == 'nt' else None

def banner():
    print(colorama.Fore.LIGHTMAGENTA_EX + """
          ,/            :::::::: ::::::::::: :::    ::: ::::    ::: ::::    ::: :::::::::: :::::::::        ,/
        ,'/           :+:    :+:    :+:     :+:    :+: :+:+:   :+: :+:+:   :+: :+:        :+:    :+:      ,'/
      ,' /           +:+           +:+     +:+    +:+ :+:+:+  +:+ :+:+:+  +:+ +:+        +:+    +:+     ,' /
    ,'  /_____,     +#++:++#++    +#+     +#+    +:+ +#+ +:+ +#+ +#+ +:+ +#+ +#++:++#   +#++:++#:     ,'  /_____,
  .'____    ,'           +#+    +#+     +#+    +#+ +#+  +#+#+# +#+  +#+#+# +#+        +#+    +#+    .'____    ,'  
       /  ,'     #+#    #+#    #+#     #+#    #+# #+#   #+#+# #+#   #+#+# #+#        #+#    #+#          /  ,'
      / ,'      #+#    #+#    #+#     #+#    #+# #+#   #+#+# #+#   #+#+# #+#        #+#    #+#          / ,'
     /,'        ########     ###      ########  ###    #### ###    #### ########## ###    ###          /,' 
    /'                                                                                                /'
            STUNNER - STTUN Protocol IP Logger
                                                        -static_one, 2026   """ + colorama.Style.RESET_ALL)
    print(colorama.Fore.CYAN + "=" * 120 + colorama.Style.RESET_ALL)
    if debug:
        print(colorama.Fore.GREEN + "[-] Debug Mode Enabled" + colorama.Style.RESET_ALL)

def check_for_wireshark_install():
    try:
        pyshark.LiveCapture()
    except Exception as e:
        print(colorama.Fore.RED + "[!] Error: Wireshark/Tshark is not installed or not in PATH. Please install Wireshark and ensure Tshark is in your system's PATH. https://www.wireshark.org/" + colorama.Style.RESET_ALL)
        print(colorama.Fore.RED + f"Detailed error: {str(e)}" + colorama.Style.RESET_ALL)
        input("\nPress Enter to exit...")
        exit()

def main():
    try:
        #check for essential wireshark install if no install print execption and exit
        check_for_wireshark_install()
        #after check is successful, clear the screen and print the banner again before starting the capture 
        os.system('cls' if os.name == 'nt' else 'clear')
        banner()
        print(colorama.Fore.CYAN + f"[*] Starting capture on interface: {iface}" + colorama.Style.RESET_ALL)
        print(colorama.Fore.CYAN + "[*] Waiting for packets..." + colorama.Style.RESET_ALL)
        #start of main capture process
        capture = pyshark.LiveCapture(interface=iface, display_filter='stun')

        for packet in capture.sniff_continuously():
            try:
                if packet.stun.type == '0x0101': #binding success response 

                    localpublicip = requests.get('https://api.ipify.org').text #get the public ip of the local device using an api
                    #get the private ip
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.connect(("8.8.8.8", 80))  # Google DNS for testing connection, doesn't actually send data
                    privateip = s.getsockname()[0]
                    s.close()
                    if debug:
                        print(colorama.Fore.GREEN + "[-] Debug Information (for comparing IPs)" + colorama.Style.RESET_ALL)
                        print(colorama.Fore.CYAN + f"Local Public IP: {localpublicip}" + colorama.Style.RESET_ALL)
                        print(colorama.Fore.CYAN + f"Local Private IP: {privateip}" + colorama.Style.RESET_ALL)

                    ipsrc = packet.ip.src
                    ipdst = packet.ip.dst

                    ignored_ips = {localpublicip, privateip}
                    candidate_ips = [
                        address
                        for address in (ipsrc, ipdst)
                        if address not in ignored_ips
                        and not any(address.startswith(prefix) for prefix in ip_whitelist)
                    ]
                    if not candidate_ips:
                        continue

                    ip = candidate_ips[0]

                    print()
                    print(colorama.Fore.BLUE+ "[!] STUN 0x0101 Packet found" + colorama.Style.RESET_ALL)
                    print()
                    print(colorama.Fore.GREEN + f"[+] Extracted IP: {ip}" + colorama.Style.RESET_ALL)
                    #put extra geolocation information using ip-api.com
                    print()

                    if debug:
                        print(colorama.Fore.GREEN + "[-] Debug: Full API response for troubleshooting:" + colorama.Style.RESET_ALL)
                        print(colorama.Fore.CYAN + f"{requests.get(f'http://ip-api.com/json/{ip}').json()}" + colorama.Style.RESET_ALL)

                    print()
                    # fetching should look pretty so im using tqdm
                    for _ in tqdm.tqdm(range(10), desc=colorama.Fore.YELLOW + "[*] Fetching IP info" + colorama.Style.RESET_ALL, ncols=100, colour="yellow", bar_format="{l_bar}{bar}"):
                            response = requests.get(
                                f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,zip,timezone,city,isp,org,lat,lon,hosting,proxy,mobile"
                            ).json()
    

                    if response["status"] != "success":
                        print(colorama.Fore.RED + f"[!] Failed to fetch information for IP: {ip}. API response: {response.get('message', 'No message provided')}" + colorama.Style.RESET_ALL)
                        continue
                    else:
                        print(colorama.Fore.GREEN + f"[+] Success!" + colorama.Style.RESET_ALL)

                    if response["org"] == "":
                        org = "N/A"
                    else:
                        org = response["org"]
                    
                    print()

                    if response.get("hosting") is True:
                        print(colorama.Fore.MAGENTA + "[#] Associated with a hosting provider; target may be a server" + colorama.Style.RESET_ALL)
                    if response.get("proxy") is True:
                        print(colorama.Fore.MAGENTA + "[#] Associated with a proxy; target may be using a VPN or anonymization service" + colorama.Style.RESET_ALL)
                    if response.get("mobile") is True:
                        print(colorama.Fore.MAGENTA + "[#] Associated with a mobile network; target may be using a mobile connection" + colorama.Style.RESET_ALL)
                    
                    print()
                    print(colorama.Fore.CYAN + "=======================================" + colorama.Style.RESET_ALL)
                    print(colorama.Fore.YELLOW + f"[+] Information for {ip}:" + colorama.Style.RESET_ALL)
                    print(colorama.Fore.CYAN + f" - Country: {response['country']}" + colorama.Style.RESET_ALL)
                    print(colorama.Fore.CYAN + f" - Region: {response['regionName']}" + colorama.Style.RESET_ALL)
                    print(colorama.Fore.CYAN + f" - ZIP: {response['zip']}" + colorama.Style.RESET_ALL)
                    print(colorama.Fore.CYAN + f" - Timezone: {response['timezone']}" + colorama.Style.RESET_ALL)
                    print(colorama.Fore.CYAN + f" - City: {response['city']}" + colorama.Style.RESET_ALL)
                    print(colorama.Fore.CYAN + f" - ISP: {response['isp']}" + colorama.Style.RESET_ALL)
                    print(colorama.Fore.CYAN + f" - ORG: {org}" + colorama.Style.RESET_ALL)
                    print(colorama.Fore.CYAN + f" - Proxy: {response.get('proxy', False)}" + colorama.Style.RESET_ALL)
                    print(colorama.Fore.CYAN + f" - Mobile: {response.get('mobile', False)}" + colorama.Style.RESET_ALL)
                    print()
                    print(colorama.Fore.CYAN + f" - Latitude: {response['lat']}" + colorama.Style.RESET_ALL)
                    print(colorama.Fore.CYAN + f" - Longitude: {response['lon']}" + colorama.Style.RESET_ALL)
                    print(colorama.Fore.CYAN + "=======================================" + colorama.Style.RESET_ALL)

                    print()
                                    
                    now = datetime.datetime.now()
                    date_time = now.strftime("%Y-%m-%d %H:00")
                    log_filename = now.strftime("log_%Y-%m-%d_%H.log")
                    os.makedirs("out", exist_ok=True)
                    log_path = os.path.join("out", log_filename)
                    with open(log_path, "a") as f:
                        f.write(f"[{date_time}] IP: {ip}, Country: {response['country']}, Region: {response['regionName']}, ZIP: {response['zip']}, Timezone: {response['timezone']}, City: {response['city']}, ISP: {response['isp']}, ORG: {org}, Latitude: {response['lat']}, Longitude: {response['lon']}\n")

                    print(colorama.Fore.GREEN + f"[+] Logged information to {log_path}" + colorama.Style.RESET_ALL)
                    #stop the capture loop
                    break
                    
            except AttributeError as e:
                #print exceptions to the user in case of malformed packets or missing fields
                print(colorama.Fore.RED + "[!] Error processing packet: " + str(e) + colorama.Style.RESET_ALL)
    except Exception as e:
        print(colorama.Fore.RED + "[!] An error occurred: " + str(e) + colorama.Style.RESET_ALL)
        input("\nPress Enter to exit...")
        exit()

if __name__ == "__main__":
    banner()

    if ip_whitelist:
        print(colorama.Fore.RED + "[!] WARNING: IP WHITELIST IS ENABLED FOR " + str(ip_whitelist) + colorama.Style.RESET_ALL)

    global iface
    print()
    #output all ifaces with numbers for user to choose from via the proper readable names
    for i, (interface_name, interface_addresses) in enumerate(psutil.net_if_addrs().items(), start=1):
        print(colorama.Fore.LIGHTMAGENTA_EX + f" {i}. {interface_name}" + colorama.Style.RESET_ALL)

    print()
    iface = input(colorama.Fore.CYAN + "Enter the network interface number to capture on (default ethernet): " + colorama.Style.RESET_ALL)
    

    if iface == "":
        iface = "ethernet"
    else:
        try:
            iface = list(psutil.net_if_addrs().keys())[int(iface) - 1]
        except (ValueError, IndexError):
            print(colorama.Fore.RED + "[!] Invalid interface number. Exiting..." + colorama.Style.RESET_ALL)
            exit()

    print(colorama.Fore.CYAN + f"[*] Starting STUN capture on interface: {iface}" + colorama.Style.RESET_ALL)
    main()
    
    input("\nPress Enter to exit...")
    exit()