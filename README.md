<img width="1449" height="301" alt="grafik" src="https://github.com/user-attachments/assets/46ce4574-e41a-4ccf-bbd2-6d0373a6032c" />


# STUNNER - STUN Packet IP extractor
 
![usage](https://img.shields.io/badge/For_Educational_purposes_only!-red) ![code](https://img.shields.io/badge/code-python3-yellow?logo=python&logoColor=3776AB) ![license](https://img.shields.io/badge/license-MIT-green) ![platform](https://img.shields.io/badge/platform-Windows_&_Linux-white) ![Static Badge](https://img.shields.io/badge/wireshark-blue?logo=wireshark&logoColor=white)

*Note: This is NOT any kind of exploit! The ONLY thing this tool does, is extract information out of STUN Protocol Packets and look up that information online.* 

## What is STUN

* STUN is a Protocol that is used mostly on IP Peer-to-Peer calls (Whatsapp, Telegram, Signal, etc..), which, for some reason, exposes the destination IP address in the Binding Success Response Packets. (0x0101) 

## What this does

* This tool uses the console version of Wireshark (tshark and pyshark) to extract the destination IP out of STUN Packets.
* Then, a IP lookup is triggered which then shows some useful details about the IP. (ISP, City, Country, Zip code, Lat., Long, etc..)
**THE SHOWN LOCATION DATA IS NOT EXACT; IT ONLY SHOWS THE NEAREST LOCATION OF THE ISP FROM THE TARGET; NOT THE DEVICE ITSELF.**

## Features

* VPN and Proxy detection
* Server detection
* Mobile Network detection
* IP whitelisting (changed in conf.json, default are the IP prefixes of Whatsapp Servers if it hits the wrong packet, recommend to not remove those)
* Logging of detections to the out folder

# Installing 

## Requirements

   You need:

* **Python 3.12 or higher**
* **pip3 or higher**
* **Wireshark and tshark set up correctly (Download from https://wireshark.org/)** 

## Installation
     
* Step 1: Download Zip and extract
* Step 2: Open a Terminal in the extracted folder
* Step 3: Paste this command into the terminal: ```pip3 install -r requirements.txt ```
* Step 4: Done!


# Usage

* **Select an Interface and start capture**
* **Call someone on a IP call (works best with whatsapp, the only thing i have tested so far)**
* **Wait and the IP will be extracted**
* *Note: Discord doesn't work with this tool. They use the Protocol TURN and don't use a Peer-to-Peer connection.*


## Troubleshooting

**Dependencies fail to install**
  
* If you are on Linux the chance is very high this message popped up when you tried Step 3: 
 
    
```
error: externally-managed-environment

× This environment is externally managed
╰─> To install Python packages system-wide, try apt install
    python3-xyz, where xyz is the package you are trying to
    install.
    If you wish to install a non-Debian-packaged Python package,
    create a virtual environment using python3 -m venv path/to/venv.
    Then use path/to/venv/bin/python and path/to/venv/bin/pip. Make
    sure you have python3-full installed.

    If you wish to install a non-Debian packaged Python application,
    it may be easiest to use pipx install xyz, which will manage a
    virtual environment for you. Make sure you have pipx installed.

    See /usr/share/doc/python3.12/README.venv for more information.

``` 


* The solution is to make a python venv in the folder where stunner.py is located by running: ```python3 -m venv .venv ```
* Activating the venv is done by running: ```source .venv/bin/activate```
* To deactivate the venv just run: ```deactivate```

**Wireshark not found**

* If an error message comes up after starting the capture, it means you either don't have wireshark currently installed or haven't set it up correctly. Follow the instructions in Requirements and make sure you install tshark. On Windows, select the tshark component in the installer, and on linux, run: ```sudo apt install tshark``` or ```sudo dnf install wireshark-cli``` or ```sudo pacman -S wireshark-cli```, depending on your distro.

 **I keep getting the server's IP**

* if it has a specific IP prefix, add the prefix to the IP whitelist in conf.json, with it having a dot after the last number. (for example: 31.13.)

