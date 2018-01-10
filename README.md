<pre>
|\   ___ \|\   __  \|\  \|\  \    /  /|\  ___ \ |\   ____\|\  \|\  \|\   __  \|\  \|\  \ |\  ___ \     
\ \  \_|\ \ \  \|\  \ \  \ \  \  /  / | \   __/|\ \  \___|\ \  \\\  \ \  \|\  \ \  \/  /|\ \   __/|    
 \ \  \ \\ \ \   _  _\ \  \ \  \/  / / \ \  \_|/_\ \_____  \ \   __  \ \   __  \ \   ___  \ \  \_|/__  
  \ \  \_\\ \ \  \\  \\ \  \ \    / /   \ \  \_|\ \|____|\  \ \  \ \  \ \  \ \  \ \  \\ \  \ \  \_|\ \ 
   \ \_______\ \__\\ _\\ \__\ \__/ /     \ \_______\____\_\  \ \__\ \__\ \__\ \__\ \__\\ \__\ \_______\
    \|_______|\|__|\|__|\|__|\|__|/       \|_______|\_________\|__|\|__|\|__|\|__|\|__| \|__|\|_______|
                                                   \|_________|                                        
</pre>

# DriveShake

Wifi network scanning tool, which can also capture WPA/WPA2 PSK handshakes. The tool automatically finds clients connected to the access point and sends deauthentication packets while sniffing for the handshake.

## Dependencies

  - python 2.x
  - scapy
  

## Prerequisites

To perform deauthentication attacks you must have a network card capable of injection

## Usage

The tool will automatically place the wireless interface in monitor mode. From
there the tool has 3 modes which can be used for different purposes.

### Scanmode

The first mode is scanmode (-S). In this mode is area is simply scanned for available access points and displays various information about each access point.

### Capturemode
The second mode is capturemode (-C), in this mode the tool will automatically scan for and deauthenticate clients connected to a specififed client while listening for WPA handshakes. The tool will continue scanning and attempting deauthentication until either a WPA handshake is recieved or the user temrinates the process. User must specify either a BSSID (-b) or SSID (-e) in this mode. It will save the cap file automatically in the current working directory unless otherwise specified by -o.


### Automode
The third mode is automode, which will automatically scan for networks and deauthenticate clients on the networks while listening for handshakes. It will save one cap file per handshake, you can specify the output directory using -O, or it will automatically save to the current working directory.


### Filters
All three modes can be filtered to specific channels (-c), BSSID (-b) or ESSIDS (-e). You can either input one BSSID/ESSID or input a file containing on BSSID/ESSID per line. 


## Examples
  
Scanmode filter for SSID "MyWifiNetwork" using wlan0 interface:

> python driveshake.py -S -e MyWifiNetwork wlan0

Capturemode on network with BSSID AA:BB:CC:DD:EE:FF, output capture file to $PWD/Handshake.cap

> python driveshake.py -C -b AA:BB:CC:DD:EE:FF  -o Handshake.cap wlan0

Automode all networks on channel 8, will save to current working directory:

> python driveshake.py -A -c 8  wlan0



