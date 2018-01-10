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

The first mode is scanmode (-S). In this mode is area is simply scanned for available access points and displays various information about each access point.


The second mode is capturemode (-C), in this mode the tool will automatically scan for and deauthenticate clients connected to a specififed client while listening for WPA handshakes. The tool will continue scanning and attempting deauthentication until either a WPA handshake is recieved or the user temrinates the process. User must specify either a BSSID (-b) or SSID (-e) in this mode. It will save the cap file automatically in the current working directory unless otherwise specified by -o.

The third mode is automode, which will automatically scan for networks and deauthenticate clients on the networks while listening for handshakes. It will save one cap file per handshake, you can specify the output directory using -O, or it will automatically save to the current working directory.

All three modes can be filtered to specific channels (-c), BSSID (-b) or ESSIDS (-e). You can either input one BSSID/ESSID or input a file containing on BSSID/ESSID per line. 


### Example
  
Scanmode filter for SSID "MyWifiNetwork" using wlan0 interface:

> python driveshake.py -S -e MyWifiNetwork wlan0

Capturemode on network with BSSID AA:BB:CC:DD:EE:FF, output capture file to $PWD/Handshake.cap

> python driveshake.py -C -b AA:BB:CC:DD:EE:FF  -o Handshake.cap wlan0

Automode all networks on channel 8, will save to current working directory:

> python driveshake.py -A -c 8  wlan0



## Python usage statement

usage: driveshake.py [-h] [-b BSSID_FILTER] [-e ESSID_FILTER] [-c CHANNEL]
                     [-i IGNORE_BSSID] [-t SCANTIME] [-w WAITTIME]
                     [-d DEAUTH_COUNT] [-A] [-S] [-C] [-o OUTPUT_FILE]
                     [-O OUTPUT_FOLDER]
                     interface

positional arguments:
  interface         wifi interface capable of monitor mode

optional arguments:
  -h, --help        show this help message and exit
  -b BSSID_FILTER   bssid to filter for or file containing bssid to filter for
                    (one per line)
  -e ESSID_FILTER   essid to filter for or file containing essid to filter for
                    (one per line)
  -c CHANNEL        specify channel
  -i IGNORE_BSSID   bssid to ignore, or file containing list of bssids (one
                    per line)
  -t SCANTIME       length of scan time (default 10s)
  -w WAITTIME       time to wait for WPA handshake after deauth (defaults:
                    capturemode 90s, automode 30s)
  -d DEAUTH_COUNT   number of deauth frames to send (default 10)
  -A                auto find AP, de-auth, capture handshakes
  -S                scan and display AP's
  -C                capture handshake for specified AP
  -o OUTPUT_FILE    location to output .cap file (capture mode)
  -O OUTPUT_FOLDER  output folder for storing cap files (auto mode)

