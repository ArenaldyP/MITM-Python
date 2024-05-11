# MITM-Python 💀
Kode python diatas adalah Serangan MITM sering dilakukan melalui teknik seperti sniffing jaringan, spoofing, atau DNS poisoning. Penyerang menempatkan dirinya di antara klien dan server yang sah, memungkinkannya untuk mengendalikan aliran komunikasi.

## Cara Kerja
1. Install Requirements.txt : pip -r Requirements.txt
2. Setting iptables di kali : **sudo iptables -I FORWARD -j NFQUEUE --queue-num 0 --queue-bypass**
3. Jalankan Server dengan : **sudo service apache2 start**
4. jangan lupa file index.html diganti dengan index.html ini
5. Lalu Jalankan Scriptnya di mulai dari ARP_Spoof.py
6. Lalu Jalankan Script DNS_Spoof.py dan selanjutnya Packet_sniffing.py

## Kode ARP_Spoof
ARP Spoof adalah serangan di mana penyerang memalsukan ARP (Address Resolution Protocol) untuk mengarahkan lalu lintas jaringan melalui komputer penyerang.

## Kode DNS_Spoof
DNS Spoof adalah serangan di mana penyerang memalsukan respons DNS untuk mengarahkan pengguna ke situs web palsu atau IP yang berbeda.

## Kode Packet_Sniffing
Kode ini mencari text yang berkaitan dengan kredensial

## Hasil
Tools ini membuat penyerang mendapatkan kredensial dari korban dengan DNS Poisoning dari Web Penyerang. Ketika korban memesuakan kredensial ***Packet sniffing*** akan mengambil kredensial korban
