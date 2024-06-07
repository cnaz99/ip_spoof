# *ip_spoof*
## *Usage Introduction*
*compile*
```bash
gcc -std=c99 -o ip_spoof ip_spoof.c
```
*example*
```bash
sudo ./ip_spoof <source_ip> <dest_ip> <count>
```
## *Project Introduction*
In the original socket broker written in C, the main principles are as follows:
1.Create the original socket
2.Construct the IP header and ICMP header
3.Construct the packet
4.Send packets
5.Handle errors and exceptions