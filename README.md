# OSCP Prep - *Katana*

## Objective

We must go from visiting a simple website to having root access over the entire web server to obtain the flag in /root.

We'll download the VM from [here](https://www.vulnhub.com/entry/katana-1,482/) and set it up with VMware Workstation Pro 16.

Once the machine is up, we get to work.

## Step 1 - Reconnaissance

We'll find our IP address and run an Nmap scan to identify our target.

```
$ sudo ifconfig

eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.57.129  netmask 255.255.255.0  broadcast 192.168.57.255
        inet6 fe80::1e91:80ff:fedf:813a  prefixlen 64  scopeid 0x20<link>
        ether 1c:91:80:df:81:3a  txqueuelen 1000  (Ethernet)
        RX packets 885  bytes 363744 (355.2 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 832  bytes 230786 (225.3 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```
```
$ sudo nmap -sn -T4 -n 192.168.57.1/24

Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-18 11:17 EDT
Nmap scan report for 192.168.57.1
Host is up (0.00065s latency).
MAC Address: 00:50:56:C0:00:08 (VMware)
Nmap scan report for 192.168.57.2
Host is up (0.00021s latency).
MAC Address: 00:50:56:F4:F8:FC (VMware)
Nmap scan report for 192.168.57.140
Host is up (0.000084s latency).
MAC Address: 00:0C:29:DF:AA:E9 (VMware)
Nmap scan report for 192.168.57.254
Host is up (0.00024s latency).
MAC Address: 00:50:56:FB:7F:30 (VMware)
Nmap scan report for 192.168.57.129
Host is up.
Nmap done: 256 IP addresses (5 hosts up) scanned in 1.98 seconds
```

Our target machine is at IP address ```192.168.57.140```, so we'll run a detailed Nmap scan on it.

```
$ sudo nmap -sS -Pn -n -T4 -f 192.168.57.140

Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-18 11:18 EDT
Nmap scan report for 192.168.57.140
Host is up (0.00014s latency).
Not shown: 994 closed tcp ports (reset)
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
80/tcp   open  http
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
8088/tcp open  radan-http
MAC Address: 00:0C:29:DF:AA:E9 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 0.29 seconds
```
