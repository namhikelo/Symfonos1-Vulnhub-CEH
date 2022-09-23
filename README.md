<p>Download Link : <a href="https://www.vulnhub.com/entry/symfonos-1,322/">https://www.vulnhub.com/entry/symfonos-1,322/</a></p>

# Symfonos1-Vulnhub-CEH
 
Kiểm tra ip có thể dùng nmap or Angry IP Scanner để scan network
Ở đây mình dùng Angry IP Scanner để thấy máy vulnhub cho nhanh. 

### Angry IP Scanner 
<p align="left"><img src="/img/1.png" alt="Run"></p>

### nmap
```bash
nmap 10.10.10.0/24
```

```bash
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-22 22:31 EDT
Nmap scan report for 10.10.10.13
Host is up (0.00020s latency).
Not shown: 995 closed tcp ports (reset)
PORT    STATE SERVICE
22/tcp  open  ssh
25/tcp  open  smtp
80/tcp  open  http
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds
MAC Address: 00:0C:29:45:A7:2E (VMware)
```

Sau khi đã có IP: 10.10.10.13/24 thì ta sẽ dùng nmap để scan dịch vụ của máy.

```bash
nmap -sV -sC -sN -p- 10.10.10.13
```

```bash
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-22 00:16 EDT
Nmap scan report for 10.10.10.13
Host is up (0.000075s latency).
Not shown: 65530 closed tcp ports (reset)
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
| ssh-hostkey: 
|   2048 ab:5b:45:a7:05:47:a5:04:45:ca:6f:18:bd:18:03:c2 (RSA)
|   256 a0:5f:40:0a:0a:1f:68:35:3e:f4:54:07:61:9f:c6:4a (ECDSA)
|_  256 bc:31:f5:40:bc:08:58:4b:fb:66:17:ff:84:12:ac:1d (ED25519)
25/tcp  open  smtp        Postfix smtpd
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=symfonos
| Subject Alternative Name: DNS:symfonos
| Not valid before: 2019-06-29T00:29:42
|_Not valid after:  2029-06-26T00:29:42
|_smtp-commands: symfonos.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8
80/tcp  open  http        Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Site doesn't have a title (text/html).
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 4.5.16-Debian (workgroup: WORKGROUP)
MAC Address: 00:0C:29:45:A7:2E (VMware)
Service Info: Hosts:  symfonos.localdomain, SYMFONOS; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 1h39m59s, deviation: 2h53m12s, median: 0s
| smb2-time: 
|   date: 2022-09-22T04:16:30
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
|_nbstat: NetBIOS name: SYMFONOS, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.5.16-Debian)
|   Computer name: symfonos
|   NetBIOS computer name: SYMFONOS\x00
|   Domain name: \x00
|   FQDN: symfonos
|_  System time: 2022-09-21T23:16:30-05:0
```

Ở đây chúng ta thấy các dịch vụ như: port 22(ssh), 25(SMTP), 80(HTTP), 139(SMB), 445(SMB).

Hệ điều hành Window 6.1

### Scan lỗ hổng bảo mật
```bash
nmap -Pn --script vuln 10.10.10.13
```

```bash
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-22 23:05 EDT
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 10.10.10.13
Host is up (0.000096s latency).
Not shown: 995 closed tcp ports (reset)
PORT    STATE SERVICE
22/tcp  open  ssh
25/tcp  open  smtp
| ssl-dh-params: 
|   VULNERABLE:
|   Anonymous Diffie-Hellman Key Exchange MitM Vulnerability
|     State: VULNERABLE
|       Transport Layer Security (TLS) services that use anonymous
|       Diffie-Hellman key exchange only provide protection against passive
|       eavesdropping, and are vulnerable to active man-in-the-middle attacks
|       which could completely compromise the confidentiality and integrity
|       of any data exchanged over the resulting session.
|     Check results:
|       ANONYMOUS DH GROUP 1
|             Cipher Suite: TLS_DH_anon_WITH_AES_256_CBC_SHA
|             Modulus Type: Safe prime
|             Modulus Source: Unknown/Custom-generated
|             Modulus Length: 2048
|             Generator Length: 8
|             Public Key Length: 2048
|     References:
|_      https://www.ietf.org/rfc/rfc2246.txt
| smtp-vuln-cve2010-4344: 
|_  The SMTP server is not Exim: NOT VULNERABLE
80/tcp  open  http
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| http-enum: 
|_  /manual/: Potentially interesting folder
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds
MAC Address: 00:0C:29:45:A7:2E (VMware)

Host script results:
| smb-vuln-regsvc-dos: 
|   VULNERABLE:
|   Service regsvc in Microsoft Windows systems vulnerable to denial of service
|     State: VULNERABLE
|       The service regsvc in Microsoft Windows 2000 systems is vulnerable to denial of service caused by a null deference
|       pointer. This script will crash the service if it is vulnerable. This vulnerability was discovered by Ron Bowes
|       while working on smb-enum-sessions.
|_          
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: false

Nmap done: 1 IP address (1 host up) scanned in 65.86 seconds
```

Ta thấy nó xuất hiện mã lỗi CVE-2011-1002

### SMB

```bash 
man smbclient
```

```bash
Usage: smbclient [-?EgqBNPkV] [-?|--help] [--usage] [-M|--message=HOST] [-I|--ip-address=IP] [-E|--stderr] [-L|--list=HOST] [-T|--tar=<c|x>IXFvgbNan] [-D|--directory=DIR] [-c|--command=STRING] [-b|--send-buffer=BYTES]
        [-t|--timeout=SECONDS] [-p|--port=PORT] [-g|--grepable] [-q|--quiet] [-B|--browse] [-d|--debuglevel=DEBUGLEVEL] [--debug-stdout] [-s|--configfile=CONFIGFILE] [--option=name=value] [-l|--log-basename=LOGFILEBASE]
        [--leak-report] [--leak-report-full] [-R|--name-resolve=NAME-RESOLVE-ORDER] [-O|--socket-options=SOCKETOPTIONS] [-m|--max-protocol=MAXPROTOCOL] [-n|--netbiosname=NETBIOSNAME] [--netbios-scope=SCOPE]
        [-W|--workgroup=WORKGROUP] [--realm=REALM] [-U|--user=[DOMAIN/]USERNAME[%PASSWORD]] [-N|--no-pass] [--password=STRING] [--pw-nt-hash] [-A|--authentication-file=FILE] [-P|--machine-pass] [--simple-bind-dn=DN]
        [--use-kerberos=desired|required|off] [--use-krb5-ccache=CCACHE] [--use-winbind-ccache] [--client-protection=sign|encrypt|off] [-k|--kerberos] [-V|--version] [OPTIONS] service <password>

```

Ở đây chúng ta dùng lệnh 

```bash
smbclient -N -L //10.10.10.13
```

Để xem dánh sách các list host dùng **smb** và  xem có xác thực khi vào **smb**

<p align="left"><img src="/img/2.png" alt="SMB"></p>

Ở đây ta thấy các user **helios** , **anonymous**.
Giờ ta sẽ connect thử các user

```bash
smbclient //10.10.10.13/helios
```

<p align="left"><img src="/img/3.png" alt="SMB"></p>

Ta không có pass để vào ok ta thử user anonymous

```bash
smbclient //10.10.10.13/anonymous
```

<p align="left"><img src="/img/4.png" alt="SMB"></p>

Ok anonymous có vẻ không cần mật khẩu để đăng nhập vào


Sau khi vào trong ta sẽ dùng lệnh **ls** để liệt kê các file. Sau đó dùng lệnh **get** để lấy file về máy. 

Để thoát ra ta sẽ **Ctrl D** or **exit**

<p align="left"><img src="/img/5.png" alt="SMB"></p>

Sau đó ta dùng lệnh cat để đọc file

<p align="left"><img src="/img/6.png" alt="SMB"></p>

Trong đoạn văn nó có đề cập 3 mật để login helios.

```bash
'epidioko', 'qwerty' and 'baseball'
```

<p align="left"><img src="/img/7.png" alt="SMB"></p>

Có vẻ tôi đã sai chỗ nào đó. Tệp này chứa cảnh báo cho người dùng không sử dụng các mật khẩu này.

Vì thế tôi đã dùng câu lệnh.

```bash
smbclient //10.10.10.13/helios -U helios
```

-U, –user=USERNAME Set the network username

<p align="left"><img src="/img/8.png" alt="SMB"></p>

Sau đó ta sẽ **get** 2 file về và đọc nội dung nó

<p align="left"><img src="/img/9.png" alt="SMB"></p>

Ở file todo nó có đề cập  Work on /h3l105. Vì thế ta sẽ chạy web đó **10.10.10.13/h3l105**

Vì vậy, nó là một trang web Wordpress. Chúng ta có thể sử dụng wpscan để liệt kê người dùng và các plugin.

<p align="left"><img src="/img/10.png" alt="SMB"></p>

```bash
wpscan --url 10.10.10.13/h3l105/ –enumerate p
```

