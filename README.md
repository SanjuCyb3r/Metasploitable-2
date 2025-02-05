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

# Nmap Vulnerability Script

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












