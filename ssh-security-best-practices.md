# SSH Security best practice

```
nano /etc/ssh/sshd_config
```

### Use public keys to log in (only this should be allowed)

Public keys should be generated using ED25519 or RSA algorithm.

```
AuthenticationMethods publickey
PasswordAuthentication no
PubkeyAuthentication yes
PreferredAuthentications=publickey (disable access without password)
```

```
~/.ssh/authorized_keys
```

```
ssh-keygen -t rsa -b 4096 ssh-keygen -t dsa ssh-keygen -t ecdsa -b 521 ssh-keygen -t ed25519 -V +52w
```

You can make this even safer with 2FA :)
more settings:

 - [https://goteleport.com/blog/how-to-ssh-properly/](https://goteleport.com/blog/how-to-ssh-properly/)
 
### Disable direct root user access

```
PermitRootLogin no
ChallengeResponseAuthentication no
PasswordAuthentication no
UsePAM no
```

### SSH to another port

```
Port 2233
```

### Disable SSH port access - only accessible from allowed IPs

```
ufw allow from 192.168.101.0/24 to any port 2233
```

But SSH itself can also be scaled down to respond only to requests from that IP:
```
ListenAddress 1.2.3.4
```

### SSH brute force attack protection 

```
DenyHost, fail2ban, sshguard
```

### User-binding SSH login

```
AllowUsers user1 user2
DenyUsers root user3 user4
```

### Disable empty passwords

```
PermitEmptyPasswords no
```

### Block port 'knocking'

[https://www.cyberciti.biz/tips/linux-unix-bsd-openssh-server-best-practices.html](https://www.cyberciti.biz/tips/linux-unix-bsd-openssh-server-best-practices.html)

```
#!/bin/bash
inet_if=eth1
ssh_port=2233
$IPT -I INPUT -p tcp --dport ${ssh_port} -i ${inet_if} -m state --state NEW -m recent  --set
$IPT -I INPUT -p tcp --dport ${ssh_port} -i ${inet_if} -m state --state NEW -m recent  --update --seconds 60 --hitcount 5 -j DROP
```


### Mandatory password changes for users from time to time

password is valid for 90 days

```
chage -M 90 user1 
```

### Idle log out timeout interval

```
ClientAliveInterval 300
ClientAliveCountMax 0
```

### Banner settings

- custom banner:
```
Banner /etc/issue
```

- Banner disable:
```
Banner none
```

### Disable ".rhosts" files 

```
IgnoreRhosts yes
```

### Disable host-based authentication

```
HostbasedAuthentication no
```

### Chroot OpenSSH

todo

### Enable only the latest protocol (which in this case is 2)

```
Protocol 2
```

### Ciphers  settings

```
# Supported HostKey algorithms by order of preference.
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
 
# Specifies the available KEX (Key Exchange) algorithms.
KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256
 
# Specifies the ciphers allowed
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
 
#Specifies the available MAC (message authentication code) algorithms
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com
```
## Links

- [https://www.cyberciti.biz/tips/linux-unix-bsd-openssh-server-best-practices.html](https://www.cyberciti.biz/tips/linux-unix-bsd-openssh-server-best-practices.html)
- [https://blog.devolutions.net/2017/04/10-steps-to-secure-open-ssh/](https://blog.devolutions.net/2017/04/10-steps-to-secure-open-ssh/)
- [https://www.layerstack.com/resources/tutorials/Linux-SSH-Security-Best-Practices-to-secure-your-Cloud%20Servers](https://www.layerstack.com/resources/tutorials/Linux-SSH-Security-Best-Practices-to-secure-your-Cloud%20Servers)
