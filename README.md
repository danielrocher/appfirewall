# Appfirewall
Monitor or block outbound traffic (filtered by process). __Experimental__

_This program is licensed to you under the terms of the GNU General Public License version 3_

# Installation

Appfirewall requires : netfilter-queue, python2.7, nfqueue-bindings-python, python-dpkt, python-ipaddress, python-enum, python-psutil
 
 
On Debian/Ubuntu :

```bash
apt-get install libnetfilter-queue1, nfqueue-bindings-python python-dpkt python-ipaddress python-enum34 python-psutil
```


## Module nfnetlink_queue

Appfirewall require NFQUEUE. It's an iptables and ip6tables target which delegate the decision on packets to a userspace software.

```bash
modprobe nfnetlink_queue
```

Check :

```bash
lsmod | grep queue
nfnetlink_queue        20480  1
```

## Auditd

Appfirewall is better with Auditd, but it can run without it.

Install Auditd (Debian/Ubuntu) :
```bash
apt-get install auditd
```

Disable and stop service :
```bash
systemctl disable auditd.service
systemctl stop auditd.service
```

# Usage

It is necessary to insert iptables rules to send traffic to a queue (by default, queue 0).

Example :
```bash
iptables  -I OUTPUT ! -o lo -j NFQUEUE --queue-bypass
ip6tables -I OUTPUT ! -o lo -j NFQUEUE --queue-bypass
```
 * `--queue-num <number>` : Queue number
 * `--queue-bypass` : The packet are authorized if no software is listening to the queue

If you use Auditd, delete all and add a rule :
```bash
auditctl -D
auditctl -a exit,always -F arch=b64 -S connect -S sendto -S sendmsg
```

# Debugging

## To monitor the status of _libnetfilter_queue_ :
```bash
watch -n 5 cat /proc/net/netfilter/nfnetlink_queue
1  31621     0 2  4016     0     0        2  1
```

* Queue number
* Process ID: process ID of program listening to the queue
* Queue total: current number of packets waiting in the queue
* Copy mode
* Copy size
* Queue dropped: number of packets dropped because queue was full
* User dropped: number of packets dropped because netlink message could not be sent to userspace.
* Total number of packets sent to queue
* 1

## Test _libnetfilter_queue_ :

In userspace, _queueasyncthread.py_ use libnetfilter_queue (queue 0)

```bash
./appfw/queueasyncthread.py 
Setting callback
Open nfqueue number 0
Queue is ready
Quit with CTRL+C
 17 | 192.168.1.12 > 192.168.1.254
 6 | 192.168.1.12 > 217.160.231.227
 1 | 192.168.1.12 > 192.168.58.1
```

## Test auditd :

### Auditd - Monitor log messages :
```bash
./appfw/auditprocess.py
Quit with CTRL+C
type=SYSCALL msg=audit(1491057722.786:102): arch=c000003e syscall=42 success=yes exit=0 a0=36 a1=7f94fecfedcc a2=10 a3=2 items=0 ppid=1334 pid=4053 auid=4294967295 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=(none) ses=4294967295 comm=444E53205265737E76657220233131 exe="/usr/lib/firefox/firefox" key=(null)
type=SOCKADDR msg=audit(1491057722.786:102): saddr=020000357F0001010000000000000000
```

### Auditd - Parse log messages :



