# Appfirewall
Monitor or block outbound traffic (filtered by process). __Experimental__

_This program is licensed to you under the terms of the GNU General Public License version 3_

# Installation

Appfirewall requires : netfilter-queue, python2.7, nfqueue-bindings-python, python-dpkt, python-ipaddress, python-enum, python-psutil
 
 
On Debian/Ubuntu :

```bash
apt-get install libnetfilter-queue1, nfqueue-bindings-python python-dpkt python-ipaddress python-enum34 python-psutil
```

Install configuration file `/etc/appfirewall.conf` :

`make install_configuration`


Edit this file at your convenience. Example :
```bash
[GLOBAL]

# NetFilter Queue Number
# default = 0
queue-num = 0

# White list
whitelist = /usr/sbin/sshd, /usr/lib/apt/methods/http, /usr/sbin/avahi-daemon, /sbin/dhclient, /usr/sbin/ntpd

# Black list
blacklist = /usr/bin/wget, /bin/nc.openbsd
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

## Audit daemon

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

## Help
./appfirewall.py --help
usage: appfirewall.py [-h] [-v] [-d] [--debug] [-w | -b | -e] [-l]
                      [-t FILENAME]

optional arguments:
  -h, --help            show this help message and exit
  -v, --version         show version
  -d, --daemon          Run as daemon
  --debug               Debug
  -w, --whitelist       accept all in whitelist, finally drop
  -b, --blacklist       drop all in blacklist, finally accept
  -e, --explore         Explore mode (accept all packets)
  -l, --log             log packet filtered to syslog
  -t FILENAME, --trace FILENAME
                        log packet filtered to file


## Monitoring (without dropping packets) and trace to file (example) :
```bash
./appfirewall.py --explore -t journalise.log
```

## Run in 'Whitelist Mode' (accept all in whitelist, finally drop) and log (example) :
```bash
./appfirewall.py --whitelist --log
```

## Run in 'Blacklist Mode' (drop all in blacklist, finally accept) and daemonize (example) :
```bash
./appfirewall.py --blacklist --daemon
```

# Debugging

## Debugging Appfirewall in "Whitelist Mode" (example) :

In this example, only _avahi-daemon_, _dnsmasq_ and _ping_ are allowed. The payload is `nc 192.168.58.1 631`.
```bash
./appfirewall.py --whitelist --debug
'/bin/nc.openbsd' (or 'nc 192.168.58.1') is not in whitelist -> DROP. ('tcp', '192.168.1.12', 43400, '192.168.58.1', 631)
```

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

## Auditd - Monitor log messages :
```bash
./appfw/auditprocess.py
Quit with CTRL+C
type=SYSCALL msg=audit(1491057722.786:102): arch=c000003e syscall=42 success=yes exit=0 a0=36 a1=7f94fecfedcc a2=10 a3=2 items=0 ppid=1334 pid=4053 auid=4294967295 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=(none) ses=4294967295 comm=444E53205265737E76657220233131 exe="/usr/lib/firefox/firefox" key=(null)
type=SOCKADDR msg=audit(1491057722.786:102): saddr=020000357F0001010000000000000000
```

## Auditd - Parse log messages :

```bash
./appfw/parseaudit.py 
Quit with CTRL+C
Starting Auditd ...
Auditd started
auditd | exe=/usr/bin/curl, command=curl resydev.fr, ppid=2817, pid=4490, uid=0, family=02, address=127.0.1.1, port=53
auditd | exe=/usr/bin/curl, command=curl resydev.fr, ppid=2817, pid=4490, uid=0, family=02, address=212.227.247.84, port=80
auditd | exe=/usr/bin/curl, command=curl resydev.fr, ppid=2817, pid=4490, uid=0, family=0A, address=2001:8d8:1001:124c:8ae5:8584:36eb:f01b, port=80
```

