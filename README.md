# Appfirewall
Monitor or block outbound traffic (filtered by process). __Experimental__

_This program is licensed to you under the terms of the GNU General Public License version 3_

# Installation


## Module

Appfirewall require NFQUEUE. It's an iptables and ip6tables target which delegate the decision on packets to a userspace software.

```bash
modprobe nfnetlink_queue
```

Check :

```bash
lsmod | grep queue
nfnetlink_queue        20480  1
```


# Usage

It is necessary to insert iptables rules to send traffic to a queue (by default, queue 0).

Examples:
```bash
iptables  -I OUTPUT ! -o lo -j NFQUEUE --queue-bypass
ip6tables -I OUTPUT ! -o lo -j NFQUEUE --queue-bypass
```
 * `--queue-num <number>` : Queue number
 * `--queue-bypass` : The packet are authorized if no software is listening to the queue


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

