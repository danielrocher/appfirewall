#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

# Written by Daniel Rocher <erable@resydev.fr>
# Portions created by the Initial Developer are Copyright (C) 2016


from socket import AF_INET, AF_INET6, inet_ntop
import nfqueue
import time, urllib

from dpkt import ip, ip6
from threading import Thread, Lock

from appfw.remote import Remote
from appfw.system import System
from appfw.queueasyncthread import QueueAsyncThread
from appfw.parseaudit import ParseAudit


class Mode():
    monitor = 1
    whitelist = 2
    blacklist = 3

class IPversion():
    v4 = 1
    v6 = 2


class AppfwCore(Thread):
    def __init__(self, queue_number=0, mode=Mode.monitor, whitelist=[], blacklist=[], icmp_max_size=0,
            udp_max_size=0, callback_alert=None, debug=False, remote_host=None):
        Thread.__init__(self)
        self.debug=debug
        self.remote_host=remote_host
        self.callback_alert=callback_alert
        self.queue_number=queue_number
        self.mode=mode
        self.monitorlist=[]
        self.srcSockTable=[]
        self.dstSockTable=[]
        self.decisionDic={}
        self.icmp_max_size_cache=[]
        self.udp_max_size_cache=[]
        self.lock_icmp_max_size_cache=Lock()
        self.lock_udp_max_size_cache=Lock()
        self.count = 0
        self.drop = 0
        self.limitsizeoftable=130 # size of cache entries
        self.whitelist=whitelist
        self.blacklist=blacklist
        self.icmp_max_size=icmp_max_size
        self.udp_max_size=udp_max_size
        self.methodCount={}
        self.system=System(debug=debug)
        self.th_queue_async=None
        self.threadauditd=None
        self.lock = Lock()
          
    def printDebug(self, msg):
        if self.debug:
            print(str(msg))

    def alert(self, msg):
        """Send a signal about a suspicious activity"""
        self.printDebug(msg)
        if self.callback_alert:
            self.callback_alert(msg)

    def _setverdict(self, payload, verdict):
        """DROP or ACCEPT packet"""
        payload.set_verdict(verdict)
        if verdict == nfqueue.NF_DROP:
            self.drop+=1


    def callback(self, i, p=None):
        """receive a packet from NF_QUEUE"""
        self.count+=1
        # default action
        action=nfqueue.NF_ACCEPT
        program=None
        pid=None
        ppid=None
        if type(i)==nfqueue.payload:
            payload=i
        elif type(p)==nfqueue.payload:
            payload=p
        else:
            print "Impossible to parse nfqueue callback !"
            return
        size_payload=payload.get_length()

        # self.printDebug ("payload len : %s" % size_payload)
        data = payload.get_data()
        ipversion=IPversion.v4
        try: # try IPv4
            pkt = ip.IP(data)
            protocol = pkt.p
        except:
            try: # try IPv6
                pkt = ip6.IP6(data)
                protocol = pkt.nxt
                ipversion=IPversion.v6
            except:
                print "Impossible to unpack IP. Accept packet"
                self._setverdict(payload, action)
                return 1
        
        # self.printDebug ("protocol : %s" % protocol)

        if ipversion==IPversion.v4:
            ipsource=inet_ntop(AF_INET, pkt.src)
            ipdestination=inet_ntop(AF_INET, pkt.dst)
        else:
            ipsource="%s" % inet_ntop(AF_INET6, pkt.src)
            ipdestination="%s" % inet_ntop(AF_INET6, pkt.dst)

        # self.printDebug ("source : %s" % ipsource)
        # self.printDebug ("dest : %s" % ipdestination)

        # limit ICMP packet size (if enable)
        # 58 = next header for ICMP on IPv6
        if (protocol==ip.IP_PROTO_ICMP or protocol==58) and self.icmp_max_size!=0 and size_payload>self.icmp_max_size:
            addresses="{}->{}".format(ipsource, ipdestination)
            self.lock_icmp_max_size_cache.acquire()
            if addresses not in self.icmp_max_size_cache:
                self.icmp_max_size_cache.append(addresses) # add to cache
                self.alert("ICMP size limit reached (%s > %s) : %s" % (size_payload, self.icmp_max_size, addresses))
                if len(self.icmp_max_size_cache)>self.limitsizeoftable:
                    del self.icmp_max_size_cache[0] # remove oldest
            self.lock_icmp_max_size_cache.release()
            if self.mode!=Mode.monitor:
                action=nfqueue.NF_DROP
                self._setverdict(payload, action)
                return 1

        # limit UDP packet size (if enable)
        if (protocol==ip.IP_PROTO_UDP) and self.udp_max_size!=0 and size_payload>self.udp_max_size:
            addresses="{}->{}".format(ipsource, ipdestination)
            self.lock_udp_max_size_cache.acquire()
            if addresses not in self.udp_max_size_cache:
                self.udp_max_size_cache.append(addresses) # add to cache
                self.alert("UDP size limit reached (%s > %s) : %s" % (size_payload, self.udp_max_size, addresses))
                if len(self.udp_max_size_cache)>self.limitsizeoftable:
                    del self.udp_max_size_cache[0] # remove oldest
            self.lock_udp_max_size_cache.release()
            if self.mode!=Mode.monitor:
                action=nfqueue.NF_DROP
                self._setverdict(payload, action)
                return 1

        sport=0
        dport=0
        protocol_name=str(protocol)
        # TCP
        if protocol == ip.IP_PROTO_TCP:
            sport=pkt.tcp.sport
            dport=pkt.tcp.dport
            protocol_name="tcp"

        # UDP
        if protocol == ip.IP_PROTO_UDP:
            sport=pkt.udp.sport
            dport=pkt.udp.dport
            protocol_name="udp"

        # ICMP
        if protocol == ip.IP_PROTO_ICMP:
            protocol_name="icmp"

        if ipversion==IPversion.v4:
           ip_version_number=0x02
        else:
           ip_version_number=0x0A

        lst_payload= (ip_version_number, protocol_name, ipsource, sport, ipdestination, dport )
        #self.printDebug(" sport : %s" % sport)
        #self.printDebug(" dport : %s" % dport)

        in_srcsocktable=False
        in_dstsocktable=False
        # search in cache
        if (protocol, ipsource, sport) in self.srcSockTable: # source socket
            in_srcsocktable=True
        if (protocol, ipdestination, dport) in self.dstSockTable: # destination socket
            in_dstsocktable=True

        # search decision in cache
        if in_srcsocktable==True or in_dstsocktable==True:
            try:
                action=self.decisionDic[(protocol, ipsource, sport)] # from source ?
            except:
                try:
                    action=self.decisionDic[(protocol, ipdestination, dport)] # from destination ?
                except:
                    pass

        else: # new connection (or not in cache)
            self.printDebug ("Payload : %s" % str(lst_payload))
            
            source_inf=None
            res=None

            if self.threadauditd.isRunning():
                source_inf="auditd"
                # Waiting because the packet come before auditd see it ...
                for i in range(20):
                    res = self.threadauditd.getProcessNameAndPidFromDestination(ipdestination, dport)
                    time.sleep(0.0001)
                    if res:
                        break

            if not res and (protocol==ip.IP_PROTO_UDP or protocol==ip.IP_PROTO_TCP):
                source_inf="procfs"
                res = self.system.getProcessNameAndPidFromPayload(lst_payload)

                # This is a dead PID, search if a program listen source port 
                if not res:
                    res = self.system.getProcessNameAndPidFromListenSourcePort(ip_version_number, protocol_name, sport)

            if res:
                program, command, pid, ppid = res
                command=" ".join(command.split()[0:2]) # reduce command
                self.printDebug("Program : {}, Command: {}, pid : {}, ppid : {}, protocol : {} , [{}]:{}->[{}]:{}  (from '{}')".format(program, command, pid, ppid, protocol_name, ipsource, sport, ipdestination, dport, source_inf))
                if self.mode==Mode.monitor and program not in self.monitorlist:
                    self.monitorlist.append(program)
                    self.send_to_remote("mon", program, command)
                    self.alert("%s (pid: %s, ppid: %s) added to list. %s" % (program, pid, ppid ,str(lst_payload)))
                elif self.mode==Mode.whitelist and program not in self.whitelist and command not in self.whitelist:
                    self.alert("'%s' (or '%s') is not in whitelist -> DROP. %s" % (program, command, str(lst_payload)))
                    self.send_to_remote("deny", program, command)
                    action=nfqueue.NF_DROP
                elif self.mode==Mode.blacklist and (program in self.blacklist or command in self.blacklist):
                    self.alert("%s (or '%s') is in blacklist -> DROP. %s" % (program, command, str(lst_payload)))
                    self.send_to_remote("deny", program, command)
                    action=nfqueue.NF_DROP
            # PID not found :-( -> accept payload
            if pid==None:
                source_inf="notfound"
                self.alert("PID not found %s" % str(lst_payload))

            try:
                self.methodCount[source_inf]+=1
            except:
                self.methodCount[source_inf]=1

            # update cache
            self.lock.acquire()
            self.srcSockTable.append((protocol, ipsource, sport))
            self.dstSockTable.append((protocol, ipdestination, dport))
            self.decisionDic[(protocol, ipsource, sport)]=action # store action in dictionary (socket source)
            self.decisionDic[(protocol, ipdestination, dport)]=action # store action in dictionary (socket destination)

            # purge cache
            try:
                if len(self.srcSockTable)>self.limitsizeoftable:
                    del self.decisionDic[self.srcSockTable[0]]
                    del self.srcSockTable[0] # remove oldest
                if len(self.dstSockTable)>self.limitsizeoftable:
                    del self.decisionDic[self.dstSockTable[0]]
                    del self.dstSockTable[0] # remove oldest
            except:
                print "error : impossible to purge ! "
            self.lock.release()

        self._setverdict(payload, action)
        return 1

    def send_to_remote(self, typ, program, command):
        if self.remote_host:
            remote=Remote("%s?type=%s&r=%s&c=%s" % (self.remote_host, typ, urllib.pathname2url(program), urllib.pathname2url(command)))
            remote.start()

    def run(self):
        if self.th_queue_async:
            print "Thread QueueAsyncThread already running"
            return
        if self.threadauditd:
            print "Thread ParseAudit already running"        
            return
        self.th_queue_async = QueueAsyncThread(self.callback, self.queue_number, self.debug)
        self.th_queue_async.start()
        
        self.threadauditd=ParseAudit(debug=self.debug, loglevel=1)
        self.threadauditd.start()

        while self.th_queue_async.is_alive():
            self.th_queue_async.join(1)

        time.sleep(1) # wait, perhaps auditd is trying to start ...
        self.threadauditd.stop()
        self.threadauditd.join()

        self.printDebug("%d packets handled" % self.count)
        self.printDebug("%d packets dropped" % self.drop)
        self.printDebug("Method used : %s" % str(self.methodCount))
        if self.mode==Mode.monitor:
            self.alert("List of programs that have attempted to connect (monitor mode only) : %s" % str(self.monitorlist))
        self.th_queue_async=None
        self.threadauditd=None

    def stop(self):
        self.th_queue_async.stop()
        self.threadauditd.stop()

