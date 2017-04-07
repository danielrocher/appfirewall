#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

# Written by Daniel Rocher <erable@resydev.fr>
# Portions created by the Initial Developer are Copyright (C) 2016


from threading import Thread, Lock
import auditprocess
import re, ipaddress

class SyscallConnectRecord():
    def __init__(self):
        self.ppid = None
        self.pid = None
        self.uid = None
        self.command = None
        self.exe = None
        self.family = None # 02 = IPv4, 0A = IPv6
        self.port = None
        self.address = None

    def isFull(self):
        return (self.ppid and self.pid and self.uid and self.command and self.exe and self.family and self.port and self.address)


class ParseAudit(Thread):
    def __init__(self, debug=False, loglevel=1):
        Thread.__init__(self)
        self.auditprocessthread=None
        self._debug=debug
        self.loglevel=loglevel
        self.SyscallRecord=None
        self.lastSyscallMatch=False
        self.dstSockTable=[]
        self.dstSockDic={}
        self.limitsizeoftable=130 # size of cache entries
        self.lock = Lock()
        self.proctitleEnabled=False

    def debug(self, msg, level=1):
        if self._debug and level<=self.loglevel:
            print(msg)

    def addRecordToCache(self):
        msg= "auditd | exe=%s, command=%s, ppid=%s, pid=%s, uid=%s, family=%s, address=%s, port=%s" \
           % (self.SyscallRecord.exe, self.SyscallRecord.command, self.SyscallRecord.ppid, self.SyscallRecord.pid, self.SyscallRecord.uid, self.SyscallRecord.family, self.SyscallRecord.address, self.SyscallRecord.port)

        self.debug(msg,1)

        # update cache
        self.lock.acquire()
        if (self.SyscallRecord.address, self.SyscallRecord.port) not in self.dstSockTable:
            self.dstSockTable.append((self.SyscallRecord.address, self.SyscallRecord.port))
            self.dstSockDic[(self.SyscallRecord.address, self.SyscallRecord.port)]=(self.SyscallRecord.exe, self.SyscallRecord.command, self.SyscallRecord.pid, self.SyscallRecord.ppid) # store action in dictionary (socket destination)
            
            # purge cache
            try:
                if len(self.dstSockTable)>self.limitsizeoftable:
                    del self.dstSockDic[self.dstSockTable[0]]
                    del self.dstSockTable[0] # remove oldest
            except:
                print "error : impossible to purge ! "
        self.lock.release()
        self.SyscallRecord=None
        self.lastSyscallMatch=False


    def parseSysCallMsg(self, msg):
        """Parse auditd SYSCALL message"""
        # 42 : connect
        # 44 : sendto
        # 46 : sendmsg
        matchObj = re.match( r'^type=SYSCALL\s+.*\s+syscall=(42|44|46)\s+.*\s+ppid=(\d+)\s+pid=(\d+)\s+.*\s+uid=(\d+)\s+.*\s+comm=(.+)\s+exe=(\S+)\s+.*', msg)
        if matchObj:
            self.SyscallRecord=SyscallConnectRecord()
            self.lastSyscallMatch=True
            self.SyscallRecord.ppid=matchObj.group(2)
            self.SyscallRecord.pid=matchObj.group(3)
            self.SyscallRecord.uid=matchObj.group(4)
            self.SyscallRecord.command=matchObj.group(5).replace('"', '')
            self.SyscallRecord.exe=matchObj.group(6).replace('"', '')

    def parseSockAddrMsg(self, msg):
        """Parse auditd SOCKADDR message"""
        matchObj = re.match( r'^type=SOCKADDR.*\s+saddr=(\S+)', msg)
        if matchObj:
            family=None
            port=None
            address=None
            saddr=matchObj.group(1)
            if len(saddr)>=2:
                family=saddr[0:2]

            if family=="02": # ipv4
                try:
                    address=int(saddr[8:16],16)
                    address=ipaddress.ip_address(address).__str__().encode('ascii')
                except:
                    address=None
                    print "error : Impossible to unpack ipv4 address : %s !" % saddr

            elif family=="0A": # ipv6
                try:
                    address=int(saddr[16:48],16)
                    address=ipaddress.ip_address(address).__str__().encode('ascii')
                except:
                    address=None
                    print "error : Impossible to unpack ipv6 address : %s !" % saddr
                
            if family=="02" or family=="0A":
                try:
                    port=saddr[2:8]
                    port=int(port,16)
                except:
                    port=None
                    print "error : Impossible to unpack port : %s !" % saddr

                if address and port and (address, port) not in self.dstSockTable:
                    self.SyscallRecord.family=family
                    self.SyscallRecord.port=port
                    self.SyscallRecord.address=address

                    if not self.proctitleEnabled and self.SyscallRecord.isFull():
                        self.addRecordToCache()



    def parseProctitleMsg(self, msg):
        """Parse auditd PROCTITLE message"""
        matchObj=re.match( r'^type=PROCTITLE.*\s+msg=.+\s+proctitle=(.*)', msg)
        if matchObj:
            try:
                command=matchObj.group(1).decode("hex").replace('\x00', ' ')
                self.SyscallRecord.command=command
            except:
                self.SyscallRecord.command=matchObj.group(1).replace('"', '')

        self.SyscallRecord.command=" ".join(self.SyscallRecord.command.split()[0:4]) # keep 3 args
        if self.SyscallRecord.isFull():
            self.addRecordToCache()


    def callback(self, msg):
        self.debug(msg, 8)
        if msg.startswith('type=SYSCALL'):
            self.parseSysCallMsg(msg)

        elif msg.startswith('type=SOCKADDR') and self.lastSyscallMatch and self.SyscallRecord!=None:
            self.parseSockAddrMsg(msg)

        # proctitle is not present on old versions of auditd
        elif msg.startswith('type=PROCTITLE'):
            if not self.proctitleEnabled:
                self.proctitleEnabled=True
            if  self.lastSyscallMatch and self.SyscallRecord!=None:
                self.parseProctitleMsg(msg)


    def getProcessNameAndPidFromDestination(self, dstaddress, dstport):
            ppid=None
            pid=None
            program_name=None
            command=None
            self.lock.acquire()
            if (dstaddress, dstport) in self.dstSockTable:
                try:
                    program_name, command, pid, ppid=self.dstSockDic[(dstaddress, dstport)]
                except:
                    pass

            elif dstport==0:
                # not TCP, not UDP !!!
                for address, port in reversed(self.dstSockTable): # reversed because newer were added at the end of this list
                    if address==dstaddress:
                        try:
                            program_name, command, pid, ppid=self.dstSockDic[(address, port)]
                        except:
                            pass
                        break
            self.lock.release()
            if pid==None:
                return False # PID not found

            return program_name, command, pid, ppid

    def isRunning(self):
        return self.auditprocessthread.isRunning()

    def run(self):
        self.debug("Starting Auditd ...", 0)
        if self.auditprocessthread :
            return
        self.auditprocessthread = auditprocess.AuditProcess(self.callback)
        self.auditprocessthread.start()
        self.debug("Auditd started", 0)

    def stop(self):
        self.debug("Stopping Auditd ...", 0)
        if self.auditprocessthread==None :
            return
        self.auditprocessthread.stop()
        self.auditprocessthread.join()
        self.auditprocessthread=None
        self.debug("Auditd stopped", 0)


if __name__ == '__main__':
    import signal, time
    global thread
    thread = ParseAudit(debug=True, loglevel=1)
    print "Quit with CTRL+C"

    def signal_handler(signal, frame):
        print "Wait. Stopping all ..."
        global thread
        thread.stop()
        thread.join()
        thread=None

    signal.signal(signal.SIGINT, signal_handler)
    thread.start()

    while thread:
       time.sleep(1)


