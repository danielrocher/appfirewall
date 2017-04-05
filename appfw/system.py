#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

# Written by Daniel Rocher <erable@resydev.fr>
# Portions created by the Initial Developer are Copyright (C) 2016

import os, re, ipaddress, psutil


class System():
    def __init__(self, debug=False):
        self.debug=debug

    def printDebug(self, msg):
        if self.debug:
            print str(msg)

    def getProcessNameAndParentFromPid(self, pid):
        program_name=None
        cmdline=None
        ppid=None
        p = psutil.Process(pid)
        try:
            program_name=p.exe()
            ppid = p.ppid()
            cmdline=p.cmdline()
        except:  # old version
            program_name=p.exe
            ppid = p.ppid
            cmdline=p.cmdline
        if isinstance(cmdline, list):
            cmdline=" ".join(cmdline[0:4]) # keep 3 args
        return program_name, cmdline, ppid


    def convertIPadress(self, address):
        """
        Convert IP Address.
        IPv4 : 19CEFCC6 -> 198.252.206.25
        IPv6 : B80D012001F100000000000001000000 -> 2001:0DB8:0000:F101:0000:0000:0000:0001
        """
        if len(address)>8:
            # IPv6
            l=[ address[i:i+4] for i in range(0, 32, 4) ]
            address=""
            for i in range(4):
                a=l[i*2+1]
                b=l[i*2]
                if len(address)>0:
                    address+=":"
                address+=a[2]+a[3]+a[0]+a[1]+":"+b[2]+b[3]+b[0]+b[1]
            return address
        else:
            # IPv4
            return '.'.join([ str(int(address[i:i+2],16)) for i in range(6, -2, -2) ])


    def getPIDfromFD(self, _fd):
        """Returns the PID that uses this FD (file descriptor)"""
        for pid in os.listdir("/proc/"):
            if not pid.isdigit(): continue
            path = "/proc/%s/fd/" % pid
            try:
                for fd in os.listdir(path):
                    f = os.readlink(path+fd)
                    if "socket:" in f:
                        matchObj = re.match( r'^socket\:\[(\d+)\]', f)
                        if matchObj:
                            if int(matchObj.group(1))==_fd:
                                return pid
            except:
                pass

        return None


    def getFDfromPayload(self, payload, fromsource=False):
        """Returns the FD (file descriptor) that uses this connection"""
        ip_version_number, protocol, srcaddress, srcport, dstaddress, dstport = payload
        # ipv6
        if ip_version_number==0X0A:
            protocol+="6"
        with open("/proc/net/%s" % protocol,"r") as f:
            for line in f.readlines():
                matchObj = re.match( r'^\s+\d+:\s+(\S+):(\S+)\s+(\S+):(\S+)\s+.*', line)
                if matchObj:
                    try:
                        _src_port=int(matchObj.group(2),16)
                        if _src_port!=srcport:
                            continue
                        _dst_port=int(matchObj.group(4),16)
                        if (_dst_port!=dstport and not fromsource):
                            continue
                    except:
                        print "error : Impossible to unpack port !"
                    try:
                        # _src_address=self.convertIPadress(matchObj.group(1))
                        _dst_address=self.convertIPadress(matchObj.group(3))
                    except:
                        print "error : Impossible to unpack IP address !"
                    # Normalize IPv6 before compare
                    if ip_version_number==0X0A:
                        dstaddress=ipaddress.IPv6Address(unicode(dstaddress))
                        _dst_address=ipaddress.IPv6Address(unicode(_dst_address))
                    # self.printDebug(":%s -> %s:%s" % (_src_port, _dst_address, _dst_port))
                    if (fromsource and _src_port==srcport) or (_src_port==srcport and _dst_address==dstaddress and _dst_port==dstport):
                        try:
                            fd=int(line.split()[9])
                            return fd
                        except:
                            pass
        return None


    def getProcessNameAndPidFromPayload(self, payload):
        """Returns the program's name, PID and the PPID that generated by this packet"""
        pid=None
        ppid=None
        program_name=None

        fd=self.getFDfromPayload(payload)

        if fd==None:
            return False

        pid=self.getPIDfromFD(fd)

        if pid==None:
            return False # PID not found because it died  ...
            
        program_name, cmdline, ppid=self.getProcessNameAndParentFromPid(int(pid))

        if ppid==None or program_name==None:
            return False
        return program_name, cmdline, pid, ppid


    def getProcessNameAndPidFromListenSourcePort(self, ip_version_number, protocol, srcport):
        """Returns the program's name, PID and the PPID that generated by this packet (from listen source port)"""
        pid=None
        ppid=None
        program_name=None
        if ip_version_number==0X0A:
            # IPv6
            address="0000:0000:0000:0000:0000:0000:0000:0000"
        else:
            # IPv4
            address="0.0.0.0"
        fd=self.getFDfromPayload((ip_version_number, protocol, address, srcport, address, 0), fromsource=True)

        if fd==None:
            return False

        pid=self.getPIDfromFD(fd)

        if pid==None:
            return False # PID not found because it died  ...

        program_name, cmdline, ppid=self.getProcessNameAndParentFromPid(int(pid))

        if ppid==None or program_name==None:
            return False

        return program_name, cmdline, pid, ppid


if __name__ == '__main__':
    import subprocess, time
    # Payload for test
    address_src="192.168.1.12"
    port_src="1111"
    address_dst="192.168.1.254"
    port_dst="46666"
    run_cmd=["nc","-u",address_dst, port_dst, "-s",address_src ,"-p", port_src]

    try:
        p = subprocess.Popen(run_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print "Payload : ", " ".join(run_cmd)
    except:
        pass

    payload = ( 0x02, "udp", address_src, int(port_src), address_dst,int( port_dst))
    time.sleep(0.001)
    s=System()
    r=s.getProcessNameAndPidFromPayload(payload)
    print "Found : ", r
    try:
        p.terminate()
        p.kill()
    except:
        pass

