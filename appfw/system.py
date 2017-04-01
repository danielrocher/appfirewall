#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

# Written by Daniel Rocher <erable@resydev.fr>
# Portions created by the Initial Developer are Copyright (C) 2016

import subprocess, psutil

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
            cmdline=" ".join(cmdline)
        return program_name, cmdline, ppid

    def getProcessNameAndPidFromPayload(self, payload):
        """Returns the program's name, PID and the PPID that generated by this packet"""
        pid=None
        ppid=None
        program_name=None
        protocol, srcaddress, srcport, dstaddress, dstport = payload

        # search connection
        p = subprocess.Popen(["fuser", "-n", protocol, "{},{},{}".format(srcport, dstaddress, dstport) ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr=p.communicate()

        try:
            pid=int(stdout.split()[0])
        except:
            pid=None

        if pid==None:
            return False # PID not found because it died  ...
            
        program_name, cmdline, ppid=self.getProcessNameAndParentFromPid(pid)
        
        if ppid==None or program_name==None:
            return False

        return program_name, cmdline, str(pid), ppid


    def getProcessNameAndPidFromListenSourcePort(self, protocol, srcport):
        """Returns the program's name, PID and the PPID that generated by this packet (from listen source port)"""
        pid=None
        ppid=None
        program_name=None

        p = subprocess.Popen(["fuser", "{}/{}".format(srcport, protocol) ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr=p.communicate()

        try:
            pid=int(stdout.split()[0])
        except:
            pid=None

        if pid==None:
            return False # PID not found because it died  ...

        program_name, cmdline, ppid=self.getProcessNameAndParentFromPid(pid)
        
        if ppid==None or program_name==None:
            return False

        return program_name, cmdline, str(pid), ppid



if __name__ == '__main__':
    payload = ( "udp", "172.30.230.14", "50405", "10.192.168.25", "2565" )
    s=System()
    print s.getProcessNameAndPidFromPayload(payload)
