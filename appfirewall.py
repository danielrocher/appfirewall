#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

# Written by Daniel Rocher <erable@resydev.fr>
# Portions created by the Initial Developer are Copyright (C) 2016


__version__="1.0"


import argparse, ConfigParser
import sys, os, time, signal
import logging
import logging.handlers

from appfw.appfwcore import *

# global
fileconfname='/etc/appfirewall.conf'


class Main():
    def __init__(self, fileconfname):
        self.fileconfname=fileconfname
        self.debug=False
        self.daemon=False
        self.queue_num=0
        self.whitelist=[]
        self.blacklist=[]
        self.icmp_max_size=0 # no limit
        self.udp_max_size=0  # no limit
        self.mode=Mode.monitor
        self.log=False
        self.trace=False
        self.trace_filename=None
        self.filetrace_descriptor=None
        self.my_logger=None
        self.appfwcore_thread=None

        # parse arguments
        self.parseArgs()
        # Read config file
        self.readConfigFile(self.fileconfname)
        if self.mode != Mode.monitor:
            if self.mode==Mode.whitelist:
                self.printDebug("WhiteList : %s" % self.whitelist)
            else:
                self.printDebug("BlackList : %s" % self.blacklist)
        else:
            self.printDebug("Monitor mode set")

        if self.icmp_max_size!=0:
            self.printDebug("limit the size of ICMP packets enabled: %s" % self.icmp_max_size)
        if self.udp_max_size!=0:
            self.printDebug("limit the size of UDP packets enabled: %s" % self.udp_max_size)

        # if log
        if self.log:
            self.my_logger = logging.getLogger('appfirewall')
            self.my_logger.setLevel(logging.DEBUG)
            handler = logging.handlers.SysLogHandler(address = '/dev/log')
            self.my_logger.addHandler(handler)

        # Run process
        if self.daemon:
            self.daemonize()

        # SIGINT for interrupt program
        signal.signal(signal.SIGINT, self.signal_handler)
        
        self.appfwcore_thread=AppfwCore(self.queue_num, mode=self.mode, whitelist=self.whitelist, blacklist=self.blacklist, icmp_max_size=self.icmp_max_size,
            udp_max_size=self.udp_max_size, callback_alert=self.callbackAlert, debug=self.debug)
        self.appfwcore_thread.start()
        
        while self.appfwcore_thread:
            time.sleep(1)

        if self.filetrace_descriptor:
            try:
                self.filetrace_descriptor.close()
            except:
                print "Impossible to close file %s" % self.trace_filename


    def signal_handler(self, signal, frame):
        self.printDebug("Wait. Stopping all ...")
        self.appfwcore_thread.stop()
        self.appfwcore_thread.join()
        self.appfwcore_thread=None
        

    def daemonize(self):
        """daemonize (run as server)"""
        try:
            pid = os.fork()
            if pid > 0:
                sys.exit(0)
        except OSError as e:
            print "fork failed: {0} ({1})".format(e.errno, e.strerror)
            sys.exit(1)

        
    def printDebug(self, msg):
        if self.debug:
            print(str(msg))

    def parseArgs(self):
        # Parse Args
        parser = argparse.ArgumentParser()
        parser.add_argument("-v", "--version", help="show version", action="store_true")
        parser.add_argument("-d", "--daemon", help="Run as daemon", action="store_true")
        parser.add_argument("--debug", help="Debug", action="store_true")
        group = parser.add_mutually_exclusive_group()
        group.add_argument("-w", "--whitelist", help="accept all in whitelist, finally drop", action="store_true")
        group.add_argument("-b", "--blacklist", help="drop all in blacklist, finally accept", action="store_true")
        group.add_argument("-m", "--monitor", help="Monitor mode (accept all packets)", action="store_true")
        parser.add_argument("-l", "--log", help="log packet filtered to syslog", action="store_true")
        parser.add_argument("-t", "--trace", metavar="FILENAME", help="log packet filtered to file")
        args=parser.parse_args()

        appName=sys.argv[0]
        if args.version==True:
            print ("{0} version : {1}".format(appName, __version__))
            sys.exit()
        if args.debug==True:
            self.debug=True

        if args.daemon==True:
            self.daemon=True

        if args.blacklist==True:
            self.mode=Mode.blacklist
        elif args.whitelist==True:
            self.mode=Mode.whitelist
        else: # default mode
            self.mode=Mode.monitor

        if args.log==True:
            self.log=True
        if args.trace:
            self.trace=True
            self.trace_filename=args.trace

    def callbackAlert(self, msg):
        # if log
        if self.log:
            self.my_logger.critical("appFirewall: %s" % msg)
        # if trace to file
        if self.trace:
            if self.filetrace_descriptor==None or self.filetrace_descriptor.closed:
                try:
                    self.filetrace_descriptor=open(self.trace_filename, "a")
                except:
                    print "Impossible to create file %s" % self.trace_filename
            try:
                self.filetrace_descriptor.write("%s - %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), msg))
                self.filetrace_descriptor.flush()
            except:
                print "Impossible to write to file %s" % self.trace_filename


            
    def getListFromLineParsing(self, string):
        if not ',' in string:
            string +=','
        tmplist=string.strip().split(',')
        newlist=[]
        for arg in tmplist:
            if arg!="":
                newlist.append(arg.strip())
        return newlist

    def readConfigFile(self, filename):
        config = ConfigParser.ConfigParser()
        config.read(self.fileconfname)
        try:
            # section DEFAULT
            self.queue_num=config.getint("GLOBAL", "queue-num")
            self.whitelist=self.getListFromLineParsing(config.get("GLOBAL", "whitelist"))
            self.blacklist=self.getListFromLineParsing(config.get("GLOBAL", "blacklist"))
            self.icmp_max_size=config.getint("GLOBAL", "icmp_max_size")
            self.udp_max_size=config.getint("GLOBAL", "udp_max_size")
        except:
            print "Unable to retrieve configuration data in {} ({})".format(filename, sys.exc_info()[0])


if __name__ == "__main__":
    Main(fileconfname)



