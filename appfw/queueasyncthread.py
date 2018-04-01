#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

# Written by Daniel Rocher <erable@resydev.fr>
# Portions created by the Initial Developer are Copyright (C) 2016


from socket import AF_INET, AF_INET6, inet_ntop
import nfqueue
import asyncore
from threading import Thread


class QueueAsyncThread(asyncore.file_dispatcher, Thread):
    def __init__(self, callback, queue_number=0, debug=False):
        Thread.__init__(self)
        self.debug=debug
        self._stop = False
        self.nf_queue_started=False
        self.queue_number=queue_number
        self.q = nfqueue.queue()
        self.printDebug("Setting callback")
        self.q.set_callback(callback)

    def printDebug(self, msg):
        if self.debug:
            print(str(msg))

    def handle_read(self):
        self.q.process_pending(5)
    
    def writable(self):
        return False
    
    def run(self):
        self.printDebug("Trying to open nfqueue %s ..." % self.queue_number)
        try:
            self.q.fast_open(self.queue_number, AF_INET6)
            self.fd = self.q.get_fd()
            self.q.set_queue_maxlen(100000)
            asyncore.file_dispatcher.__init__(self, self.fd, None)
            self.q.set_mode(nfqueue.NFQNL_COPY_PACKET)
        except:
            self._stop = True
            print "Impossible to open NetFilter Queue {}".format(self.queue_number)
            return

        self.nf_queue_started=True
        self.printDebug("Queue {} is ready".format(self.queue_number))

        while not self._stop:
            asyncore.poll(timeout=0.1)
        
        if self.nf_queue_started:
            self.printDebug("Stopping QueueAsyncThread ...")
            self.printDebug("Unbind nf_queue")
            try:
                self.q.unbind(AF_INET6)
                self.printDebug("Close nf_queue {}".format(self.queue_number))
                self.q.close()
            except:
                pass
            self.nf_queue_started=False
            self.printDebug("QueueAsyncThread stopped")

    def stop(self):
        self._stop=True


if __name__ == '__main__':
    import signal, time
    from dpkt import ip, ip6
    global thread
    
    def signal_handler(signal, frame):
        print "Wait. Stopping all ..."
        global thread
        thread.stop()
        thread.join()
        thread=None

    def callback(i, p=None):
        protocol=None
        ipsource=None
        ipdestination=None
        if type(i)==nfqueue.payload:
            payload=i
        elif type(p)==nfqueue.payload:
            payload=p
        else:
            print "Impossible to parse nfqueue callback !"
            return
        data = payload.get_data()
        try: # try IPv4
            pkt = ip.IP(data)
            protocol = pkt.p
            ipsource=inet_ntop(AF_INET, pkt.src)
            ipdestination=inet_ntop(AF_INET, pkt.dst)
        except:
            try: # try IPv6
                pkt = ip6.IP6(data)
                protocol = pkt.nxt
                ipsource="%s" % inet_ntop(AF_INET6, pkt.src)
                ipdestination="%s" % inet_ntop(AF_INET6, pkt.dst)
            except:
                print "Impossible to unpack IP"

        print " %s | %s > %s" % (protocol, ipsource, ipdestination)
        payload.set_verdict(nfqueue.NF_ACCEPT)

    thread = QueueAsyncThread(callback, 0, debug=True)
    print "Quit with CTRL+C"
    
    signal.signal(signal.SIGINT, signal_handler)
    thread.start()

    while thread:
       time.sleep(1)


        
