#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

# Written by Daniel Rocher <erable@resydev.fr>
# Portions created by the Initial Developer are Copyright (C) 2016


import subprocess
from threading import Thread


class AuditProcess(Thread):
    def __init__(self, callback=None):
        Thread.__init__(self)
        self.process=None
        self.callback=callback
        self.running=True

    def stdout(self, msg):
        self.callback(msg)

    def run(self):
        if self.process :
            return
        try:
            self.process = subprocess.Popen(["auditd", "-f" ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            for line in iter(self.process.stdout.readline, ''):
                self.stdout(line.replace('\n', ''))
                if self.process==None :
                    self.running=False
                    return

        except OSError:
            print "Failed to use auditd."
            self.process=None
            self.running=False

    def isRunning(self):
        return self.running

    def stop(self):
        if self.process==None :
            return
        self.process.kill()
        self.process=None
        self.running=False


if __name__ == '__main__':
    import signal, time
    global thread

    def callback(msg):
        print msg

    def signal_handler(signal, frame):
        print "Wait. Stopping all ..."
        global thread
        thread.stop()
        thread.join()
        thread=None

    thread = AuditProcess(callback)
    print "Quit with CTRL+C"

    signal.signal(signal.SIGINT, signal_handler)
    thread.start()

    while thread:
       time.sleep(1)


