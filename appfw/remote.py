#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

# Written by Daniel Rocher <erable@resydev.fr>
# Portions created by the Initial Developer are Copyright (C) 2016


from threading import Thread
import urllib2


class Remote(Thread):
    def __init__(self, url):
        Thread.__init__(self)
        self.url=url

    def run(self):
        try:
            urllib2.urlopen(self.url, timeout=10)
        except:
            pass

if __name__ == '__main__':
    thread = Remote("http://www.resydev.fr")
    thread.start()
    thread.join()

