#!/usr/bin/python
#-*- coding:utf-8 -*-

import os
import sys
import time

from socket import *

sock_conn = socket( AF_INET, SOCK_DGRAM);
while True:
    try :
        rc = sock_conn.sendto( "status", ("10.0.100.145", 9999));
    except :
        pass;

    print "------------------------"
    data, addr = sock_conn.recvfrom(16);
    print data;

    time.sleep( 1);

sock_conn.close();

