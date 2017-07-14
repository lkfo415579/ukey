#!/usr/bin/python
#-*- coding: utf-8 -*-

import os
import sys
import time
from socket import *
from threading import *
from Queue import *

from ukey import *


#-- 检测是否过期 --#
def ukey_is_expired() :
    rc = False;

    try :
        ukey_ctx = UkeyMgr();
        ukey_ctx.enable_exception( False);
        if ukey_ctx.find_ukey() :
            if (ukey_ctx.read_ver_info() == False) or (ukey_ctx.rest_of_time() <= 0) :
                rc = True;
            else :
                rc = False;
        else :
            rc = True;
    except Exception, e:
        rc = True;
    return rc;
#--end->Func: ukey_is_expired --#


#-- 检测是否存在 --#
def ukey_is_alive() :
    rc = True;
    try :
        ukey_ctx = UkeyMgr();
        ukey_ctx.enable_exception( False);

        if (ukey_ctx.find_ukey() is None) :
            rc = False;
        else :
            rc = True;
    except :
        rc = False;
    return rc;
#--end->Func: ukey_is_alive--#


#-- 衰减计费请以分钟为单位 --#
def ukey_elapsed_time( minutes=0) :
    rc = True;

    if ( ukey_is_alive()) :
        try :
            ukey_ctx = UkeyMgr();
            ukey_ctx.enable_exception( False);

            if ( ukey_ctx.set_elapsed_time( minutes)) :
                rc = True;
            else :
                rc = False;
        except :
            rc = False;
    else :
        rc = False;

    return rc;
#--end->Func: ukey_elapsed_time--#


#-- 更新UKEY的线程 --#
def update_ukey_do( status_dict, req_queue) :
    start_time = 0;
    end_time   = 0; 
    timer_cnt  = 0;
    timer_cnt_mod = 0;

    check_ukey_start_time = 0;

    while True :
        check_ukey_end_time = time.time();

        #-- 第一次启动的时候检测一下 --#
        if ( 0 == check_ukey_start_time) :
            check_ukey_start_time = time.time();

            if (True == ukey_is_expired()) :
                status_dict['expired'] = True;
            else :
                status_dict['expired'] = False;

        #-- 每隔10s检测一次 --#
        if ( 10 < int( check_ukey_end_time - check_ukey_start_time)) :
            check_ukey_start_time = check_ukey_end_time;

            if (True == ukey_is_expired()) :
                status_dict['expired'] = True;
            else :
                status_dict['expired'] = False;

        data = None;
        try :
            data = req_queue.get( True, 1);
        except :
            data = None;

        if ( data is not None) and (1 == data[0]) :
            if (0 == start_time) :
                start_time = data[ 1];
                pass;

            #-- 记录最后的时间 --#
            end_time = data[ 1];

            #-- 计算使用时间 --#
            timer_cnt = timer_cnt_mod + int( data[1] - start_time);

            if ( 180 < timer_cnt) :
                while True :
                    rc = ukey_elapsed_time( timer_cnt / 60);
                    if ( rc is True) :
                        timer_cnt_mod = timer_cnt % 60;
                        start_time = 0;
                        timer_cnt  = 0;

                        break;
        else :
            if ( 0 < start_time) :
                timer_cnt_mod = timer_cnt;
            start_time = 0;
            end_time   = 0;
#-- end->Func: update_ukey_do --#



#-- 获取HOST和PORT --#
execfile( "ukey.agent.conf");


#-- 主程序入口 --#
if __name__ == '__main__':
    status_dict = {"expired": True};
    req_queue   = Queue();

    #-- 启动一个线程实时更新UKEY --#
    update_ukey_th = Thread( target=update_ukey_do, args=( status_dict, req_queue, ));
    update_ukey_th.setDaemon( True);
    update_ukey_th.start();
    
    #-- 创建socket --#
    sock_ctx   = socket(AF_INET, SOCK_STREAM, 0);
    sock_ctx.bind( (HOST, PORT) );
    sock_ctx.listen(32);
    while True :
        print "Is expired.", status_dict[ "expired"];
        try :
            sock_clt, clt_addr = sock_ctx.accept();
            data = sock_clt.recv( 16);
            print str( clt_addr), " ==> Req: ", data

            now_time = int( time.time());
            if "status" == data :
                if (False == status_dict[ "expired"] ) :
                    sock_clt.send( "ok");
                    req_queue.put_nowait((1, now_time));
                else :
                    sock_clt.sendall( "expired");
                    req_queue.put_nowait((0, now_time));
            else :
                sock_clt.send( "expired");
                req_queue.put_nowait( (0, now_time));

        except :
            data = None;
        print "Close";
        sock_clt.close();


    #-- 关闭 --#
    sock_ctx.close();



