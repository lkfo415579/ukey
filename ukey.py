#!/usr/bin/env python
#encoding=utf-8

import serial
import glob
import sys
import singleton
from ctypes import *
import threading
import time
import traceback
import crc32
import random
from aes import AES

class TTime(LittleEndianStructure):
    pass
TTime._pack_ = 1
TTime._fields_ = [
                ('year',  c_uint16), 
                ('month', c_uint8), 
                ('day',   c_uint8), 
                ('hour',  c_uint8), 
                ('minute',c_uint8), 
                ('second',c_uint8), 
                ('dummy', c_uint8)
                ]
                
class TCmdContents(Union):
    pass
TCmdContents._pack_=1
TCmdContents._fields_=[
                ('data',            c_uint32 * 28), 
                ('first_use_date',  TTime), 
                ('expired_time',    c_uint32), 
                ('comment',         c_uint8 * 100), 
                ('elapsed_time',    c_uint32),
                ('user_data',       c_uint8 * 32),  
                ('encrypt_data',    c_uint8 * 112) 
                ]

class TPktCmd(LittleEndianStructure):
    pass
TPktCmd._pack_ = 1
TPktCmd._fields_=[
                ('head',    c_uint32),
                ('cmd',     c_uint16),
                ('contents',TCmdContents),
                ('crc32',   c_uint32), 
                ('check',   c_uint16), 
                ('tail',    c_uint32)
                ]



class TPktUpdate(LittleEndianStructure):
    pass
TPktUpdate._pack_ = 1
TPktUpdate._fields_=[
                ('head',    c_uint32),
                ('cmd',     c_uint16),
                ('published_date',    TTime),
                ('expired_date',  TTime), 
                ('first_time',  TTime), 
                ('expired_time',  c_uint32), 
                ('check',   c_uint16), 
                ('tail',    c_uint32)
                ]


class TVerInfo(LittleEndianStructure):
    pass
TVerInfo._pack_ = 1
TVerInfo._fields_=[
                ('type',            c_uint16),
                ('first_use_date',  TTime), 
                ('expired_time',    c_uint32), 
                ('rest_of_time',    c_uint32), 
                ('user_data',       c_uint8 * 32)
                ]
                
class TUidandComment(LittleEndianStructure):
    pass
TUidandComment._pack_ = 1
TUidandComment._fields_=[
                ('comment',    c_uint8 * 100), 
                ('uid',        c_uint8 * 12)
                ]
                
class TRecvContents(Union):
    pass
TRecvContents._pack_=1
TRecvContents._fields_=[
                        ('rand_data', c_uint32 * 28), 
                        ('ver_info',  TVerInfo), 
                        ('uid_comment',  TUidandComment), 
                        ('encrypt_data',  c_uint8 * 112), 
                        ]
class TPktRecv(LittleEndianStructure):
    pass
    
TPktRecv._pack_ = 1
TPktRecv._fields_=[
                ('head',    c_uint32),
                ('result',  c_uint16),
                ('contents',TRecvContents), 
                ('crc32',   c_uint32), 
                ('check',   c_uint16), 
                ('tail',    c_uint32)
                ]
                
PKT_HEAD = 0xaa55ff00
PKT_TAIL = 0x10ff55aa
BAUDRATE = 9600
OUR_KEY = (0x2b, 0x7e, 0x15, 0x16, 0x18, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c)

class UkeyMgr(singleton.Singleton):
    __is_init = False
    def __init__(self):
        if UkeyMgr.__is_init:
            return 
            
        UkeyMgr.__is_init = True
        super(UkeyMgr,  self).__init__()
        self.__comment = ""
        self.__uid = ""
        self.__first_use_date = (0, 0, 0, 0, 0, 0)
        self.__expired_time = 0
        self.__rest_of_time = 0
        self.__user_data = ""
        self.__use_exception = False
        
        self.__port = self.find_ukey()
        if self.__port != None:
            self.read_ver_info()
        else:
            UkeyMgr.__is_init = False
            #raise Exception("CAN NOT find a ukey.")
        
    def status(self):
        if self.__port == None:
            #if self.__use_exception:
                #raise Exception("CAN NOT find a ukey.")
            return False
        else:
            return True
            
    def enable_exception(self,  en):
        if en:
            self.__use_exception = True
        else:
            self.__use_exception = False
        
    def first_use_date(self):
        return self.__first_use_date
        
    def uid(self):
        return self.__uid
        
    def comment(self):
        return self.__comment
        
    def expired_time(self):
        return self.__expired_time
        
    def rest_of_time(self):
        return self.__rest_of_time
        
    def user_data(self):
        return self.__user_data
        
    def __encrypt_send_pkt(self, pkt):
        our_key = OUR_KEY
        engine = AES()

        send = cast(pkt, POINTER(TPktCmd)).contents
        src = list()
        for i in xrange(112):
            src.append(send.contents.encrypt_data[i])
        
        encrypt_pkt = (c_uint8 * len(pkt))()
        #encrypt_pkt = ' ' * len(pkt)
        dest = cast(encrypt_pkt, POINTER(TPktCmd)).contents
        #print 'start:'
        for i in xrange(112 / 16):
            ec_src = engine.encrypt(src[(i * 16):(i * 16 + 16)], our_key, engine.keySize["SIZE_128"])
            #print ec_src
            for j in xrange(16):
                dest.contents.encrypt_data[i * 16 + j] = ec_src[j]
                
        dest.head = send.head
        dest.cmd = send.cmd
        dest.crc32 = send.crc32
        dest.check = send.check
        dest.tail = send.tail
        return encrypt_pkt
        #calc_out = engine.encrypt(test_in,  test_key,  engine.keySize["SIZE_128"])
        
    def __decrypt_recv_pkt(self,  pkt):
        our_key = OUR_KEY
        engine = AES()

        recv = cast(pkt,  POINTER(TPktRecv)).contents
        src = list()
        for i in xrange(112):
            src.append(recv.contents.encrypt_data[i])
        
        decrypt_pkt = (c_uint8 * len(pkt))()
        dest = cast(decrypt_pkt, POINTER(TPktRecv)).contents
        
        for i in xrange(112 / 16):
            dc_src = engine.decrypt(src[(i * 16):(i * 16 + 16)], our_key, engine.keySize["SIZE_128"])
            for j in xrange(16):
                dest.contents.encrypt_data[i * 16 + j] = dc_src[j]
                
        dest.head = recv.head
        dest.result = recv.result
        dest.crc32 = recv.crc32
        dest.check = recv.check
        dest.tail = recv.tail
        return decrypt_pkt
        
        
    def __print_pkt(self,  pkt):
        print "print packet data:"
        if type(pkt) == str:
            for i in xrange(len(pkt)):
                print hex(ord(pkt[i])), 
        else:
            for i in xrange(len(pkt)):
                print hex(pkt[i]), 
        print "end."
        
    def show_info(self):
        try:
            print 'comment:', self.__comment
            print 'serial no:', self.__uid
            print 'version Info:', self.__first_use_date,  self.__expired_time,  self.__rest_of_time
            print 'user data:', self.__user_data
        except:
            pass
            
    def __deal_uart_recv_data(self, ser):
        data = ser.read(ser.inWaiting())
        if len(data) < sizeof(TPktRecv):
            print self.__port, 'Receive Error, Data Len:', len(data)
            ser.close()
            if self.__use_exception:
                raise Exception("Can't receive a valid string from " + self.__port)
            return False
        pktRecv = cast(data,  POINTER(TPktRecv)).contents
        crc_check = crc32.crc32(data,  sizeof(TPktRecv) - 10)
        if crc_check == pktRecv.crc32:
            data = self.__decrypt_recv_pkt(data)
            pktRecv = cast(data,  POINTER(TPktRecv)).contents
            if (pktRecv.result == 0x8002
                or pktRecv.result == 0x8003
                or pktRecv.result == 0x8004
                or pktRecv.result == 0x8005
                or pktRecv.result == 0x8007):
                self.__first_use_date = (pktRecv.contents.ver_info.first_use_date.year, 
                            pktRecv.contents.ver_info.first_use_date.month,
                            pktRecv.contents.ver_info.first_use_date.day, 
                            pktRecv.contents.ver_info.first_use_date.hour,
                            pktRecv.contents.ver_info.first_use_date.minute,
                            pktRecv.contents.ver_info.first_use_date.second)
                self.__expired_time = pktRecv.contents.ver_info.expired_time
                self.__rest_of_time = pktRecv.contents.ver_info.rest_of_time
                self.__user_data = ""
                for i in xrange(pktRecv.contents.ver_info.user_data[0]):
                    self.__user_data = self.__user_data + chr(pktRecv.contents.ver_info.user_data[i + 1])
            elif (pktRecv.result == 0x8001
                or pktRecv.result == 0x8006):
                self.__comment = self.__array2str(pktRecv.contents.uid_comment.comment)
                self.__uid = self.__array2hexstr(pktRecv.contents.uid_comment.uid)
            else:
                ser.close()
                if self.__use_exception:
                    raise Exception("Bad ack packet. CODE: " + str(hex(pktRecv.result)))
                return False
                
            ser.close()
            return True
        else:
            ser.close()
            if self.__use_exception:
                raise Exception("crc check error.")
            return False
            
    def read_ver_info(self):
        try:
            ser = serial.Serial(port=self.__port, 
                                baudrate=BAUDRATE, 
                                bytesize=8,
                                stopbits=1, 
                                parity='N',
                                xonxoff=False, 
                                rtscts=False, 
                                dsrdtr=False)
            pkt = (c_uint8 * sizeof(TPktCmd))()
            pktCmd = cast(pkt,  POINTER(TPktCmd)).contents
            pktCmd.head = PKT_HEAD
            pktCmd.cmd = 0x2
            for i in xrange(28):
                pktCmd.contents.data[i] = int(random.random() * 2 ** 32)
            
            pkt = self.__encrypt_send_pkt(pkt)
            pktCmd = cast(pkt,  POINTER(TPktCmd)).contents
            
            pktCmd.crc32 = crc32.crc32(pkt,  sizeof(TPktCmd) - 10)
            pktCmd.tail = PKT_TAIL
            
            chk_sum = 0
            for i in xrange(sizeof(TPktCmd) - 6):
                chk_sum += pkt[i]
            pktCmd.check = chk_sum

            def ser_write():
                try:
                    ser.write(pkt)
                except:
                    pass
                
            ser_write_thread = threading.Thread(target=ser_write, args=())
            ser_write_thread.setDaemon(False)
            ser_write_thread.start()
            ser_write_thread.join(2.0)
            if ser_write_thread.isAlive():
                ser.close()
                ser_write_thread.join(2.0)
                if self.__use_exception:
                    raise Exception("Send data failed.")
                return False
            else:
                time.sleep(2.0)
                return self.__deal_uart_recv_data(ser)
                
        except Exception, e:
            if self.__use_exception:
                raise e
            traceback.print_exc()
            return False
            
            
    def read_comment_uid(self):
        try:
            ser = serial.Serial(port=self.__port, 
                                baudrate=BAUDRATE, 
                                bytesize=8,
                                stopbits=1, 
                                parity='N',
                                xonxoff=False, 
                                rtscts=False, 
                                dsrdtr=False)
            pkt = (c_uint8 * sizeof(TPktCmd))()
            pktCmd = cast(pkt,  POINTER(TPktCmd)).contents
            pktCmd.head = PKT_HEAD
            pktCmd.cmd = 0x1
            for i in xrange(28):
                pktCmd.contents.data[i] = int(random.random() * 2 ** 32)
            
            pkt = self.__encrypt_send_pkt(pkt)
            pktCmd = cast(pkt,  POINTER(TPktCmd)).contents
            
            pktCmd.crc32 = crc32.crc32(pkt,  sizeof(TPktCmd) - 10)
            pktCmd.tail = PKT_TAIL
            
            chk_sum = 0
            for i in xrange(sizeof(TPktCmd) - 6):
                chk_sum += pkt[i]
            pktCmd.check = chk_sum

            def ser_write():
                try:
                    ser.write(pkt)
                except:
                    pass
                
            ser_write_thread = threading.Thread(target=ser_write, args=())
            ser_write_thread.setDaemon(False)
            ser_write_thread.start()
            ser_write_thread.join(2.0)
            if ser_write_thread.isAlive():
                ser.close()
                ser_write_thread.join(2.0)
                if self.__use_exception:
                    raise Exception("Send data failed.")
                return False
            else:
                time.sleep(2.0)
                return self.__deal_uart_recv_data(ser)
        except Exception,  e:
            if self.__use_exception:
                raise e
            traceback.print_exc()
            return False
    
    def set_comment(self,  comment):
        try:
            ser = serial.Serial(port=self.__port, 
                                baudrate=BAUDRATE, 
                                bytesize=8,
                                stopbits=1, 
                                parity='N',
                                xonxoff=False, 
                                rtscts=False, 
                                dsrdtr=False)
            
            pkt = (c_uint8 * sizeof(TPktCmd))()
            pktCmd = cast(pkt,  POINTER(TPktCmd)).contents
            pktCmd.head = PKT_HEAD
            pktCmd.cmd = 0x6
            for i in xrange(28):
                pktCmd.contents.data[i] = int(random.random() * 2 ** 32)
                
            length = len(comment)
            if length >= 100:
                length = 99
            
            for i in xrange(100):
                pktCmd.contents.comment[i] = 0xff
            for i in xrange(length):
                pktCmd.contents.comment[i] = ord(comment[i])
            pktCmd.contents.comment[length] = 0
            
            pkt = self.__encrypt_send_pkt(pkt)
            pktCmd = cast(pkt,  POINTER(TPktCmd)).contents
            
            pktCmd.crc32 = crc32.crc32(pkt,  sizeof(TPktCmd) - 10)
            pktCmd.tail = PKT_TAIL
            
            chk_sum = 0
            for i in xrange(sizeof(TPktCmd) - 6):
                chk_sum += pkt[i]
            pktCmd.check = chk_sum

            def ser_write():
                try:
                    ser.write(pkt)
                except:
                    pass
                
            ser_write_thread = threading.Thread(target=ser_write, args=())
            ser_write_thread.setDaemon(False)
            ser_write_thread.start()
            ser_write_thread.join(2.0)
            if ser_write_thread.isAlive():
                ser.close()
                ser_write_thread.join(2.0)
                if self.__use_exception:
                    raise Exception("Send data failed.")
                return False
            else:
                time.sleep(2.0)
                return self.__deal_uart_recv_data(ser)
                
        except Exception,  e:
            if self.__use_exception:
                raise e
            traceback.print_exc()
            return False
            
    def set_elapsed_time(self,  elapsed_time):
        try:
            ser = serial.Serial(port=self.__port, 
                                baudrate=BAUDRATE, 
                                bytesize=8,
                                stopbits=1, 
                                parity='N',
                                xonxoff=False, 
                                rtscts=False, 
                                dsrdtr=False)
            
            pkt = (c_uint8 * sizeof(TPktCmd))()
            pktCmd = cast(pkt,  POINTER(TPktCmd)).contents
            pktCmd.head = PKT_HEAD
            pktCmd.cmd = 0x5
            for i in xrange(28):
                pktCmd.contents.data[i] = int(random.random() * 2 ** 32)
            pktCmd.contents.elapsed_time = elapsed_time
            
            pkt = self.__encrypt_send_pkt(pkt)
            pktCmd = cast(pkt,  POINTER(TPktCmd)).contents
            
            pktCmd.crc32 = crc32.crc32(pkt,  sizeof(TPktCmd) - 10)
            pktCmd.tail = PKT_TAIL
            
            chk_sum = 0
            for i in xrange(sizeof(TPktCmd) - 6):
                chk_sum += pkt[i]
            pktCmd.check = chk_sum

            def ser_write():
                try:
                    ser.write(pkt)
                except:
                    pass
                
            ser_write_thread = threading.Thread(target=ser_write, args=())
            ser_write_thread.setDaemon(False)
            ser_write_thread.start()
            ser_write_thread.join(2.0)
            if ser_write_thread.isAlive():
                ser.close()
                ser_write_thread.join(2.0)
                if self.__use_exception:
                    raise Exception("Send data failed.")
                return False
            else:
                time.sleep(2.0)
                return self.__deal_uart_recv_data(ser)
        except Exception,  e:
            if self.__use_exception:
                raise e
            traceback.print_exc()
            return False
            
    def set_expired_time(self,  expired_time):
        try:
            ser = serial.Serial(port=self.__port, 
                                baudrate=BAUDRATE, 
                                bytesize=8,
                                stopbits=1, 
                                parity='N',
                                xonxoff=False, 
                                rtscts=False, 
                                dsrdtr=False)
            
            pkt = (c_uint8 * sizeof(TPktCmd))()
            pktCmd = cast(pkt,  POINTER(TPktCmd)).contents
            pktCmd.head = PKT_HEAD
            pktCmd.cmd = 0x3
            for i in xrange(28):
                pktCmd.contents.data[i] = int(random.random() * 2 ** 32)
            pktCmd.contents.expired_time = expired_time

            pkt = self.__encrypt_send_pkt(pkt)
            pktCmd = cast(pkt,  POINTER(TPktCmd)).contents
            
            pktCmd.crc32 = crc32.crc32(pkt,  sizeof(TPktCmd) - 10)
            pktCmd.tail = PKT_TAIL
            
            chk_sum = 0
            for i in xrange(sizeof(TPktCmd) - 6):
                chk_sum += pkt[i]
            pktCmd.check = chk_sum

            def ser_write():
                try:
                    ser.write(pkt)
                except:
                    pass
                
            ser_write_thread = threading.Thread(target=ser_write, args=())
            ser_write_thread.setDaemon(False)
            ser_write_thread.start()
            ser_write_thread.join(2.0)
            if ser_write_thread.isAlive():
                ser.close()
                ser_write_thread.join(2.0)
                if self.__use_exception:
                    raise Exception("Send data failed.")
                return False
            else:
                time.sleep(2.0)
                return self.__deal_uart_recv_data(ser)
        except Exception,  e:
            if self.__use_exception:
                raise e
            traceback.print_exc()
            return False
        
    def set_first_use_date(self,  year, month,  day,  hour, minute,  second):
        try:
            ser = serial.Serial(port=self.__port, 
                                baudrate=BAUDRATE, 
                                bytesize=8,
                                stopbits=1, 
                                parity='N',
                                xonxoff=False, 
                                rtscts=False, 
                                dsrdtr=False)
            
            pkt = (c_uint8 * sizeof(TPktCmd))()
            pktCmd = cast(pkt,  POINTER(TPktCmd)).contents
            pktCmd.head = PKT_HEAD
            pktCmd.cmd = 0x4
            for i in xrange(28):
                pktCmd.contents.data[i] = int(random.random() * 2 ** 32)
            pktCmd.contents.first_use_date.year = year
            pktCmd.contents.first_use_date.month = month
            pktCmd.contents.first_use_date.day = day
            pktCmd.contents.first_use_date.hour = hour
            pktCmd.contents.first_use_date.minute = minute
            pktCmd.contents.first_use_date.second = second
            
            pkt = self.__encrypt_send_pkt(pkt)
            pktCmd = cast(pkt,  POINTER(TPktCmd)).contents

            pktCmd.crc32 = crc32.crc32(pkt,  sizeof(TPktCmd) - 10)
            pktCmd.tail = PKT_TAIL
            
            chk_sum = 0
            for i in xrange(sizeof(TPktCmd) - 6):
                chk_sum += pkt[i]
            pktCmd.check = chk_sum

            def ser_write():
                try:
                    ser.write(pkt)
                except:
                    pass
                
            ser_write_thread = threading.Thread(target=ser_write, args=())
            ser_write_thread.setDaemon(False)
            ser_write_thread.start()
            ser_write_thread.join(2.0)
            if ser_write_thread.isAlive():
                ser.close()
                ser_write_thread.join(2.0)
                if self.__use_exception:
                    raise Exception("Send data failed.")
                return False
            else:
                time.sleep(2.0)
                return self.__deal_uart_recv_data(ser)
        except Exception,  e:
            if self.__use_exception:
                raise e
            traceback.print_exc()
            return False

    def set_user_data(self, user_data):
        try:
            if type(user_data) != str or len(user_data) > 31:
                if self.__use_exception:
                    raise Exception("Bad Parameter.")
                return False
                
            ser = serial.Serial(port=self.__port, 
                                baudrate=BAUDRATE, 
                                bytesize=8,
                                stopbits=1, 
                                parity='N',
                                xonxoff=False, 
                                rtscts=False, 
                                dsrdtr=False)
            
            pkt = (c_uint8 * sizeof(TPktCmd))()
            pktCmd = cast(pkt,  POINTER(TPktCmd)).contents
            pktCmd.head = PKT_HEAD
            pktCmd.cmd = 0x7
            for i in xrange(28):
                pktCmd.contents.data[i] = int(random.random() * 2 ** 32)
                
            pktCmd.contents.user_data[0] = len(user_data)
            for i in xrange(len(user_data)):
                pktCmd.contents.user_data[1 + i] = ord(user_data[i])

            pkt = self.__encrypt_send_pkt(pkt)
            pktCmd = cast(pkt,  POINTER(TPktCmd)).contents

            pktCmd.crc32 = crc32.crc32(pkt,  sizeof(TPktCmd) - 10)
            pktCmd.tail = PKT_TAIL
            
            chk_sum = 0
            for i in xrange(sizeof(TPktCmd) - 6):
                chk_sum += pkt[i]
            pktCmd.check = chk_sum

            def ser_write():
                try:
                    ser.write(pkt)
                except:
                    pass
                
            ser_write_thread = threading.Thread(target=ser_write, args=())
            ser_write_thread.setDaemon(False)
            ser_write_thread.start()
            ser_write_thread.join(2.0)
            if ser_write_thread.isAlive():
                ser.close()
                ser_write_thread.join(2.0)
                if self.__use_exception:
                    raise Exception("Send data failed.")
                return False
            else:
                time.sleep(2.0)
                return self.__deal_uart_recv_data(ser)
        except Exception,  e:
            if self.__use_exception:
                raise e
            traceback.print_exc()
            return False
            
    def ukey_pos(self):
        try:
            return self.__port
        except:
            traceback.print_exc()
            return None
        
    def __array2str(self, comment):
        contents = ""
        for i in xrange(len(comment)):
            if (comment[i] == 0):
                break
            contents = contents + chr(comment[i])
        return contents
        
    def __array2hexstr(self, comment):
        contents = ""
        for i in xrange(len(comment)):
            contents = contents + hex(comment[i])[2:]
        return contents
        
    def find_ukey(self):
        ports = UkeyMgr.serial_ports()
        for p in ports:
            try:
                #print p,'Detecting...', 
                ser = serial.Serial(port=p, 
                                baudrate=BAUDRATE, 
                                bytesize=8,
                                stopbits=1, 
                                parity='N',
                                xonxoff=False, 
                                rtscts=False, 
                                dsrdtr=False)
                                
                pkt = (c_uint8 * sizeof(TPktCmd))()
                pktCmd = cast(pkt,  POINTER(TPktCmd)).contents
                pktCmd.head = PKT_HEAD
                pktCmd.cmd = 0x1
                for i in xrange(28):
                    pktCmd.contents.data[i] = int(random.random() * 2 ** 32)
                    
                
                pkt = self.__encrypt_send_pkt(pkt)
                pktCmd = cast(pkt,  POINTER(TPktCmd)).contents
                
                pktCmd.crc32 = crc32.crc32(pkt,  sizeof(TPktCmd) - 10)
                pktCmd.tail = PKT_TAIL
                
                chk_sum = 0
                for i in xrange(sizeof(TPktCmd) - 6):
                    chk_sum += pkt[i]
                pktCmd.check = chk_sum
                
                def ser_write():
                    try:
                        ser.write(pkt)
                    except:
                        pass
                    
                ser_write_thread = threading.Thread(target=ser_write, args=())
                ser_write_thread.setDaemon(False)
                ser_write_thread.start()
                ser_write_thread.join(2.0)
                if ser_write_thread.isAlive():
                    ser.close()
                    ser_write_thread.join(2.0)
                else:
                    time.sleep(2.0)
                    data = ser.read(ser.inWaiting())
                    if len(data) < sizeof(TPktRecv):
                        #print p, 'Receive Error, Data Len:', len(data)
                        ser.close()
                        continue
                    pktRecv = cast(data,  POINTER(TPktRecv)).contents
                    '''
                    #調試相關的信息
                    print 'LEN:', len(data)
                    for i in xrange(len(data)):
                        print hex(ord(data[i])), 
                    print
                    '''
                    crc_check = crc32.crc32(data,  sizeof(TPktRecv) - 10)
                    if crc_check == pktRecv.crc32:
                        data = self.__decrypt_recv_pkt(data)
                        pktRecv = cast(data,  POINTER(TPktRecv)).contents
                        self.__comment = self.__array2str(pktRecv.contents.uid_comment.comment)
                        self.__uid = self.__array2hexstr(pktRecv.contents.uid_comment.uid)
                        ser.close()
                        #print 'Ukey found.'
                        return p
                    else:
                        ser.close()
                #print 'Found nothing.'
            except Exception,  e:
                #print 'Error occurs, Message:', 
                #print e
                pass;
        
    @staticmethod
    def serial_ports():
        """ Lists serial port names

            :raises EnvironmentError:
                On unsupported or unknown platforms
            :returns:
                A list of the serial ports available on the system
        """
        if sys.platform.startswith('win'):
            ports = ['COM%s' % (i + 1) for i in range(256)]
        elif sys.platform.startswith('linux') or sys.platform.startswith('cygwin'):
            # this excludes your current terminal "/dev/tty"
            ports = glob.glob('/dev/ttyUSB*')
        elif sys.platform.startswith('darwin'):
            ports = glob.glob('/dev/tty.*')
        else:
            raise EnvironmentError('Unsupported platform')

        result = []
        for port in ports:
            try:
                s = serial.Serial(port,  BAUDRATE,  timeout=0.5)
                s.close()
                result.append(port)
            except (OSError, serial.SerialException):
                pass
        return result



