#!/usr/bin/env python
#encoding=utf-8


class Singleton(object):
    _instance = None
    def __new__(self,  *args,  **kwargs):
        if not self._instance:
            self._instance = super(Singleton,  self).__new__(self,  *args,  **kwargs)
        return self._instance
        
if __name__ == '__main__':
    class Test(Singleton):
        isInit = False
        def __init__(self):
            if not Test.isInit:
                Test.isInit = True
                print 'initialize.'
    class Ts(object):
        index = 0
        def __init__(self):
            Ts.index += 1
            
        def get(self):
            print Ts.index
            
    t1 = Test()
    t2 = Test()
    print t1,  t2
    
    t3 = Ts()
    t4 = Ts()
    t4.get()
