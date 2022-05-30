#!coding=utf8
import sys
import os
from time import sleep
import frida

# os.system("adb push G:/spaceWork/TEST/夺宝消消消/dumplua /sdcard/dumplua")
device = frida.get_usb_device()
pkgName = "com.hp.castle"
pid = device.spawn(pkgName)
session = device.attach(pid)
device.resume(pid)

rpc = open('rpc.js', 'r', encoding='utf-8').read()
scr = open('dumpdll.js', 'r', encoding='utf-8').read()

def on_message(message, data):
    if message['type'] == 'send':
        content = message['payload']
        print(content)
    else:
        print(message)

rpc = session.create_script(rpc)
rpc.on("message",on_message)
rpc.load()

# sleep(20)


# # dump libil2cpp.so
# il2cppSo = rpc.exports.dumpmodule("libil2cpp.so")
# if il2cppSo != -1:
#         dumpSoName = "libil2cpp" + ".dump.so"   
#         with open(dumpSoName, "wb") as f:
#             f.write(il2cppSo)
#             f.close()


# #dump global-metedata.bat
# gmbBuffer = rpc.exports.gmdscan()
# if gmbBuffer != None:
#     print("write gmbBuffer to file")
#     gmb = "global-metedata_dump.bat"
#     with open(gmb , "wb") as f:
#         f.write(gmbBuffer)
#         f.close()

# dumpdll
# rpc.exports.dumpdll()

# hook hotfix 

script = session.create_script(scr)
script.on("message", on_message)
script.load()




sys.stdin.read()


