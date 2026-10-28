"""Execute saved ARM64 callback and power consumer with mocked external DDI.
No driver load, device access, installation, live power operation, or reboot.
The prototype retains one 24-byte allocation through transient removal.
"""
from pathlib import Path
import hashlib,json,struct,sys,uuid
sys.path.insert(0,r'H:\Vlad\Charging\research\2026-10-26\tools\python-deps')
import pefile
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE
from unicorn.arm64_const import *
ROOT=Path(__file__).resolve().parent
SOURCE=(ROOT/'qcpep8150.sys').read_bytes()
assert hashlib.sha256(SOURCE).hexdigest()=='39fafcd60536c7d36dd95187dc9f51bfc4af661b614bce4a5e9ec0729fe24e01'
PE=pefile.PE(data=SOURCE)
BASE=PE.OPTIONAL_HEADER.ImageBase
STACK=0x40000000; AUX=0x41000000; HEAP=0x42000000; STUB=0x43000000; RET=STUB+0xff0
PTR=BASE+0x1c8bc0; TARGET=BASE+0x1c8bc8
ARRIVAL=uuid.UUID('cb3a4004-46f0-11d0-b08f-00609713053f').bytes_le
REMOVAL=uuid.UUID('cb3a4005-46f0-11d0-b08f-00609713053f').bytes_le
class LifetimeFailure(Exception):pass
class Machine:
 def __init__(self,data):
  self.u=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
  self.u.mem_map(BASE,PE.OPTIONAL_HEADER.SizeOfImage)
  self.u.mem_write(BASE,pefile.PE(data=data).get_memory_mapped_image())
  for addr,size in [(STACK,0x20000),(AUX,0x10000),(HEAP,0x10000),(STUB,0x10000)]:self.u.mem_map(addr,size)
  self.live={};self.allocations=0;self.frees=0;self.closed=0;self.deleted=0;self.created=0;self.opened=0;self.queries=0;self.powerCalls=0
  self.createStatus=0;self.openStatus=0;self.queryStatus=0;self.failAllocation=False
  self.w64(BASE+0x1c6620,BASE+0x1c6620);self.w64(BASE+0x1c6628,BASE+0x1c6628)
  self.w64(BASE+0x16a360,STUB+0x100);self.w64(BASE+0x16a098,STUB+0x200)
  self.w64(BASE+0x16a468,STUB+0x300);self.w64(BASE+0x16a410,STUB+0x400)
  self.w64(BASE+0x1c8bb8,STUB+0x500);self.w64(BASE+0x1c8f08,AUX+0x2000)
  self.u.mem_write(BASE+0x1c8c1c,struct.pack('<I',2))
  self.w64(AUX+0x948,STUB+0x600)
  self.w64(BASE+0x1c9230,AUX+0x3000);self.w64(AUX+0x3008,AUX+0x3100);self.w64(AUX+0x3108,AUX+0x3200)
  self.u.mem_write(AUX+0x3200,'USBHOST\0'.encode('utf-16-le'))
  self.u.hook_add(UC_HOOK_CODE,self.code)
  self.u.hook_add(UC_HOOK_MEM_READ|UC_HOOK_MEM_WRITE,self.access)
 def w64(self,at,value):self.u.mem_write(at,struct.pack('<Q',value))
 def r64(self,at):return struct.unpack('<Q',self.u.mem_read(at,8))[0]
 def finish(self,status=0):
  self.u.reg_write(UC_ARM64_REG_X0,status&0xffffffffffffffff)
  self.u.reg_write(UC_ARM64_REG_PC,self.u.reg_read(UC_ARM64_REG_LR))
 def access(self,u,access,at,size,value,data):
  for p,live in self.live.items():
   if at<p+24 and at+size>p and not live:raise LifetimeFailure('use-after-free at '+hex(at))
 def code(self,u,at,size,data):
  if at==RET:u.emu_stop();return
  a=lambda n:u.reg_read(UC_ARM64_REG_X0+n)
  if at==BASE+0x39a8:self.finish(int(bytes(u.mem_read(a(0),16))==bytes(u.mem_read(a(1),16))))
  elif at==BASE+0x43c0:
   if self.createStatus==0:self.created+=1;self.w64(a(2),AUX+0x4000+self.created*0x100)
   self.finish(self.createStatus)
  elif at==BASE+0x4380:self.finish()
  elif at==BASE+0x4428:self.opened+=1;self.finish(self.openStatus)
  elif at==BASE+0x2c1e0:self.queries+=1;self.finish(self.queryStatus)
  elif at==BASE+0x4488:
   assert a(0)==self.r64(TARGET);self.closed+=1;self.finish()
  elif at==BASE+0x3ba0:self.deleted+=1;self.finish()
  elif at==STUB+0x100:
   assert a(0)==0x200 and a(1)==24 and a(2)==0x59657071
   if self.failAllocation:self.finish(0);return
   p=HEAP+self.allocations*0x100;self.allocations+=1;self.live[p]=True;self.u.mem_write(p,b'\xcd'*24);self.finish(p)
  elif at==STUB+0x200:
   assert a(1)==0x59657071
   p=a(0)
   if p not in self.live or not self.live[p]:raise LifetimeFailure('invalid/double free at '+hex(p))
   self.live[p]=False;self.frees+=1;self.u.mem_write(p,b'\xdd'*24);self.finish()
  elif at==STUB+0x300:self.finish()
  elif at==STUB+0x400:
   assert a(0)==self.r64(PTR)+8
   self.u.mem_write(a(0),struct.pack('<HHIQ',14,16,0,a(1)));self.finish()
  elif at==STUB+0x500:
   assert a(0)==self.r64(PTR) and self.live.get(a(0),False)
   self.powerCalls+=1;self.finish()
  elif at==STUB+0x600:self.finish()
 def call(self,rva,a0,a1):
  sp=STACK+0x18000
  for n in range(19,29):self.u.reg_write(UC_ARM64_REG_X0+n,0x123400+n)
  self.u.reg_write(UC_ARM64_REG_SP,sp);self.u.reg_write(UC_ARM64_REG_LR,RET)
  self.u.reg_write(UC_ARM64_REG_X0,a0);self.u.reg_write(UC_ARM64_REG_X1,a1)
  self.u.emu_start(BASE+rva,RET,count=20000)
  assert self.u.reg_read(UC_ARM64_REG_PC)==RET
  assert self.u.reg_read(UC_ARM64_REG_SP)==sp
  for n in range(19,29):assert self.u.reg_read(UC_ARM64_REG_X0+n)==0x123400+n
  return self.u.reg_read(UC_ARM64_REG_X0)&0xffffffff
 def event(self,guid):
  self.u.mem_write(AUX+0x100,b'\0'*0x40);self.u.mem_write(AUX+0x104,guid);self.w64(AUX+0x128,AUX+0x1000)
  return self.call(0x380d0,AUX+0x100,AUX)
 def power(self,on):self.call(0x1fb0,AUX,int(on))
 def stats(self):return dict(allocations=self.allocations,frees=self.frees,closes=self.closed,deletes=self.deleted,queries=self.queries,powerCalls=self.powerCalls,liveBuffers=sum(self.live.values()))
