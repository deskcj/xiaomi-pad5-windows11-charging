"""Actual ARM64 Type-C request handlers and register helpers, without hardware I/O."""
import hashlib,json,struct,os
from pathlib import Path
import pefile
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn.arm64_const import *
CTX=0x40000000;TABLE=CTX+0x2000;TRACE=CTX+0x1000
INBUF=CTX+0x3000;OUTBUF=CTX+0x3200;STUB=0x50000000
STACK=0x200000;STOP=0x400000;PORT=0x1234567812345678
nv={r:0xabc0000000000000+i for i,r in enumerate(range(UC_ARM64_REG_X19,UC_ARM64_REG_X28+1))}
nv[UC_ARM64_REG_FP]=0xabc1234567890000;nv[UC_ARM64_REG_X18]=0x1818181818181818
class Machine:
 def __init__(self,path,base=0x140000000,ready=1,busy=0,trace=False,error=0):
  self.path=Path(path);self.pe=pefile.PE(str(path));self.base=base;self.error=error
  self.calls=[];self.messages=[];self.vregs={0x1a:0x0a,0x1c:0,0x50:0};self.capture=False;self.snapshots=[];self.last=[];self.information=None
  self.uc=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u=self.uc
  for a,n in [(base,0x20000),(CTX,0x4000),(STUB,0x1000),(STACK,0x10000),(STOP,0x1000)]:u.mem_map(a,n)
  u.mem_write(base,self.pe.get_memory_mapped_image())
  for a,v in [(base+0xc498,TABLE),(base+0xc4c8,0x12345000),(TABLE+0x650,STUB),(TABLE+0x868,STUB+0x400),(TABLE+0x870,STUB+0x500),(TABLE+0x898,STUB+0x600),(base+0xb110,STUB+0x100),(CTX+0x30,STUB+0x200),(CTX+0x38,STUB+0x300),(CTX+0x80,PORT),(base+0xc108,TRACE if trace else base+0xc108),(base+0xc100,TRACE+0x100),(TRACE+0x140,0x55667700)]:self.qword(a,v)
  u.mem_write(CTX+0xf0,bytes([ready]));u.mem_write(CTX+0x118,struct.pack('<I',busy))
  u.mem_write(OUTBUF,b'\xa5'*256);u.hook_add(UC_HOOK_CODE,self.hook)
 def qword(self,a,v):self.uc.mem_write(a,struct.pack('<Q',v))
 def hook(self,u,a,n,unused):
  self.last=(self.last+[hex(a)])[-12:]
  rva=a-self.base
  if self.capture and (0x8e38<=rva<0x8fbc or 0x8fc8<=rva<0x914c):
   regs=[u.reg_read(UC_ARM64_REG_X0+i) for i in range(29)]+[u.reg_read(UC_ARM64_REG_FP),u.reg_read(UC_ARM64_REG_LR)]
   self.snapshots.append((rva,u.reg_read(UC_ARM64_REG_SP)-(STACK+0x7000),regs,bytes(u.mem_read(STACK+0x7000,0x2000))))
  lr=u.reg_read(UC_ARM64_REG_LR)
  if a==STUB+0x100:u.reg_write(UC_ARM64_REG_PC,lr);return
  result=0;handled=True
  if a==STUB:result=CTX
  elif a in [STUB+0x200,STUB+0x300]:
   reg=u.reg_read(UC_ARM64_REG_W0);length=u.reg_read(UC_ARM64_REG_W1);buf=u.reg_read(UC_ARM64_REG_X2);out=u.reg_read(UC_ARM64_REG_X3)
   self.calls.append({'kind':'write' if a==STUB+0x200 else 'read','register':reg,'length':length,'status':self.error})
   assert 0<length<64
   if not self.error:
    if a==STUB+0x200:self.vregs[reg]=int.from_bytes(u.mem_read(buf,length),'little')
    else:u.mem_write(buf,self.vregs.get(reg,0).to_bytes(length,'little'))
   u.mem_write(out,struct.pack('<I',self.error));result=0xdeadbeef
  elif a in [STUB+0x400,STUB+0x500]:
   self.qword(u.reg_read(UC_ARM64_REG_X3),INBUF if a==STUB+0x400 else OUTBUF)
   if u.reg_read(UC_ARM64_REG_X4):self.qword(u.reg_read(UC_ARM64_REG_X4),256)
  elif a==STUB+0x600:self.information=u.reg_read(UC_ARM64_REG_X2)
  elif rva in [0x15b0,0x1510,0x1698,0x4758,0x4840,0x4938,0x4a08,0x4ac8]:
   self.messages.append({'id':u.reg_read(UC_ARM64_REG_W3),'status':u.reg_read(UC_ARM64_REG_W5)})
  else:handled=False
  if handled:
   assert u.reg_read(UC_ARM64_REG_SP)%16==0
   for r in range(UC_ARM64_REG_X0,UC_ARM64_REG_X17+1):u.reg_write(r,0xcccccccccccccccc)
   u.reg_write(UC_ARM64_REG_X0,result);u.reg_write(UC_ARM64_REG_PC,lr)
 def call(self,which,value=0x4a):
  u=self.uc
  for r,v in nv.items():u.reg_write(r,v)
  u.reg_write(UC_ARM64_REG_SP,STACK+0x8000);u.reg_write(UC_ARM64_REG_LR,STOP)
  u.reg_write(UC_ARM64_REG_X0,0x10101010)
  if which in ['read','write']:
   entry=0x8e38 if which=='read' else 0x8fc8
   u.reg_write(UC_ARM64_REG_W1,0x1a);u.reg_write(UC_ARM64_REG_W2,1);u.reg_write(UC_ARM64_REG_X3,INBUF)
   u.mem_write(INBUF,bytes([value]))
  else:
   u.reg_write(UC_ARM64_REG_X1,0x20202020)
   if which=='set-role':entry=0x6b40;data=struct.pack('<QIB',PORT,2,value)
   elif which=='set-power':entry=0x6b40;data=struct.pack('<QIB',PORT,4,value)
   elif which=='transmit':entry=0x7090;data=struct.pack('<QB',PORT,value)
   elif which=='command':entry=0x7eb0;data=struct.pack('<QB',PORT,value)
   elif which=='get-status':entry=0x6170;data=struct.pack('<Q',PORT)
   else:raise ValueError(which)
   u.mem_write(INBUF,data)
  try:u.emu_start(self.base+entry,STOP,count=10000)
  except Exception:
   print({'which':which,'PC':hex(u.reg_read(UC_ARM64_REG_PC)),'LR':hex(u.reg_read(UC_ARM64_REG_LR)),'last':self.last,'calls':self.calls});raise
  assert u.reg_read(UC_ARM64_REG_PC)==STOP,'Call did not return'
  assert u.reg_read(UC_ARM64_REG_SP)==STACK+0x8000,'Stack corrupted'
  assert all(u.reg_read(r)==v for r,v in nv.items()),'Nonvolatile register corrupted'
  return {'status':u.reg_read(UC_ARM64_REG_W0),'lock':int.from_bytes(u.mem_read(CTX+0x118,4),'little'),'calls':list(self.calls),'trace':list(self.messages),'virtualRole':self.vregs[0x1a],'outputInformation':self.information,'outputStatusHex':bytes(u.mem_read(OUTBUF,3)).hex()}

if __name__=='__main__':
 original=Path(os.environ.get('NABU_TYPEC_SOURCE',r'H:\Vlad\Charging\research\2026-10-26\handover\qcusbctcpm8150.sys'))
 assert hashlib.sha256(original.read_bytes()).hexdigest()=='7c63f4a4b8a9ee0f49b427b6ac94867d2475e02f85d92d5fbcfe4a8aa1804067'
 cases=[]
 for method in ['read','write','set-role','set-power','transmit','command','get-status']:
  for tracing in [False,True]:
   m=Machine(original,trace=tracing,error=0xc0000001)
   result=m.call(method,value=0x99 if method=='command' else 0x4a)
   cases.append({'method':method,'traceEnabled':tracing,**result})
 print(json.dumps(cases,indent=2))
 Path(__file__).with_name('original-error-counterexamples.json').write_text(json.dumps(cases,indent=2),encoding='utf-8')
