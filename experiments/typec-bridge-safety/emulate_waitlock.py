"""Execute original synchronization callbacks; mock only WDF and tracing."""
import json,struct,os
from pathlib import Path
from emulate_transport import Machine,CTX,TABLE,STUB,STACK,STOP,nv
from unicorn.arm64_const import *
class WaitMachine(Machine):
 def __init__(self,path,acquire=0x102,trace=False,base=0x140000000):
  super().__init__(path,base=base,ready=0,trace=trace)
  self.acquire=acquire;self.lock_owned=False;self.wait_events=[]
  self.qword(TABLE+0x9c8,STUB+0x700);self.qword(TABLE+0x9d0,STUB+0x800);self.qword(CTX+0x178,0x76543210)
 def hook(self,u,a,n,unused):
  rva=a-self.base
  if self.capture and (0x11a40<=rva<0x11bfc or 0x11c00<=rva<0x11dbc):
   regs=[u.reg_read(UC_ARM64_REG_X0+i) for i in range(29)]+[u.reg_read(UC_ARM64_REG_FP),u.reg_read(UC_ARM64_REG_LR)]
   self.snapshots.append((rva,u.reg_read(UC_ARM64_REG_SP)-(STACK+0x7000),regs,bytes(u.mem_read(STACK+0x7000,0x2000))))
  if a in [STUB+0x700,STUB+0x800]:
   if a==STUB+0x700:
    timeout=struct.unpack('<q',u.mem_read(u.reg_read(UC_ARM64_REG_X2),8))[0]
    self.lock_owned=self.acquire==0
    self.wait_events.append({'operation':'acquire','timeout100ns':timeout,'result':self.acquire})
    value=self.acquire
   else:
    self.wait_events.append({'operation':'release','ownedByThisCall':self.lock_owned});value=0
    self.lock_owned=False
   lr=u.reg_read(UC_ARM64_REG_LR)
   for r in range(UC_ARM64_REG_X0,UC_ARM64_REG_X17+1):u.reg_write(r,0xcccccccccccccccc)
   u.reg_write(UC_ARM64_REG_X0,value);u.reg_write(UC_ARM64_REG_PC,lr);return
  super().hook(u,a,n,unused)
 def run_callback(self,entry,poison=0):
  u=self.uc
  u.mem_write(STACK+0x7fa0,bytes([poison])*0x60)
  for r,v in nv.items():u.reg_write(r,v)
  u.reg_write(UC_ARM64_REG_SP,STACK+0x8000);u.reg_write(UC_ARM64_REG_LR,STOP);u.reg_write(UC_ARM64_REG_X0,CTX)
  before=bytes([1,0 if entry==0x11a40 else 1]);u.mem_write(CTX+0x200,before)
  u.emu_start(self.base+entry,STOP,count=10000)
  assert u.reg_read(UC_ARM64_REG_PC)==STOP and u.reg_read(UC_ARM64_REG_SP)==STACK+0x8000
  assert all(u.reg_read(r)==v for r,v in nv.items())
  return {'entry':hex(entry),'acquireStatus':self.acquire,'events':self.wait_events,'flagsBefore':before.hex(),'flagsAfter':bytes(u.mem_read(CTX+0x200,2)).hex()}
if __name__=='__main__':
 original=Path(os.environ.get('NABU_TYPEC_SOURCE',r'H:\Vlad\Charging\research\2026-10-26\handover\qcusbctcpm8150.sys'))
 results=[]
 for entry in [0x11a40,0x11c00]:
  for status in [0,0x102,0xc0000001]:
   for tracing in [False,True]:
    m=WaitMachine(original,status,tracing);results.append({'traceEnabled':tracing,**m.run_callback(entry)})
 Path(__file__).with_name('waitlock-counterexamples.json').write_text(json.dumps(results,indent=2),encoding='utf-8')
 print(json.dumps(results,indent=2))
