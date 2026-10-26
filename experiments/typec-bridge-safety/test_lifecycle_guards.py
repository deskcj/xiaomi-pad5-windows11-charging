"""Original lifecycle prefixes up to the protected-body boundary, plus failure exit.
Never executes a protected body or calls the Windows kernel.
"""
from pathlib import Path
import itertools,json
from emulate_transport import CTX,TABLE,STUB,STACK,STOP,nv
from emulate_waitlock import WaitMachine
from unicorn.arm64_const import *
root=Path(__file__).resolve().parent
class Lifecycle(WaitMachine):
 def __init__(self,path,entry,body,status,trace,base):
  super().__init__(path,status,trace,base);self.entry=entry;self.body=body;self.entered=False
  self.qword(CTX+0x148,0x11110000);self.qword(CTX+0x150,0x22220000)
  self.qword(TABLE+0x570,STUB+0x900)
  self.worker=CTX+0x3800;self.qword(self.worker,0x10101010)
 def hook(self,u,a,n,unused):
  if a==self.base+self.body:
   self.entered=True;u.emu_stop();return
  if a==STUB:
   key=u.reg_read(UC_ARM64_REG_X2)
   devicekey=int.from_bytes(u.mem_read(self.base+0xc128,8),'little')
   value=CTX if key==devicekey else self.worker
   lr=u.reg_read(UC_ARM64_REG_LR)
   for r in range(UC_ARM64_REG_X0,UC_ARM64_REG_X17+1):u.reg_write(r,0xcccccccccccccccc)
   u.reg_write(UC_ARM64_REG_X0,value);u.reg_write(UC_ARM64_REG_PC,lr);return
  if a==STUB+0x900:
   u.reg_write(UC_ARM64_REG_X0,0x10101010);u.reg_write(UC_ARM64_REG_PC,u.reg_read(UC_ARM64_REG_LR));return
  super().hook(u,a,n,unused)
 def run(self,poison):
  u=self.uc;u.mem_write(STACK+0x7f00,bytes([poison])*0x100)
  for r,v in nv.items():u.reg_write(r,v)
  u.reg_write(UC_ARM64_REG_SP,STACK+0x8000);u.reg_write(UC_ARM64_REG_LR,STOP)
  u.reg_write(UC_ARM64_REG_X0,CTX if self.entry in [0x11a40,0x11c00] else 0x20202020)
  u.emu_start(self.base+self.entry,STOP,count=10000)
  if not self.entered:
   assert u.reg_read(UC_ARM64_REG_PC)==STOP and u.reg_read(UC_ARM64_REG_SP)==STACK+0x8000
   assert all(u.reg_read(r)==v for r,v in nv.items())
  return {'entry':hex(self.entry),'protectedBodyReached':self.entered,'lockOwned':self.lock_owned,'events':self.wait_events}
if __name__=='__main__':
 old=root/'typec-transportfix2/qcusbctcpm8150-transportfix2-UNSIGNED-NOT-INSTALLED.sys'
 new=root/'typec-safetyfix3/qcusbctcpm8150-safetyfix3-UNSIGNED-NOT-INSTALLED.sys'
 count=0;counter=0
 for (entry,body),status,tracing,base,poison in itertools.product([(0xfa80,0xfbf4),(0x10180,0x102ec),(0x110d0,0x11238),(0x11a40,0x11b50),(0x11c00,0x11d10)],[0,0x102,0xc0000001],[False,True],[0x140000000,0x180000000,0x7ffb12340000],[0,0xa5,0xff]):
  a=Lifecycle(old,entry,body,status,tracing,base).run(poison);b=Lifecycle(new,entry,body,status,tracing,base).run(poison)
  assert a['protectedBodyReached']==(status in [0,0x102]),a
  assert b['protectedBodyReached']==(status==0),b
  assert b['events'][0]['timeout100ns']==-300000000,b
  assert not b['protectedBodyReached'] or b['lockOwned']
  if status==0x102:assert a['protectedBodyReached'] and not a['lockOwned'];counter+=1
  count+=1
 report={'pairedGuardPrefixCases':count,'timeoutWithoutOwnershipCounterexamples':counter,'allFiveAcquireGuardsEmulated':True,'ASLRBases':3,'stackPoisonPatterns':3,'protectedBodyOnTimeout':False,'fullLifecycleAfterSuccessfulAcquireExecuted':False,'failureExitsRestoreStackAndNonvolatile':True,'hardwareTested':False}
 (root/'typec-safetyfix3/lifecycle-guard-verification.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
 print(json.dumps(report,indent=2))
