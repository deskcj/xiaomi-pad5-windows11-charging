"""Replay actual ARM64 PMIC role and original OTG entry points; no device I/O."""
import sys,json,struct,hashlib
from pathlib import Path
import pefile
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn.arm64_const import *
root=Path(__file__).resolve().parents[1]
r5=root.parent/'candidate-fix20r5-drp/build/qcpmicext8150_unsigned.sys'
r6=Path(sys.argv[1]) if len(sys.argv)>1 else root/'build/qcpmicext8150_unsigned.sys'
stock=Path(r'C:\Windows\System32\DriverStore\FileRepository\qcpmicext8150.inf_arm64_fe1800db720f064c\qcpmicext8150.sys')
class Model:
 def __init__(self,path,base):
  self.pe=pefile.PE(str(path));self.base=base
  self.u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u=self.u
  u.mem_map(base,0x20000);u.mem_write(base,self.pe.get_memory_mapped_image())
  u.mem_map(0x200000,0x10000);u.mem_map(0x400000,0x1000)
  for i in [0,1]:
   u.mem_write(base+0xd548+i*0x30,struct.pack('<Q',base+0x18000+i*0x100));u.mem_write(base+0x18000+i*0x100,struct.pack('<II',2,0x1500))
  u.mem_write(base+0xd658,struct.pack('<Q',base+0x18100))
  u.mem_write(base+0xd098,struct.pack('<Q',base+0xd098))
  self.regs={0x1140:0,0x1544:0x10,0x1509:5};self.writes=[];self.error=0;self.read_error=0
  self.command=struct.unpack('<I',self.pe.get_data(0x82bc,4))[0]
  self.nv={r:0xabc0000000000000+i for i,r in enumerate(range(UC_ARM64_REG_X19,UC_ARM64_REG_X28+1))}
  self.nv[UC_ARM64_REG_FP]=0xabc1234567890000;self.nv[UC_ARM64_REG_X18]=0x1234567890abcdef
  def hook(u,a,n,unused):
   rva=a-self.base
   if rva not in [0xb858,0xb948]:return
   sid=u.reg_read(UC_ARM64_REG_W0);reg=u.reg_read(UC_ARM64_REG_W1);assert sid==2
   if rva==0xb858:
    rc=self.read_error
    if not rc:u.mem_write(u.reg_read(UC_ARM64_REG_X2),bytes([self.regs.get(reg,0)]))
   else:
    mask=u.reg_read(UC_ARM64_REG_W2);value=u.reg_read(UC_ARM64_REG_W3);self.writes.append([sid,reg,mask,value]);rc=self.error
    if not rc:self.regs[reg]=(self.regs.get(reg,0)&~mask)|(value&mask)
   lr=u.reg_read(UC_ARM64_REG_LR)
   for r in range(UC_ARM64_REG_X0,UC_ARM64_REG_X17+1):u.reg_write(r,0xdedebabefeed0000+r)
   u.reg_write(UC_ARM64_REG_W0,rc);u.reg_write(UC_ARM64_REG_PC,lr)
  u.hook_add(UC_HOOK_CODE,hook)
 def call(self,otg=None,vconn=None):
  u=self.u
  for r in range(UC_ARM64_REG_X0,UC_ARM64_REG_X17+1):u.reg_write(r,0)
  for r,v in self.nv.items():u.reg_write(r,v)
  u.reg_write(UC_ARM64_REG_SP,0x208000);u.reg_write(UC_ARM64_REG_LR,0x400000)
  u.reg_write(UC_ARM64_REG_W0,1)
  if vconn is not None:entry=0x8b40;u.reg_write(UC_ARM64_REG_W1,vconn)
  elif otg is None:entry=0x8ac0;u.reg_write(UC_ARM64_REG_W1,0)
  else:
   entry=0x7dd0;u.reg_write(UC_ARM64_REG_W1,self.command);u.reg_write(UC_ARM64_REG_X2,0x202000);u.reg_write(UC_ARM64_REG_X3,4);u.reg_write(UC_ARM64_REG_X4,0x202100);u.reg_write(UC_ARM64_REG_X5,4)
   u.mem_write(0x202000,struct.pack('<I',otg));u.mem_write(0x202100,b'\xff'*4)
  u.emu_start(self.base+entry,0x400000,count=3000)
  assert u.reg_read(UC_ARM64_REG_PC)==0x400000 and u.reg_read(UC_ARM64_REG_SP)==0x208000
  assert all(u.reg_read(r)==v for r,v in self.nv.items())
  result=u.reg_read(UC_ARM64_REG_W0)
  return result if otg is None else (result,struct.unpack('<I',u.mem_read(0x202100,4))[0])

old=pefile.PE(str(stock));new=pefile.PE(str(r6))
assert old.get_data(0x7dd0,0x8410-0x7dd0)==new.get_data(0x7dd0,0x8410-0x7dd0),'Original OTG callback changed'
counter=Model(r5,0x140000000);assert counter.call(1)==(0,0);assert counter.regs[0x1140]==1
assert counter.call()==0;assert counter.regs[0x1140]==0,'R5 counterexample did not reproduce'
cases=0
for base in [0x140000000,0x180000000,0x7ffb12340000]:
 for initial in [0,1]:
  for err in [0,0x61,0xffffffff]:
   m=Model(r6,base);assert m.call(initial)==(0,0);before=m.regs.copy();m.read_error=err
   rc=m.call();assert rc==err;assert m.regs[0x1140]==initial
   assert not err or m.regs==before
   m.read_error=0;assert m.call(1)==(0,0);assert m.call()==0 and m.regs[0x1140]==1
   assert m.call(0)==(0,0);assert m.call()==0 and m.regs[0x1140]==0
   m.error=0x61;assert m.call(1)==(0,0x61);assert m.regs[0x1140]==0
   assert m.call()==0x61
   cases+=1
vconn_cases=0
for base in [0x140000000,0x180000000,0x7ffb12340000]:
 for command in [0,1,2,3,4,5,6,7,8]:
  m=Model(r6,base);assert m.call(vconn=command)==0
  expected={0:[2,0x1552,3,0],1:[2,0x1552,3,1],2:[2,0x1552,3,2],5:[2,0x1550,5,5],6:[2,0x1550,5,4],7:[2,0x1550,5,5],8:[2,0x1550,5,4]}
  assert m.writes==([expected[command]] if command in expected else [])
  vconn_cases+=1
report={'candidateSHA256':hashlib.sha256(r6.read_bytes()).hexdigest(),'r5CounterexampleReproduced':True,'actualOriginalOTGCallbackExecuted':True,'originalOTGCallbackByteIdenticalToStock':True,'statefulSequences':cases,'ASLRBases':3,'nonzeroX18Preserved':True,'legacyVconnLeafCases':vconn_cases,'kernelDriverLoaded':False,'hardwareModelLimitation':'SPMI functions mocked; no CC analog, hub firmware, PD negotiation, interrupts, DMA or physical timing simulated.'}
(root/'build/role-vbus-sequence-report.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
print(json.dumps(report,indent=2))
