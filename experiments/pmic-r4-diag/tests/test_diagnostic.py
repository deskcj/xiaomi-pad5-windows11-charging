"""Exercise the compiled read-only diagnostic callback and real IOCTL dispatcher."""
import sys,struct,json,itertools,hashlib
from pathlib import Path
root=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(root.parent/'research/2026-10-26/tools/python-deps'))
import pefile
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn.arm64_const import *
candidate=Path(sys.argv[1]) if len(sys.argv)>1 else root/'build/qcpmicext8150_unsigned.sys'
pe=pefile.PE(str(candidate));image=pe.get_memory_mapped_image()
code=next(s for s in pe.sections if s.Name.rstrip(b'\0')==b'.ncode')
allowed=[0x110d,0x1140,0x1153,0x1307,0x1308,0x130b,0x1310,0x1358,0x1370,0x1506,0x1508,0x1509,0x150b,0x1544]
snapshots={}
nv={r:0xabc0000000000000+i for i,r in enumerate(range(UC_ARM64_REG_X19,UC_ARM64_REG_X28+1))}
nv[UC_ARM64_REG_FP]=0xabc1234567890000
STACK=0x200000;STOP=0x400000
def run(reg=0x1509,value=0,error=0,index=1,op=0x51,version=1,tag=0x4e420000,ready=True,sid=2,peripheral=0x1500,base=0x140000000,capture=False,dispatch=False,input_length=16):
 cpu=Uc(UC_ARCH_ARM64,UC_MODE_ARM);cpu.mem_map(base,0x20000);cpu.mem_write(base,image)
 cpu.mem_map(STACK,0x10000);cpu.mem_map(STOP,0x1000)
 ctx=base+0x18000
 cpu.mem_write(base+0xd578,struct.pack('<Q',ctx if ready else 0));cpu.mem_write(ctx,struct.pack('<II',sid,peripheral))
 cpu.reg_write(UC_ARM64_REG_SP,STACK+0x8000);cpu.reg_write(UC_ARM64_REG_LR,STOP)
 for r,v in nv.items():cpu.reg_write(r,v)
 reads=[]
 if dispatch:
  # The original dispatcher does its own input-size checks and reports its
  # callback DWORD at the existing output. Only audited logical index 1 is used.
  cpu.mem_write(base+0xd550,b'\x01');cpu.mem_write(base+0xd558,struct.pack('<Q',base+0xd130))
  cpu.mem_write(base+0xd098,struct.pack('<Q',base+0xd098))
  cpu.mem_write(base+0xc0a8,struct.pack('<Q',STOP+0x100))
  cpu.mem_write(STACK+0x1000,struct.pack('<4I',index,op,tag|reg,version))
  for r,v in [(UC_ARM64_REG_X0,0),(UC_ARM64_REG_X1,0x802a0fb4),(UC_ARM64_REG_X2,STACK+0x1000),(UC_ARM64_REG_X3,input_length),(UC_ARM64_REG_X4,STACK+0x1100),(UC_ARM64_REG_X5,4),(UC_ARM64_REG_X6,STACK+0x1200)]:cpu.reg_write(r,v)
  entry=base+0x8dd0
 else:
  for r,v in [(UC_ARM64_REG_W0,index),(UC_ARM64_REG_W1,op),(UC_ARM64_REG_W2,tag|reg),(UC_ARM64_REG_W3,version)]:cpu.reg_write(r,v)
  entry=base+0x8be0
 def hook(uc,address,size,user):
  rva=address-base
  if capture and code.VirtualAddress<=rva<code.VirtualAddress+code.Misc_VirtualSize-8:
   regs=[uc.reg_read(UC_ARM64_REG_X0+i) for i in range(29)]+[uc.reg_read(UC_ARM64_REG_FP),uc.reg_read(UC_ARM64_REG_LR)]
   mem=bytes(uc.mem_read(STACK+0x7000,0x2000));key=(rva,tuple(regs),uc.reg_read(UC_ARM64_REG_SP))
   snapshots[key]=(rva,uc.reg_read(UC_ARM64_REG_SP)-(STACK+0x7000),regs,mem)
  if address==STOP+0x100:uc.reg_write(UC_ARM64_REG_PC,uc.reg_read(UC_ARM64_REG_LR))
  if rva==0xb948:raise AssertionError('Diagnostic path attempted a PMIC write')
  if rva==0xb858:
   assert uc.reg_read(UC_ARM64_REG_SP)%16==0
   reads.append((uc.reg_read(UC_ARM64_REG_W0),uc.reg_read(UC_ARM64_REG_W1)))
   if not error:uc.mem_write(uc.reg_read(UC_ARM64_REG_X2),bytes([value]))
   lr=uc.reg_read(UC_ARM64_REG_LR)
   for r in range(UC_ARM64_REG_X0,UC_ARM64_REG_X17+1):uc.reg_write(r,0xcccccccccccccccc)
   uc.reg_write(UC_ARM64_REG_W0,error);uc.reg_write(UC_ARM64_REG_PC,lr)
 cpu.hook_add(UC_HOOK_CODE,hook);cpu.emu_start(entry,STOP,count=5000)
 assert cpu.reg_read(UC_ARM64_REG_PC)==STOP
 assert cpu.reg_read(UC_ARM64_REG_SP)==STACK+0x8000
 assert all(cpu.reg_read(r)==v for r,v in nv.items())
 assert cpu.reg_read(UC_ARM64_REG_X18)==0
 result=cpu.reg_read(UC_ARM64_REG_W0)
 if dispatch:return result,struct.unpack('<I',cpu.mem_read(STACK+0x1100,4))[0],struct.unpack('<Q',cpu.mem_read(STACK+0x1200,8))[0],reads
 return result,reads
count=0
for base,reg,value,error in itertools.product([0x140000000,0x180000000,0x10000000],allowed,[0,1,0x20,0x40,0xff],[0,0x61,0x6d,0xffffffff]):
 result,reads=run(reg=reg,value=value,error=error,base=base)
 assert reads==[(2,reg)]
 assert result==(0x4e430000|(error&0xffff) if error else 0x4e420000|value)
 count+=1
for kwargs in [{'index':0},{'index':2},{'index':0xffffffff},{'ready':False},{'sid':1},{'sid':3},{'peripheral':0x1300}]:
 result,reads=run(**kwargs);assert result==0x4e430061 and not reads;count+=1
badregs=sorted(({0,1,0x1100,0x1540,0xffff}|{r+d for r in allowed for d in [-1,1]})-set(allowed))
for reg in badregs:
 result,reads=run(reg=reg);assert result==0x4e430061 and not reads;count+=1
for kwargs in [{'op':0},{'op':0x50},{'op':0x52},{'version':0},{'version':2},{'tag':0},{'tag':0x4e430000},{'index':0xffffffff,'op':0}]:
 result,reads=run(**kwargs);assert result==0 and not reads;count+=1
integration=0
for reg in allowed:
 status,output,length,reads=run(reg=reg,value=0xa5,dispatch=True)
 assert status==0 and output==0x4e4200a5 and length==4 and reads==[(2,reg)]
 integration+=1
for length in [0,4,8,12,15]:
 status,output,returned,reads=run(dispatch=True,input_length=length)
 assert status==0xc000000d and not reads;integration+=1
for kwargs in [{},{'error':0x61},{'ready':False},{'sid':1},{'reg':0xffff},{'op':0},{'index':0xffffffff},{'version':0},{'peripheral':0}]:run(capture=True,**kwargs)
source=(root/'build/unwind-fixtures.bin').read_bytes();magic,old_count=struct.unpack_from('<II',source)
assert magic==0x3157444e
with (root/'build/unwind-all-fixtures.bin').open('wb') as f:
 f.write(struct.pack('<II',magic,old_count+len(snapshots)));f.write(source[8:])
 for pc,sp,regs,mem in snapshots.values():f.write(struct.pack('<II31Q',pc,sp,*regs)+mem)
report={'sha256':hashlib.sha256(candidate.read_bytes()).hexdigest(),'DiagnosticCallbackCases':count,'OriginalDispatcherIntegrationCases':integration,'WhitelistRegisters':len(allowed),'PMICWriteAttempts':0,'NativeUnwindFixtures':old_count+len(snapshots),'RolePolicyChangedFromR3':False,'KernelDriverLoaded':False}
(root/'build/diagnostic-emulation-report.json').write_text(json.dumps(report,indent=2),encoding='utf-8',newline='\n')
print(json.dumps(report,indent=2))
