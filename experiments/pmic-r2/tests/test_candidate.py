"""Execute actual patched ARM64 instructions with adversarial SPMI outcomes.
No kernel driver is loaded. Emit boundary snapshots for native RtlVirtualUnwind.
"""
import hashlib,json,struct,sys
from pathlib import Path
root=Path(__file__).resolve().parents[1]
(root/'build').mkdir(parents=True,exist_ok=True)
fallback=root.parent/'research/2026-10-26/tools/python-deps'
if fallback.exists():sys.path.insert(0,str(fallback))
import pefile
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn.arm64_const import *
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM

candidate=Path(sys.argv[1]) if len(sys.argv)>1 else root/'build/qcpmicext8150_unsigned.sys'
pe=pefile.PE(str(candidate));base=pe.OPTIONAL_HEADER.ImageBase
image=pe.get_memory_mapped_image();stack=0x200000;stop=0x400000
code_section=next(s for s in pe.sections if s.Name.rstrip(b'\0')==b'.ncode')
helper_start=code_section.VirtualAddress
helper_end=helper_start+code_section.Misc_VirtualSize-8
nonvolatile={reg:0xabc0000000000000+i for i,reg in enumerate(range(UC_ARM64_REG_X19,UC_ARM64_REG_X28+1))}
# Unicorn does not enumerate X29/X30 next to X19..X28.
nonvolatile[UC_ARM64_REG_FP]=0xabc1234567890000
snapshots=[]

def run(state=0,index=0,role=0,read_error=0,otg_error=0,role_error=0,ready=True,sid=2,clobber=0xa5a5a5a5,capture=False,load_base=None,slot_presence=None):
    base=pe.OPTIONAL_HEADER.ImageBase if load_base is None else load_base
    uc=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
    uc.mem_map(base,0x20000);uc.mem_write(base,image)
    uc.mem_map(stack,0x10000);uc.mem_map(stop,0x1000)
    table=base+0x18000
    for i in range(3):
        present=ready if slot_presence is None else slot_presence[i]
        pointer=table+0x100*i if present else 0
        uc.mem_write(base+0xd548+0x30*i,struct.pack('<Q',pointer))
        if pointer:uc.mem_write(pointer,struct.pack('<I',sid+i))
    uc.reg_write(UC_ARM64_REG_SP,stack+0x8000);uc.reg_write(UC_ARM64_REG_LR,stop)
    for reg,val in nonvolatile.items():uc.reg_write(reg,val)
    uc.reg_write(UC_ARM64_REG_W0,index);uc.reg_write(UC_ARM64_REG_W1,role)
    reads=[];writes=[];steps=[]
    def hook(cpu,address,size,user):
        rva=address-base
        if helper_start<=rva<helper_end:
            assert cpu.reg_read(UC_ARM64_REG_SP)%16==0,'Unaligned stack'
            steps.append(rva)
            if capture:
                regs=[cpu.reg_read(UC_ARM64_REG_X0+i) for i in range(29)]+[cpu.reg_read(UC_ARM64_REG_FP),cpu.reg_read(UC_ARM64_REG_LR)]
                snapshots.append((rva,cpu.reg_read(UC_ARM64_REG_SP)-(stack+0x7000),regs,bytes(cpu.mem_read(stack+0x7000,0x2000))))
        if rva in (0xb858,0xb948):
            assert cpu.reg_read(UC_ARM64_REG_SP)%16==0
            if rva==0xb858:
                reads.append([cpu.reg_read(UC_ARM64_REG_W0),cpu.reg_read(UC_ARM64_REG_W1)])
                if not read_error:cpu.mem_write(cpu.reg_read(UC_ARM64_REG_X2),bytes([state]))
                rc=read_error
            else:
                entry=[cpu.reg_read(UC_ARM64_REG_W0),cpu.reg_read(UC_ARM64_REG_W1),cpu.reg_read(UC_ARM64_REG_W2),cpu.reg_read(UC_ARM64_REG_W3)]
                writes.append(entry);rc=otg_error if entry[1]==0x1140 else role_error
            lr=cpu.reg_read(UC_ARM64_REG_LR)
            for reg in range(UC_ARM64_REG_X0,UC_ARM64_REG_X17+1):cpu.reg_write(reg,clobber)
            cpu.reg_write(UC_ARM64_REG_W0,rc);cpu.reg_write(UC_ARM64_REG_PC,lr)
    uc.hook_add(UC_HOOK_CODE,hook)
    uc.emu_start(base+0x8ac0,stop,count=1000)
    assert uc.reg_read(UC_ARM64_REG_PC)==stop,'Did not return to caller'
    assert uc.reg_read(UC_ARM64_REG_SP)==stack+0x8000,'Stack not restored'
    assert all(uc.reg_read(reg)==val for reg,val in nonvolatile.items()),'Nonvolatile register corrupted'
    assert uc.reg_read(UC_ARM64_REG_X18)==0,'Windows platform register x18 changed'
    return {'rc':uc.reg_read(UC_ARM64_REG_W0),'reads':reads,'writes':writes,'steps':len(steps)}

tests=0
for sid in [2,7]:
 for clobber in [0,0xa5a5a5a5,0xffffffffffffffff]:
  for state in range(256):
   r=run(state=state,sid=sid,clobber=clobber)
   expected=[[sid,0x1544,0x17,4]] if 5<=state<=34 else [[sid,0x1140,1,0],[sid,0x1544,0x17,0x10]]
   assert r['reads']==[[sid,0x1509]] and r['writes']==expected and r['rc']==0,(state,r)
   tests+=1
for error in [1,0x61,0x6d,0xffffffff]:
 for state in [0,5,34,35,255]:
  r=run(state=state,read_error=error);assert r['rc']==error and not r['writes'];tests+=1
 for state in [0,35,255]:
  r=run(state=state,otg_error=error);assert r['rc']==error and r['writes']==[[2,0x1140,1,0]];tests+=1
 for state in [0,5,35]:
  r=run(state=state,role_error=error);assert r['rc']==error;tests+=1
for index in [0,1,2]:
 for role in [0,1,2,3,4,5,0xffffffff]:
  r=run(index=index,role=role,ready=False);assert r['rc']==0x61 and not r['reads'] and not r['writes'];tests+=1
for index in [0,1,2]:
 for role in [0,1,2,3,4,5,0xffffffff]:
  if index==0 and role==0:continue
  r=run(index=index,role=role)
  if role>4 or index>=2:assert r['rc']==0x61 and not r['reads'] and not r['writes']
  else:assert not r['reads'] and r['writes']==[[2+index,0x1544,0x17,{0:16,1:2,2:4,3:2,4:4}[role]]]
  tests+=1
for relocated_base in [0x10000000,0x180000000,0x7ffb12340000]:
 r=run(state=0,load_base=relocated_base)
 assert r['writes']==[[2,0x1140,1,0],[2,0x1544,0x17,16]] and r['rc']==0
 tests+=1
# Mixed-readiness cases missed by r1: only the selected supported slot matters.
for slot0 in [False,True]:
 for slot1 in [False,True]:
  for slot2 in [False,True]:
   for index in [0,1,2,0xffffffff]:
    for role in [0,1,2,3,4,9]:
     r=run(index=index,role=role,slot_presence=[slot0,slot1,slot2])
     if index>=2 or not [slot0,slot1][index] or role>4:
      assert r['rc']==0x61 and not r['reads'] and not r['writes'],(index,role,slot0,slot1,r)
     elif index==0 and role==0:
      assert r['reads']==[[2,0x1509]] and r['writes']==[[2,0x1140,1,0],[2,0x1544,0x17,16]]
     else:
      assert not r['reads'] and r['writes']==[[2+index,0x1544,0x17,{0:16,1:2,2:4,3:2,4:4}[role]]]
     tests+=1
for state in range(256):
 r=run(state=state,index=1,role=0,slot_presence=[False,True,False])
 assert r['rc']==0 and not r['reads'] and r['writes']==[[3,0x1544,0x17,16]]
 tests+=1
# Capture every instruction boundary on distinct control-flow paths, including
# shrink-wrapped prolog/epilog fragments generated by MSVC.
for kwargs in [{},{'state':5},{'ready':False},{'read_error':0x6d},{'otg_error':0x6d},{'index':1},{'role':1},{'role':9},{'index':1,'slot_presence':[False,True,False]},{'index':1,'slot_presence':[True,False,False]},{'index':0xffffffff}]:run(capture=True,**kwargs)
unique={}
for snapshot in snapshots:unique[(snapshot[0],snapshot[1],tuple(snapshot[2]))]=snapshot
snapshots=list(unique.values())
fixture=root/'build/unwind-fixtures.bin'
with fixture.open('wb') as f:
 f.write(struct.pack('<II',0x3157444e,len(snapshots)))
 for pc,sp,regs,mem in snapshots:f.write(struct.pack('<II31Q',pc,sp,*regs)+mem)
disasm=root/'build/candidate-disasm.txt'
with disasm.open('w',encoding='utf-8') as f:
 for i in Cs(CS_ARCH_ARM64,CS_MODE_ARM).disasm(pe.get_data(helper_start,code_section.Misc_VirtualSize),helper_start):f.write(f'{i.address:x} {i.mnemonic} {i.op_str}\n')
report={'candidate':candidate.name,'sha256':hashlib.sha256(candidate.read_bytes()).hexdigest(),'passedARM64Cases':tests,'nativeUnwindFixtures':len(snapshots),'all256StateBytesCovered':True,'additionalASLRBases':3,'preservedNonvolatileRegisters':True,'stackRestored':True,'x18Untouched':True,'hardwareTesting':False,'remainingLimitation':'Legacy fix20 role heuristic and other VCONN changes retained; PD, hub hotplug, real charging and Windows boot not tested.'}
(root/'build/emulation-report.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
print(json.dumps(report,indent=2))
