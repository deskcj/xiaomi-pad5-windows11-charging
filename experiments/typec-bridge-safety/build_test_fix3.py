"""Add strict WDF wait-lock success checks and correct relative timeout encoding.
Offline only; does not install or execute any code in the Windows kernel.
"""
from pathlib import Path
import struct,json,hashlib,itertools
import pefile
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
from emulate_waitlock import WaitMachine
root=Path(__file__).resolve().parent;out=root/'typec-safetyfix3';out.mkdir(exist_ok=True)
source=root/'typec-transportfix2/qcusbctcpm8150-transportfix2-UNSIGNED-NOT-INSTALLED.sys'
data=source.read_bytes();assert hashlib.sha256(data).hexdigest()=='5b4432837a00db454a04aad2cc01ea1018d312988a057aa1fb82630882fa9e24'
pe=pefile.PE(data=data);result=bytearray(data);cs=Cs(CS_ARCH_ARM64,CS_MODE_ARM);patches=[]
sites=[(0xfb14,0xfbb4,0xfbf4,0),(0x10200,0x102a8,0x102ec,19),(0x11174,0x111f4,0x11238,0),(0x11a58,0x11b0c,0x11b50,0),(0x11c18,0x11ccc,0x11d10,0)]
def patch(rva,expected,word):
 o=pe.get_offset_from_rva(rva);i=next(cs.disasm(bytes(result[o:o+4]),rva));before=i.mnemonic+' '+i.op_str
 assert before==expected,(hex(rva),before,expected)
 b=struct.pack('<I',word);i=next(cs.disasm(b,rva));patches.append({'rva':hex(rva),'before':before,'after':i.mnemonic+' '+i.op_str});result[o:o+4]=b
for timer,condition,target,reg in sites:
 # -300000000 ticks = relative30s; +300000000 is an absolute date in1601.
 patch(timer,'mov w8, #0xa300',0x92800008|(0xa2ff<<5))
 patch(timer+4,'movk w8, #0x11e1, lsl #16',0xf2a00008|(0xee1e<<5))
 store=struct.unpack('<I',pe.get_data(timer+8,4))[0]
 offset=((store>>10)&0xfff)*4
 assert offset in [0,16] and store&0xffc003ff==0xb90003e8
 expected='str w8, [sp]' if offset==0 else 'str w8, [sp, #0x10]'
 patch(timer+8,expected,0xf9000000|((offset//8)<<10)|(31<<5)|8)
 delta=target-condition;assert delta%4==0
 patch(condition,f'tbz w{reg}, #0x1f, #0x{target:x}',0x34000000|(((delta//4)&0x7ffff)<<5)|reg)
checksum=pe.OPTIONAL_HEADER.get_field_absolute_offset('CheckSum');struct.pack_into('<I',result,checksum,0);struct.pack_into('<I',result,checksum,pefile.PE(data=bytes(result)).generate_checksum())
candidate=out/'qcusbctcpm8150-safetyfix3-UNSIGNED-NOT-INSTALLED.sys'
if candidate.exists():assert candidate.read_bytes()==result
candidate.write_bytes(result);fixed=pefile.PE(data=bytes(result));assert fixed.verify_checksum()
for n in [1,3,5,10,12]:
 a=pe.OPTIONAL_HEADER.DATA_DIRECTORY[n];b=fixed.OPTIONAL_HEADER.DATA_DIRECTORY[n]
 assert (a.VirtualAddress,a.Size)==(b.VirtualAddress,b.Size) and pe.get_data(a.VirtualAddress,a.Size)==fixed.get_data(b.VirtualAddress,b.Size)
assert pe.get_data(0x8e38,0x914c-0x8e38)==fixed.get_data(0x8e38,0x914c-0x8e38),'Verified transport helpers changed'
assert [(s.VirtualAddress,s.SizeOfRawData,s.Characteristics) for s in pe.sections]==[(s.VirtualAddress,s.SizeOfRawData,s.Characteristics) for s in fixed.sections]
count=0;counterexamples=0;snapshots=[]
for base,entry,status,tracing,poison in itertools.product([0x140000000,0x180000000,0x7ffb12340000],[0x11a40,0x11c00],[0,0x102,0xc0000001,0xffffffff],[False,True],[0,0xa5,0xff]):
 old=WaitMachine(source,status,tracing,base);new=WaitMachine(candidate,status,tracing,base)
 if base==0x140000000:new.capture=True
 a=old.run_callback(entry,poison);b=new.run_callback(entry,poison)
 assert all(e.get('timeout100ns',-300000000)==-300000000 for e in b['events'])
 releases=[e for e in b['events'] if e['operation']=='release']
 if status==0:
  assert len(releases)==1 and releases[0]['ownedByThisCall']
  assert a['flagsAfter']==b['flagsAfter']
 else:
  assert not releases and b['flagsBefore']==b['flagsAfter'],b
  if status==0x102:
   assert any(e['operation']=='release' and not e['ownedByThisCall'] for e in a['events']);counterexamples+=1
 snapshots.extend(new.snapshots);count+=1
unique={}
for s in snapshots:unique[(s[0],s[1],tuple(s[2]))]=s
snapshots=list(unique.values())
with (out/'waitlock-unwind-fixtures.bin').open('wb') as f:
 f.write(struct.pack('<II',0x3157444e,len(snapshots)))
 for pc,sp,regs,mem in snapshots:f.write(struct.pack('<II31Q',pc,sp,*regs)+mem)
report={'baseTransportFixSHA256':hashlib.sha256(data).hexdigest(),'candidateSHA256':hashlib.sha256(result).hexdigest(),'newInstructionPatches':patches,'waitLockCallSitesPatched':5,'timeoutIsRelative30s':True,'timeoutWrittenAsFull64Bits':True,'stackPoisonPatterns':3,'successRequiresSTATUS_SUCCESS':True,'pairedCallbackCases':count,'timeoutOwnershipCounterexamples':counterexamples,'nativeWaitCallbackFixtures':len(snapshots),'transportHelpersByteIdenticalToFix2':True,'kernelDriverInstalled':False,'hardwareCauseProven':False,'allFiveCallerPathsEmulated':False,'callerCoverage':'Two small callbacks fully emulated; startup/cleanup workers have structural patch checks, pending full lifecycle modeling.'}
(out/'verification.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
print(json.dumps({k:v for k,v in report.items() if k!='newInstructionPatches'},indent=2))
