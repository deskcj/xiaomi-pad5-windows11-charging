"""Offline Type-C transport repair: release own lock and propagate backend status.
No installation, register I/O, device reset, or production driver execution.
"""
from pathlib import Path
import hashlib,json,struct,itertools,os
import pefile
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
from emulate_transport import Machine,CTX
root=Path(__file__).resolve().parent;out=root/'typec-transportfix2';out.mkdir(exist_ok=True)
source=Path(os.environ.get('NABU_TYPEC_SOURCE',str(root.parents[1]/'2026-10-26/handover/qcusbctcpm8150.sys')))
data=source.read_bytes();sourcehash=hashlib.sha256(data).hexdigest()
assert sourcehash=='7c63f4a4b8a9ee0f49b427b6ac94867d2475e02f85d92d5fbcfe4a8aa1804067'
pe=pefile.PE(data=data);result=bytearray(data);cs=Cs(CS_ARCH_ARM64,CS_MODE_ARM);patches=[]
def patch(rva,before,word):
 offset=pe.get_offset_from_rva(rva);ins=next(cs.disasm(bytes(result[offset:offset+4]),rva));assert ins.mnemonic+' '+ins.op_str==before,(hex(rva),ins.mnemonic,ins.op_str)
 after=struct.pack('<I',word);new=next(cs.disasm(after,rva));patches.append({'rva':hex(rva),'before':before,'after':new.mnemonic+' '+new.op_str});result[offset:offset+4]=after
# The previously isolated not-ready lock repair.
for a,b,c,literal in [(0x8f5c,0x8f60,0x8f78,0x8fc4),(0x90ec,0x90f0,0x9108,0x9154)]:
 word=struct.unpack('<I',pe.get_data(a,4))[0]
 patch(a,f'ldr w10, #0x{literal:x}',(word&~31)|21)
 patch(b,'mov w21, w10',0xb9011a9f)
 patch(c,'mov w5, w10',0x2a1503e5)
# On backend error, preserve the exact status in nonvolatile w21 before WPP.
# Three address-calculation instructions become ADR+LDR+MOV; no code growth,
# stack, prologue/epilogue, branch-target or unwind metadata change.
for a in [0x8f20,0x90b0]:
 delta=0xc108-a;assert -(1<<20)<=delta<(1<<20);imm=delta&0x1fffff
 adr=0x10000000|((imm&3)<<29)|((imm>>2)<<5)|9
 patch(a,'adrp x8, #0xc000',adr)
 patch(a+4,'add x9, x8, #0x108',0xf9400128)
 patch(a+8,'ldr x8, [x8, #0x108]',0x2a0503f5)
security=pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
assert security.VirtualAddress+security.Size==len(result)
result=result[:security.VirtualAddress];struct.pack_into('<II',result,security.get_file_offset(),0,0)
check=pe.OPTIONAL_HEADER.get_field_absolute_offset('CheckSum');struct.pack_into('<I',result,check,0)
struct.pack_into('<I',result,check,pefile.PE(data=bytes(result)).generate_checksum())
candidate=out/'qcusbctcpm8150-transportfix2-UNSIGNED-NOT-INSTALLED.sys'
if candidate.exists():assert candidate.read_bytes()==result,'Do not overwrite a different candidate'
candidate.write_bytes(result);new=pefile.PE(data=bytes(result));assert new.verify_checksum()
for n in [1,3,5,10,12]:
 a=pe.OPTIONAL_HEADER.DATA_DIRECTORY[n];b=new.OPTIONAL_HEADER.DATA_DIRECTORY[n]
 assert (a.VirtualAddress,a.Size)==(b.VirtualAddress,b.Size) and pe.get_data(a.VirtualAddress,a.Size)==new.get_data(b.VirtualAddress,b.Size)
assert [(s.VirtualAddress,s.SizeOfRawData,s.Characteristics) for s in pe.sections]==[(s.VirtualAddress,s.SizeOfRawData,s.Characteristics) for s in new.sections]
count=0;counterexamples=0;fixtures=[]
methods=['read','write','set-role','set-power','transmit','command','get-status']
for base,ready,busy,tracing,error,method in itertools.product([0x140000000,0x180000000,0x7ffb12340000],[0,1],[0,1,2],[False,True],[0,0xc0000001,0xc0000185,0xc000009e,0xffffffff],methods):
 old=Machine(source,base,ready,busy,tracing,error);fixed=Machine(candidate,base,ready,busy,tracing,error)
 if base==0x140000000 and busy<2 and method in ['read','write']:fixed.capture=True
 value=0x99 if method=='command' else (0 if method=='transmit' else 0x4a)
 a=old.call(method,value);b=fixed.call(method,value)
 expected=0xc0000010 if busy else (0xc0000182 if not ready else error)
 assert b['status']==expected,(base,ready,busy,tracing,error,method,b,hex(expected))
 assert b['lock']==busy,(method,b)
 if busy or not ready:assert not b['calls']
 elif error:
  assert a['status']==0 and a['calls'] and b['calls'];counterexamples+=1
  if method=='get-status':assert b['outputInformation'] is None and len(b['calls'])==1 and len(a['calls'])==3
 else:
  assert a==b,(method,a,b)
  if method=='get-status':assert b['outputInformation']==3
 # A newly propagated error also reaches the existing caller's error trace.
 # Preserve all original helper messages; allow the now-reachable outer trace.
 if method in ['read','write']:assert a['trace']==b['trace']
 elif method!='get-status':assert b['trace'][:len(a['trace'])]==a['trace'],('Old trace prefix changed',method,a,b)
 fixtures.extend(fixed.snapshots);count+=1
unique={}
for f in fixtures:unique[(f[0],f[1],tuple(f[2]))]=f
fixtures=list(unique.values())
with (out/'unwind-fixtures.bin').open('wb') as f:
 f.write(struct.pack('<II',0x3157444e,len(fixtures)))
 for pc,sp,regs,mem in fixtures:f.write(struct.pack('<II31Q',pc,sp,*regs)+mem)
# Not-ready then ready must recover without changing device or port state.
seq=0
for first,second,tracing in itertools.product(['read','write'],['read','write'],[False,True]):
 fixed=Machine(candidate,ready=0,trace=tracing);assert fixed.call(first)['status']==0xc0000182
 fixed.uc.mem_write(CTX+0xf0,b'\x01');assert fixed.call(second)['status']==0;seq+=1
report={'sourceSHA256':sourcehash,'candidateSHA256':hashlib.sha256(result).hexdigest(),'candidateBytes':len(result),'instructionPatches':patches,'pairedActualARM64Cases':count,'backendErrorCounterexamples':counterexamples,'retrySequences':seq,'nativeUnwindFixtures':len(fixtures),'ASLRBases':3,'x18AndNonvolatilePreserved':True,'existingLockOwnerPreserved':True,'failedGetStatusNotPublishedAsValid':True,'kernelDriverInstalled':False,'kernelDriverLoaded':False,'hardwareRegistersWritten':False,'hardwareCauseProven':False,'fullChargingFixClaimed':False,'limitation':'WDF/backend/WPP mocked. Does not simulate USB PHY, PD wire timing or actual hub/SSD.'}
(out/'verification.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
print(json.dumps({k:v for k,v in report.items() if k!='instructionPatches'},indent=2))
