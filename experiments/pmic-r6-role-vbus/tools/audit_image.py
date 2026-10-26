from pathlib import Path
import json,sys,struct,hashlib
import pefile
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
root=Path(__file__).resolve().parents[1]
stock=pefile.PE(r'C:\Windows\System32\DriverStore\FileRepository\qcpmicext8150.inf_arm64_fe1800db720f064c\qcpmicext8150.sys')
unsigned=pefile.PE(str(root/'build/qcpmicext8150_unsigned.sys'))
signed=pefile.PE(str(root/'package/qcpmicext8150.sys'))
assert unsigned.FILE_HEADER.Machine==signed.FILE_HEADER.Machine==0xaa64
assert unsigned.verify_checksum() and signed.verify_checksum()
for a,b in zip(unsigned.sections,signed.sections):
 assert a.Name==b.Name and a.VirtualAddress==b.VirtualAddress and a.Misc_VirtualSize==b.Misc_VirtualSize
 assert a.get_data()==b.get_data(),'Signing changed a mapped section'
for n in [1,3,5,10,12]:
 a=unsigned.OPTIONAL_HEADER.DATA_DIRECTORY[n];b=signed.OPTIONAL_HEADER.DATA_DIRECTORY[n]
 assert (a.VirtualAddress,a.Size)==(b.VirtualAddress,b.Size)
 assert unsigned.get_data(a.VirtualAddress,a.Size)==signed.get_data(b.VirtualAddress,b.Size)
assert all(not(s.Characteristics&0x80000000 and s.Characteristics&0x20000000) for s in signed.sections)
md=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
diffs=[]
for sec in stock.sections:
 if not sec.Characteristics&0x20000000:continue
 old=sec.get_data();new=unsigned.get_data(sec.VirtualAddress,len(old))
 offsets=[i for i in range(0,len(old),4) if old[i:i+4]!=new[i:i+4]]
 groups=[]
 for i in offsets:
  if groups and i==groups[-1][-1]+4:groups[-1].append(i)
  else:groups.append([i])
 for g in groups:
  rva=sec.VirtualAddress+g[0];n=g[-1]-g[0]+4
  def dis(b):return [f'{x.address:x} {x.mnemonic} {x.op_str}' for x in md.disasm(b,rva)]
  diffs.append({'rva':hex(rva),'bytes':n,'stock':dis(stock.get_data(rva,n)),'candidate':dis(unsigned.get_data(rva,n))})
report={'unsignedSHA256':hashlib.sha256(Path(unsigned.__data__.name).read_bytes()).hexdigest() if hasattr(unsigned.__data__,'name') else hashlib.sha256((root/'build/qcpmicext8150_unsigned.sys').read_bytes()).hexdigest(),'signedSHA256':hashlib.sha256((root/'package/qcpmicext8150.sys').read_bytes()).hexdigest(),'signedMappedSectionsEqualUnsigned':True,'allChecksumsValid':True,'RWXSections':False,'oldExecutableSectionDifferences':diffs,'kernelLoadPerformed':False}
(root/'build/static-image-audit.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
print(json.dumps({'signedSHA256':report['signedSHA256'],'mappedSectionsEqual':True,'originalExecutableDifferences':diffs},indent=2))
