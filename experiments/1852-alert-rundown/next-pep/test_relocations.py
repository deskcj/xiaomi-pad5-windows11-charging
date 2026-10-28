"""Use Microsoft LINK as independent oracle for ARM64 COFF addends."""
from pathlib import Path
import hashlib,json,re,struct,sys
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT.parent/'tools'))
from link_backend import coff,signed
import pefile
p=pefile.PE(data=(ROOT/'build/reloc-probe-NOT-LOADED.dll').read_bytes())
mapping=(ROOT/'build/reloc-probe.map').read_text()
target=int(re.search(r'\bBlock\s+([0-9a-fA-F]{16})\b',mapping).group(1),16)
ss,sy=coff((ROOT/'build/probe_get.obj').read_bytes())
s=next(s for s in ss if s['name']=='.text$mn')
exports={e.name.decode():e.address+p.OPTIONAL_HEADER.ImageBase for e in p.DIRECTORY_ENTRY_EXPORT.symbols}
get=next(x for x in sy if x and x['name']=='get_after')
start=exports['get_after']-get['value'];data=bytearray(s['data']);old=bytearray(s['data']);rows=[]
for offset,idx,kind in s['relocs']:
    assert sy[idx]['name']=='Block';word=struct.unpack_from('<I',data,offset)[0];place=start+offset
    if kind==4:
        addend=signed((((word>>5)&0x7ffff)<<2)|((word>>29)&3),21)
        def encode(a):
            imm=((((target+a)&~4095)-(place&~4095))//4096)&0x1fffff
            return (word&~((0x7ffff<<5)|(3<<29)))|((imm&3)<<29)|((imm>>2)<<5)
        repaired=encode(addend);incorrect=encode(addend*4096)
        rows.append(dict(offset=offset,addendBytes=addend))
    elif kind in [6,7]:
        scale=0 if kind==6 else (word>>30)&3
        value=(target+(((word>>10)&4095)<<scale))&4095
        repaired=(word&~(4095<<10))|((value>>scale)<<10);incorrect=repaired
    else:raise AssertionError(kind)
    struct.pack_into('<I',data,offset,repaired);struct.pack_into('<I',old,offset,incorrect)
expected=p.get_data(start-p.OPTIONAL_HEADER.ImageBase,len(data))
assert bytes(data)==expected,'Corrected COFF relocation does not match Microsoft LINK'
assert bytes(old)!=expected,'Expected historical addend error counterexample'
assert {0,32}<={r['addendBytes'] for r in rows},rows
assert (target&4095)==4080 and ((target+32)&~4095)!=(target&~4095),'Probe does not cross a page'
report=dict(status='CORRECTED_RELOCATION_BYTES_MATCH_MICROSOFT_LINK',cases=rows,
    completeTextByteIdentical=True,historicalAlgorithmCounterexample=True,
    probeDLLSHA256=hashlib.sha256((ROOT/'build/reloc-probe-NOT-LOADED.dll').read_bytes()).hexdigest(),
    probeDLLLoaded=False,driverLoaded=False,hardwareIO=False)
(ROOT/'build/relocation-oracle.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
print(json.dumps(report,indent=2))
