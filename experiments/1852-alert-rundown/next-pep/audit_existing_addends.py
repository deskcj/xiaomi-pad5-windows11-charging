"""Check whether the COFF addend defect affects the exact1851/1852 objects."""
from pathlib import Path
import hashlib,json,struct,sys
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT.parent/'tools'))
from link_backend import coff,signed
old=Path(r'H:\Vlad\Charging\candidate-1851-stock-repair')
rows=[]
for root,kind,label in [(ROOT.parent,'client','1852-client'),(old,'client','1851-client'),(old,'backend','1851-backend')]:
    path=root/f'build/{kind}_repair.obj';blob=path.read_bytes()
    meta=json.loads((root/f'build/{kind}-build.json').read_text())
    assert hashlib.sha256(blob).hexdigest()==meta['objectSHA256']
    sections,symbols=coff(blob);found=[]
    for s in sections:
        for offset,index,kind in s['relocs']:
            if kind!=4:continue
            word=struct.unpack_from('<I',s['data'],offset)[0]
            addend=signed((((word>>5)&0x7ffff)<<2)|((word>>29)&3),21)
            found.append(addend)
    assert found and not any(found),(label,found)
    rows.append(dict(object=label,sha256=meta['objectSHA256'],ADRPRelocations=len(found),allADRPAddendsZero=True,
        historicalBytePageAddendDefectAffectsThisObject=False))
(ROOT/'build/existing-object-addends.json').write_text(json.dumps(rows,indent=2)+'\n',encoding='utf-8')
print(json.dumps(rows,indent=2))
