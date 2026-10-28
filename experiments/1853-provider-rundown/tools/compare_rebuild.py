"""Require byte-identical final SYS and all allocated COFF sections/relocations.
COFF timestamps, debug paths and their checksums may differ across directories.
"""
import hashlib,json,sys
from pathlib import Path
from link_backend import coff
ROOT=Path(__file__).resolve().parents[1]
sha=lambda b:hashlib.sha256(b).hexdigest()
rebuild=ROOT/(sys.argv[1] if len(sys.argv)>1 else 'reproduce')
assert rebuild.parent==ROOT and rebuild.name.startswith('reproduce')
a=(ROOT/'build/client_repair.obj').read_bytes();b=(rebuild/'build/client_repair.obj').read_bytes()
sa,ya=coff(a);sb,yb=coff(b)
assert ya==yb,'Compiled symbols differ'
assert len(sa)==len(sb)
allowed={'.text$mn','.text','.bss','.data','.rdata','.xdata','.pdata','.gfids$y','.giats$y','.gljmp$y','.drectve'}
compared=[];ignored=[]
for x,y in zip(sa,sb):
    assert x['name']==y['name'] and x['flags']==y['flags']
    if x['name'] in allowed:
        assert x==y,('Allocated section/relocations differ',x['name'])
        compared.append(x['name'])
    else:
        assert x['name'] in ['.debug$S','.debug$T','.chks64']
        ignored.append(x['name'])
first=(ROOT/'build/qcusbctcpm8150.sys').read_bytes()
second=(rebuild/'build/qcusbctcpm8150.sys').read_bytes()
assert first==second,'Final unsigned SYS is not byte-identical'
report=dict(identical=True,finalSYSByteIdentical=True,separateDirectory=True,rebuildDirectory=rebuild.name,
    unsignedSHA256=sha(first),objectSHA256=sha(a),rebuiltObjectSHA256=sha(b),
    rawCOFFByteIdentical=a==b,allocatedCOFFSectionsAndRelocationsIdentical=True,
    comparedSections=compared,ignoredOnlyCOFFMetadata=ignored,
    metadataExplanation='COFF timestamp, absolute debug source path and debug checksum differ; all linked bytes and symbols match.')
(ROOT/'build/reproducibility.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
print('Independent rebuild: final SYS byte-identical; allocated COFF data/code/unwind/relocations identical.')
