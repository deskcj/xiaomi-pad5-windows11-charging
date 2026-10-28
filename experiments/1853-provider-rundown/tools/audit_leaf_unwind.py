"""Prove that compiler-omitted runtime-function regions are real leaves."""
import json,struct,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,r'H:\Vlad\Charging\research\2026-10-26\tools\python-deps')
import pefile
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
from link_backend import coff
def audit(kind):
    name='qcpmictcc8150' if kind=='backend' else 'qcusbctcpm8150'
    pe=pefile.PE(str(ROOT/f'build/{name}.sys'))
    d=pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
    ranges=[]
    for r,u in struct.iter_unpack('<II',pe.get_data(d.VirtualAddress,d.Size)):
        length=(((u>>2)&0x7ff) if u&3 else (struct.unpack('<I',pe.get_data(u,4))[0]&0x3ffff))*4
        ranges.append((r,r+length))
    cs=Cs(CS_ARCH_ARM64,CS_MODE_ARM);cs.detail=True
    section=next(s for s in pe.sections if s.Name.rstrip(b'\0')==b'.skcode')
    manifest=json.loads((ROOT/f'build/{kind}-build.json').read_text())
    coff_sections,coff_symbols=coff((ROOT/f'build/{kind}_repair.obj').read_bytes())
    text_indices={s['index'] for s in coff_sections if s['name'].startswith('.text')}
    work=[manifest['symbols'][s['name']] for s in coff_symbols if s and s['type']==32 and s['section'] in text_indices]
    work += [a for a,b in ranges if section.VirtualAddress<=a<section.VirtualAddress+section.Misc_VirtualSize]
    work += [a['rva'] for a in manifest.get('adapters',[])]
    reachable=set()
    while work:
        at=work.pop()
        if not section.VirtualAddress<=at<section.VirtualAddress+section.Misc_VirtualSize or at in reachable:continue
        reachable.add(at)
        ins=list(cs.disasm(pe.get_data(at,4),at));assert len(ins)==1,(hex(at),'Invalid reachable instruction')
        ins=ins[0]
        if ins.mnemonic in ['b','cbz','cbnz','tbz','tbnz'] or ins.mnemonic.startswith('b.'):
            target=ins.operands[-1].imm
            work.append(target)
        if ins.mnemonic not in ['ret','br','b','brk','udf']:work.append(at+4)
    leaves=[]
    for at in sorted(reachable):
        if any(a<=at<b for a,b in ranges):continue
        code=pe.get_data(at,4)
        if code==bytes(4):continue # unreachable section alignment
        ins=list(cs.disasm(code,at));assert len(ins)==1,(hex(at),code.hex())
        ins=ins[0]
        assert ins.mnemonic not in ['bl','blr','paciasp','pacibsp'],(hex(at),ins.mnemonic)
        read,written=ins.regs_access()
        names=[cs.reg_name(r) for r in written]
        forbidden={'sp','wsp','fp','x29','w29','lr','x30','w30','x18','w18'}
        forbidden|={p+str(i) for p in ['x','w'] for i in range(19,29)}
        forbidden|={p+str(i) for p in ['v','q','d','s','h','b'] for i in range(8,16)}
        assert not forbidden.intersection(names),(hex(at),ins.mnemonic,ins.op_str,names)
        assert 'sp' not in ins.op_str,(hex(at),ins.mnemonic,ins.op_str)
        leaves.append(dict(rva=at,code=code.hex(),instruction=ins.mnemonic+' '+ins.op_str))
    report=dict(kind=kind,omittedLeafInstructions=len(leaves),noStackOrNonvolatileWrites=True,
                noLinkRegisterChanges=True,noCalls=True,leaves=leaves,
                reachableInstructions=len(reachable),
                leafLow=section.VirtualAddress,leafHigh=section.VirtualAddress+section.Misc_VirtualSize)
    (ROOT/f'build/{kind}-leaf-unwind-proof.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(kind,len(leaves),'compiler leaf instructions proven')
if __name__=='__main__':audit('client')
