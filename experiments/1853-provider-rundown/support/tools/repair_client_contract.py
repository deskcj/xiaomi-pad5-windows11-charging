"""An OFFLINE instruction fragment, never a PE/SYS or installer.
Scope: existing synchronous callback ABI, two statuses, owned-lock release.
Does not implement lifetime/rundown or validate a PMIC snapshot.
"""
from pathlib import Path
import hashlib, json, struct, sys
sys.path.insert(0,r'H:\Vlad\Charging\research\2026-10-26\tools\python-deps')
import pefile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT/'reference/qcusbctcpm8150.sys'
SOURCE_HASH='7c63f4a4b8a9ee0f49b427b6ac94867d2475e02f85d92d5fbcfe4a8aa1804067'

def branch(at,to):
    delta=to-at
    assert delta%4==0 and -(1<<27)<=delta<(1<<27)
    return 0x14000000|((delta//4)&0x3ffffff)
def conditional(at,to,reg,nonzero=False):
    delta=to-at
    assert delta%4==0 and -(1<<20)<=delta<(1<<20)
    return (0x35000000 if nonzero else 0x34000000)|(((delta//4)&0x7ffff)<<5)|reg
def tbnz31(at,to,reg):
    delta=to-at
    assert delta%4==0 and -(1<<15)<=delta<(1<<15)
    return 0x37000000|(31<<19)|(((delta//4)&0x3fff)<<5)|reg
def movz(reg,value): return 0x52800000|(value<<5)|reg
def movk16(reg,value): return 0x72a00000|(value<<5)|reg
def patch_image():
    data=SOURCE.read_bytes()
    assert hashlib.sha256(data).hexdigest()==SOURCE_HASH
    pe=pefile.PE(data=data)
    mapped=bytearray(pe.get_memory_mapped_image())
    patches=[]
    md=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
    for shift,epilogue,literal,tag in [(0,0x8fa0,0x8fc4,0x9d),
                                       (0x190,0x9130,0x9154,0xa0)]:
        # Original acquired path and the existing not-ready branch retain their
        # addresses. Busy never releases a lock owned by another invocation.
        at=lambda r:r+shift
        nop=0xd503201f
        words={r:nop for r in range(0x8f14,0x8fa0,4)}
        words.update({
            0x8f14:0x2a0003f5,          # mov w21,w0: preserve callback NTSTATUS
            0x8f18:0xd5033bbf,          # dmb ish: publish before lock release
            0x8f1c:0xb9011a9f,          # str wzr,[x20,#0x118]: release own lock
            0x8f20:tbnz31(at(0x8f20),at(0x8f54),21),
            0x8f24:conditional(at(0x8f24),at(0x8f40),21,True),
            0x8f28:0xb94013e8,          # ldr w8,[sp,#0x10]: vendor status
            0x8f2c:conditional(at(0x8f2c),epilogue,8),
            0x8f30:movz(21,0x185),
            0x8f34:movk16(21,0xc000),
            0x8f38:branch(at(0x8f38),at(0x8f54)),
            0x8f40:movz(21,0x185),       # pending/timeout is not synchronous success
            0x8f44:movk16(21,0xc000),
            0x8f48:branch(at(0x8f48),at(0x8f54)),
            0x8f54:movz(3,tag),
            0x8f58:branch(at(0x8f58),at(0x8f6c)),
            0x8f5c:0xd5033bbf,
            0x8f60:0xb9011a9f,          # not-ready AFTER acquiring: release own
            0x8f64:0x18000000|(((literal-at(0x8f64))//4)<<5)|21,
            0x8f68:movz(3,tag+1),
            0x8f6c:0x90000008,          # adrp x8: same original WPP data page
            0x8f70:0x91042109,          # add x9,x8,#0x108
            0x8f74:0xf9408508,          # ldr x8,[x8,#0x108]
            0x8f78:0xeb09011f,          # cmp x8,x9
            0x8f7c:0x54000000|(((epilogue-at(0x8f7c))//4)<<5),
            0x8f80:0x2a1503e5,          # mov w5,w21 (also busy common tail)
            0x8f84:0x90000008,
            0x8f88:0xf9408108,          # ldr x8,[x8,#0x100]
            0x8f8c:0x910da324,          # add x4,x25,#0x368
            0x8f90:movz(2,9),
            0x8f94:0xf9402100,          # ldr x0,[x8,#0x40]
            0x8f98:movz(1,2),
            0x8f9c:branch(at(0x8f9c),0x1698)|0x80000000, # bl WPP
        })
        # ADRP must be encoded for each PC (read lives on page8000, write9000).
        for r in [0x8f6c,0x8f84]:
            pages=((0xc000-(at(r)&~0xfff))//4096)&0x1fffff
            words[r]=0x90000008|((pages&3)<<29)|((pages>>2)<<5)
        for r,word in words.items():
            rva=at(r)
            before=bytes(mapped[rva:rva+4]);after=struct.pack('<I',word)
            assert len(list(md.disasm(after,rva)))==1
            mapped[rva:rva+4]=after
            if before!=after:
                dis=lambda code:next(md.disasm(code,rva))
                a,b=dis(before),dis(after)
                patches.append(dict(rva=hex(rva),before=before.hex(),after=after.hex(),
                     original=a.mnemonic+' '+a.op_str,repaired=b.mnemonic+' '+b.op_str))
        # Busy already checks WPP; jump into the shared tail after that check.
        busy=at(0x8ee0)
        old=bytes(mapped[busy:busy+4]);new=struct.pack('<I',branch(busy,at(0x8f80)))
        mapped[busy:busy+4]=new
        patches.append(dict(rva=hex(busy),before=old.hex(),after=new.hex(),
                            purpose='shared WPP tail, preserves foreign owner'))
        start=0x8e38+shift
        assert mapped[start:at(0x8f14)]==pe.get_data(start,at(0x8f14)-start)
        assert mapped[epilogue:epilogue+28]==pe.get_data(epilogue,28)
    return pe,bytes(mapped),patches

if __name__=='__main__':
    pe,mapped,patches=patch_image()
    fragment=mapped[0x8e38:0x9158]
    (ROOT/'build/client-contract-fragment-OFFLINE.bin').write_bytes(fragment)
    report=dict(source_sha256=SOURCE_HASH,fragment_rva='0x8e38',
                fragment_sha256=hashlib.sha256(fragment).hexdigest(),
                format='raw ARM64 instruction region, NOT PE/SYS',
                both_statuses=True,prologue_epilogue_unchanged=True,
                release_memory_barrier=True,multicore_memory_model_tested=False,
                lifetime_rundown_implemented=False,installed=False,patches=patches)
    (ROOT/'build/client-contract-fragment.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k!='patches'},indent=2))
