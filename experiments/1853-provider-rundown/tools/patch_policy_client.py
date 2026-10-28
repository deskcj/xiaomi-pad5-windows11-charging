"""Finish native client image and explicit battery cache repair. Offline."""
import json,sys,struct,hashlib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'support/tools'))
from repair_client_contract import patch_image,branch
import pefile
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
sha=lambda b:hashlib.sha256(b).hexdigest()
cs=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
def finish(path,data,report):
    p=pefile.PE(data=bytes(data));pos=p.OPTIONAL_HEADER.get_field_absolute_offset('CheckSum')
    struct.pack_into('<I',data,pos,0);struct.pack_into('<I',data,pos,pefile.PE(data=bytes(data)).generate_checksum())
    assert pefile.PE(data=bytes(data)).verify_checksum()
    path.write_bytes(data);report['unsignedSHA256']=sha(data)
    path.with_suffix('.policy.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
def patch_client():
    path=ROOT/'build/qcusbctcpm8150.sys';data=bytearray(path.read_bytes());pe=pefile.PE(data=data)
    manifest=json.loads((ROOT/'build/client-build.json').read_text())
    assert sha(data)==manifest['unsignedSHA256']
    orig,mapped,transport=patch_image();changes=[]
    for row in transport:
        at=int(row['rva'],16);before=bytes.fromhex(row['before']);after=bytes.fromhex(row['after'])
        off=pe.get_offset_from_rva(at);assert data[off:off+4]==before
        data[off:off+4]=after
    def patch(at,expected,word):
        off=pe.get_offset_from_rva(at);old=bytes(data[off:off+4]);i=next(cs.disasm(old,at))
        assert i.mnemonic+' '+i.op_str==expected,(hex(at),i.mnemonic,i.op_str)
        after=struct.pack('<I',word);data[off:off+4]=after
        changes.append(dict(rva=at,before=old.hex(),after=after.hex(),purpose=expected))
    # This typed halfword has ready at F0 and stop at F1. Both helpers already
    # own 118 before the check: close can neither admit nor free a new caller.
    for at in [0x8ee4,0x9074]:patch(at,'ldrb w8, [x20, #0xf0]',0x79400000|((0xf0//2)<<10)|(20<<5)|8)
    sites=[(0xfb14,0xfbb4,0xfbf4,0),(0x10200,0x102a8,0x102ec,19),
           (0x11174,0x111f4,0x11238,0),(0x11a58,0x11b0c,0x11b50,0),(0x11c18,0x11ccc,0x11d10,0)]
    for timer,cond,target,reg in sites:
        patch(timer,'mov w8, #0xa300',0x92800008|(0xa2ff<<5))
        patch(timer+4,'movk w8, #0x11e1, lsl #16',0xf2a00008|(0xee1e<<5))
        word=struct.unpack('<I',pe.get_data(timer+8,4))[0];offset=((word>>10)&0xfff)*4
        expected='str w8, [sp]' if offset==0 else 'str w8, [sp, #0x10]'
        patch(timer+8,expected,0xf9000000|((offset//8)<<10)|(31<<5)|8)
        patch(cond,f'tbz w{reg}, #0x1f, #0x{target:x}',0x34000000|(((target-cond)//4)<<5)|reg)
    # The separate D0-exit's 178 wait lock used the same poisoned 32-bit
    # absolute timeout, which wasn't included in historical fix3 coverage.
    patch(0x12dbc,'mov w8, #0xa300',0x92800008|(0xa2ff<<5))
    patch(0x12dc0,'movk w8, #0x11e1, lsl #16',0xf2a00008|(0xee1e<<5))
    patch(0x12dc4,'str w8, [sp, #0x10]',0xf9000be8)
    patch(0x13148,'tbz w0, #0x1f, #0x1318c',0x34000000|(((0x1318c-0x13148)//4)<<5))
    patch(0x1321c,'tbz w22, #0x1f, #0x13260',0x34000000|(((0x13260-0x1321c)//4)<<5)|22)
    # A close operation must obtain ownership even if the old 100ms budget
    # elapsed. Native Yield sleeps 1ms; the stop flag prevents new admissions.
    patch(0x11288,'b.gt #0x11250',branch(0x11288,0x11250))
    patch(0x13000,'b.gt #0x12fc8',branch(0x13000,0x12fc8))
    finish(path,data,dict(name='client-1851',baseNativeSHA256=manifest['unsignedSHA256'],
                         transportPatches=transport,patches=changes,installed=False))
def patch_battery():
    original=(ROOT/'reference/qcbattmngr8150.sys').read_bytes()
    assert sha(original)=='3659a20de0606aa7283ea3197a1c212e28bfec212c838914f19d74be629453a3'
    p=pefile.PE(data=original);data=bytearray(original[:max(s.PointerToRawData+s.SizeOfRawData for s in p.sections)])
    # Preserve actual battery USB/DC policy. Only the skip based on its private
    # stale cache is removed, so recovery's external suspend is overwritten on
    # the next real policy evaluation. No guessed charge/thermal limits.
    at=0x18094;off=p.get_offset_from_rva(at);old=p.get_data(at,4)
    i=next(cs.disasm(old,at));assert i.mnemonic=='b.eq' and i.op_str=='#0x18190'
    data[off:off+4]=struct.pack('<I',0xd503201f)
    at_status=0x1812c;status_before=p.get_data(at_status,4)
    i=next(cs.disasm(status_before,at_status));assert i.mnemonic=='tbnz' and i.op_str=='w19, #0x1f, #0x1817c'
    status_after=struct.pack('<I',0x35000000|(((0x1817c-at_status)//4)<<5)|19)
    data[p.get_offset_from_rva(at_status):p.get_offset_from_rva(at_status)+4]=status_after
    struct.pack_into('<II',data,p.OPTIONAL_HEADER.DATA_DIRECTORY[4].get_file_offset(),0,0)
    finish(ROOT/'build/qcbattmngr8150.sys',data,dict(name='battery-10731',originalSHA256=sha(original),
           patches=[dict(rva=at,before=old.hex(),after='1f2003d5'),dict(rva=at_status,before=status_before.hex(),after=status_after.hex())],
           policyPreserved=True,suspendReappliedOnPolicyEvaluation=True,newImports=False,installed=False))
if __name__=='__main__':patch_client();patch_battery();print('Native client and battery SYS prepared; no installation.')
