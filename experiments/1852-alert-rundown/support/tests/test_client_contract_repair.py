"""Execute original request callers with an offline repaired instruction region.
The original real two-status ABI is modeled; no Windows kernel is called.
"""
from pathlib import Path
import hashlib, importlib.util, itertools, json, struct, sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
sys.path.insert(0,r'H:\Vlad\Charging\research\2026-10-26\tools\python-deps')
from repair_client_contract import patch_image, SOURCE, SOURCE_HASH
from unicorn.arm64_const import *
spec=importlib.util.spec_from_file_location('contract_machine',ROOT/'reference/legacy_client_machine.py')
legacy=importlib.util.module_from_spec(spec);spec.loader.exec_module(legacy)

class Client(legacy.Machine):
    def __init__(self,nt,vendor,repaired=True,**kwargs):
        self.nt=nt;self.vendor=vendor
        super().__init__(SOURCE,error=0,**kwargs)
        if repaired:
            self.uc.mem_write(self.base+0x8e38,PATCHED[0x8e38:0x9158])
    def hook(self,u,a,n,unused):
        if a not in [legacy.STUB+0x200,legacy.STUB+0x300]:
            return super().hook(u,a,n,unused)
        reg=u.reg_read(UC_ARM64_REG_W0);length=u.reg_read(UC_ARM64_REG_W1)
        buf=u.reg_read(UC_ARM64_REG_X2);out=u.reg_read(UC_ARM64_REG_X3)
        lr=u.reg_read(UC_ARM64_REG_LR)
        assert 0<length<64 and u.reg_read(UC_ARM64_REG_SP)%16==0
        self.calls.append(dict(register=reg,length=length,ntstatus=hex(self.nt),vendor=self.vendor))
        if self.nt==0 and self.vendor==0:
            if a==legacy.STUB+0x200:self.vregs[reg]=int.from_bytes(u.mem_read(buf,length),'little')
            else:u.mem_write(buf,self.vregs.get(reg,0).to_bytes(length,'little'))
        else:
            # A failed transport is allowed to have changed its output locally;
            # the caller must not advertise this as a valid port snapshot.
            if a==legacy.STUB+0x300:u.mem_write(buf,b'\xe7'*length)
        u.mem_write(out,struct.pack('<I',self.vendor))
        for r in range(UC_ARM64_REG_X0,UC_ARM64_REG_X17+1):u.reg_write(r,0xcccccccccccccccc)
        u.reg_write(UC_ARM64_REG_X0,self.nt);u.reg_write(UC_ARM64_REG_PC,lr)

_,PATCHED,_=patch_image()
def main():
    assert hashlib.sha256(SOURCE.read_bytes()).hexdigest()==SOURCE_HASH
    fragment=(ROOT/'build/client-contract-fragment-OFFLINE.bin').read_bytes()
    assert fragment==PATCHED[0x8e38:0x9158]
    cases=0;failure_publications=0;counterexamples=0
    statuses=[(0,0),(0,4),(0xc0000001,0),(0xc0000185,4),(0x102,0),(0x103,0),(1,0)]
    for base,tracing,method,ready,busy,(nt,vendor) in itertools.product(
        [0x140000000,0x180000000,0x7ffb12340000],[False,True],
        ['read','write','set-role','set-power','transmit','command','get-status'],
        [0,1],[0,1,2],statuses):
        m=Client(nt,vendor,base=base,trace=tracing,ready=ready,busy=busy)
        value=0x99 if method=='command' else (0 if method=='transmit' else 0x4a)
        result=m.call(method,value)
        expected=0xc0000010 if busy else (0xc0000182 if not ready else
            (nt if nt&0x80000000 else (0xc0000185 if nt or vendor else 0)))
        assert result['status']==expected,(method,nt,vendor,result,hex(expected))
        assert result['lock']==busy,result
        if busy or not ready:assert not m.calls
        if method=='get-status':
            if expected:
                assert result['outputInformation'] is None,result
                assert len(m.calls)==(1 if ready and not busy else 0),result
                failure_publications+=1
            else:assert result['outputInformation']==3
        if ready and not busy and (nt or vendor):
            old=Client(nt,vendor,repaired=False,base=base,trace=tracing).call(method,value)
            assert not old['status']&0x80000000,old
            counterexamples+=1
        cases+=1
    seq=0
    for first,second,tracing in itertools.product(['read','write'],['read','write'],[False,True]):
        m=Client(0,0,ready=0,trace=tracing)
        assert m.call(first)['status']==0xc0000182
        m.uc.mem_write(legacy.CTX+0xf0,b'\x01')
        assert m.call(second)['status']==0
        seq+=1
    report=dict(cases=cases,original_error_counterexamples=counterexamples,
                failed_status_not_advertised_cases=failure_publications,
                not_ready_then_ready_sequences=seq,ASLR_bases=3,
                actual_original_callers=True,actual_repaired_ARM64_fragment=True,
                tested_fragment_sha256=hashlib.sha256(fragment).hexdigest(),
                SP_LR_X18_nonvolatile_preserved=True,hardware=False,
                kernel_unwind_execution=False,lifetime_rundown_implemented=False)
    (ROOT/'build/client-contract-verification.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report,indent=2))
if __name__=='__main__':main()
