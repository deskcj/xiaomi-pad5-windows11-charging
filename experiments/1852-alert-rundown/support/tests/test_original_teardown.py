"""Original 110D0 full teardown, including the previously untested owned body.
Only instructions run in Unicorn. Lifetime hazards are recorded at mocked
callback/target boundaries, not claimed as an observed Windows crash.
"""
from pathlib import Path
import hashlib, importlib.util, itertools, json, struct, sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,r'H:\Vlad\Charging\research\2026-10-26\tools\python-deps')
from unicorn.arm64_const import *
spec=importlib.util.spec_from_file_location('teardown_machine',ROOT/'reference/legacy_client_machine.py')
legacy=importlib.util.module_from_spec(spec);spec.loader.exec_module(legacy)

class Teardown(legacy.Machine):
    def __init__(self,busy,release_at,trace=False,base=0x140000000):
        super().__init__(ROOT/'reference/qcusbctcpm8150.sys',base=base,ready=1,busy=busy,trace=trace)
        self.initial_busy=busy;self.release_at=release_at
        self.stalls=0;self.events=[];self.acquire_owned=False
        self.secondary=legacy.CTX+0x3800
        self.qword(legacy.CTX+8,0x77770000)
        self.qword(legacy.CTX+0x18,0x88880000)
        self.qword(legacy.CTX+0x28,legacy.STUB+0x900)
        self.qword(legacy.CTX+0x148,0x99990000)
        self.qword(self.secondary+0x28,0)
        for slot,stub in [(0x570,0xa00),(0x9c8,0xb00),(0x9d0,0xc00),
                           (0x550,0xd00),(0x680,0xe00),(0x548,0xf00)]:
            self.qword(legacy.TABLE+slot,legacy.STUB+stub)
        self.qword(base+0xb000,legacy.STUB+0x980) # KeStallExecutionProcessor
        if trace:self.uc.mem_write(legacy.TRACE+0x148,struct.pack('<H',1))
    def busy(self):return struct.unpack('<I',self.uc.mem_read(legacy.CTX+0x118,4))[0]
    def hook(self,u,a,n,unused):
        lr=u.reg_read(UC_ARM64_REG_LR)
        value=0;handled=True
        if a==legacy.STUB:
            key=u.reg_read(UC_ARM64_REG_X2)
            device_key=struct.unpack('<Q',u.mem_read(self.base+0xc128,8))[0]
            value=legacy.CTX if key==device_key else self.secondary
        elif a==legacy.STUB+0xa00:value=0x10101010
        elif a==legacy.STUB+0xb00:
            self.acquire_owned=True
            self.events.append(dict(operation='waitlock-acquire',owned=True))
        elif a==legacy.STUB+0xc00:
            self.events.append(dict(operation='waitlock-release',owned=self.acquire_owned))
            self.acquire_owned=False
        elif a==legacy.STUB+0x980:
            self.stalls+=1
            if self.release_at==self.stalls:u.mem_write(legacy.CTX+0x118,bytes(4))
        elif a in [legacy.STUB+0x900,legacy.STUB+0xd00,legacy.STUB+0xe00]:
            self.events.append(dict(operation={0x900:'backend-close',0xd00:'target-close',
                                              0xe00:'target-dereference'}[a-legacy.STUB],
                                    transport_owner=self.busy(),stalls=self.stalls))
        elif a==legacy.STUB+0xf00:self.events.append(dict(operation='workitem-delete'))
        else:handled=False
        if not handled:return super().hook(u,a,n,unused)
        assert u.reg_read(UC_ARM64_REG_SP)%16==0
        for r in range(UC_ARM64_REG_X0,UC_ARM64_REG_X17+1):u.reg_write(r,0xcccccccccccccccc)
        u.reg_write(UC_ARM64_REG_X0,value);u.reg_write(UC_ARM64_REG_PC,lr)
    def run(self):
        u=self.uc
        for r,value in legacy.nv.items():u.reg_write(r,value)
        u.reg_write(UC_ARM64_REG_SP,legacy.STACK+0x8000)
        u.reg_write(UC_ARM64_REG_LR,legacy.STOP)
        u.reg_write(UC_ARM64_REG_X0,0x20202020)
        u.emu_start(self.base+0x110d0,legacy.STOP,count=100000)
        assert u.reg_read(UC_ARM64_REG_PC)==legacy.STOP
        assert u.reg_read(UC_ARM64_REG_SP)==legacy.STACK+0x8000
        assert all(u.reg_read(r)==v for r,v in legacy.nv.items())
        closed=[e for e in self.events if e['operation']=='backend-close']
        assert len(closed)==1
        assert self.busy()==0 and u.mem_read(legacy.CTX+0xf0,1)==b'\0'
        return dict(initial_busy=self.initial_busy,foreign_release_at=self.release_at,
                    stalls=self.stalls,events=self.events,
                    teardown_owned_transport=closed[0]['transport_owner']==3,
                    final_busy=self.busy(),SP_LR_X18_nonvolatile_preserved=True)

def main():
    source=ROOT/'reference/qcusbctcpm8150.sys'
    assert hashlib.sha256(source.read_bytes()).hexdigest()=='7c63f4a4b8a9ee0f49b427b6ac94867d2475e02f85d92d5fbcfe4a8aa1804067'
    results=[]
    for base,tracing,busy,release in itertools.product(
        [0x140000000,0x180000000,0x7ffb12340000],[False,True],[0,1,2],[1,99,100,None]):
        m=Teardown(busy,release,trace=tracing,base=base)
        r=m.run()
        expected=busy==0 or release in [1,99]
        assert r['teardown_owned_transport']==expected,r
        r.update(base=hex(base),trace=tracing);results.append(r)
    report=dict(cases=len(results),
                teardown_without_transport_ownership=sum(not r['teardown_owned_transport'] for r in results),
                full_original_teardown_executed=True,
                previous_safetyfix3_only_corrects_outer_waitlock=True,
                actual_crash_on_tablet_proven=False,hardware=False,results=results)
    (ROOT/'build/original-teardown-counterexamples.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k!='results'},indent=2))
if __name__=='__main__':main()
