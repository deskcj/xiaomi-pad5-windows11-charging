"""Patched whole PE: dual-status callers and complete original cleanup body."""
from pathlib import Path
import hashlib,importlib.util,itertools,json,struct,sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'support/tests'))
from test_client_contract_repair import Client,legacy
from test_original_teardown import Teardown
from unicorn.arm64_const import *
import pefile
PATH=ROOT/'build/qcusbctcpm8150.sys'
MAPPED=pefile.PE(str(PATH)).get_memory_mapped_image()
fixtures={}
def capture(m,u,a):
    r=a-m.base
    if m.base!=0x140000000:return
    if not (0x8e38<=r<0x9158 or 0x110d0<=r<0x11450 or 0x12da0<=r<0x133d4 or 0x17000<=r<0x18000):return
    if hasattr(m,'stalls') and m.stalls>=2 and (0x11250<=r<0x1128c or 0x12fc8<=r<0x13004 or 0x17000<=r<0x18000):return
    regs=[u.reg_read(UC_ARM64_REG_X0+i) for i in range(29)]+[u.reg_read(UC_ARM64_REG_FP),u.reg_read(UC_ARM64_REG_LR)]
    sp=u.reg_read(UC_ARM64_REG_SP)
    key=(r,sp,tuple(regs[19:]))
    if key not in fixtures:fixtures[key]=(r,sp-0x207000,regs,bytes(u.mem_read(0x207000,8192)))
class Calls(Client):
    def __init__(self,nt,vendor,stopping=0,**kwargs):
        super().__init__(nt,vendor,**kwargs)
        self.uc.mem_write(self.base,MAPPED)
        # Restore only the test's WDF and WPP globals, never the code fragment.
        self.qword(self.base+0xc498,legacy.TABLE);self.qword(self.base+0xc4c8,0x12345000)
        self.qword(self.base+0xb110,legacy.STUB+0x100)
        self.qword(self.base+0xc108,legacy.TRACE if kwargs.get('trace') else self.base+0xc108)
        self.qword(self.base+0xc100,legacy.TRACE+0x100)
        self.uc.mem_write(legacy.CTX+0xf1,bytes([stopping]))

class Drain(Teardown):
    def __init__(self,busy,release_at,**kwargs):
        super().__init__(busy,release_at,**kwargs)
        self.uc.mem_write(self.base,MAPPED)
        self.qword(self.base+0xc498,legacy.TABLE);self.qword(self.base+0xc4c8,0x12345000)
        self.qword(self.base+0xb110,legacy.STUB+0x100)
        self.qword(self.base+0xc108,legacy.TRACE if kwargs.get('trace') else self.base+0xc108)
        self.qword(self.base+0xc100,legacy.TRACE+0x100)
        self.qword(self.base+0xb0c0,legacy.STUB+0x990)
    def hook(self,u,a,n,unused):
        capture(self,u,a)
        if a==legacy.STUB+0x990:
            assert u.reg_read(UC_ARM64_REG_X0)==0 and u.reg_read(UC_ARM64_REG_X1)==0
            assert struct.unpack('<q',u.mem_read(u.reg_read(UC_ARM64_REG_X2),8))[0]==-10000
            self.stalls+=1
            if self.release_at==self.stalls:u.mem_write(legacy.CTX+0x118,bytes(4))
            self.events.append(dict(operation='yield',foreignOwner=self.busy()))
            lr=u.reg_read(UC_ARM64_REG_LR)
            for r in range(UC_ARM64_REG_X0,UC_ARM64_REG_X17+1):u.reg_write(r,0xcccccccccccccccc)
            u.reg_write(UC_ARM64_REG_X0,0);u.reg_write(UC_ARM64_REG_PC,lr);return
        return super().hook(u,a,n,unused)

class D0(Drain):
    def __init__(self,busy,release_at,locks=(0,0),**kwargs):
        super().__init__(busy,release_at,**kwargs)
        self.uc.mem_map(legacy.STUB+0x1000,0x1000)
        self.qword(legacy.TABLE+0x520,legacy.STUB+0x1100)
        self.qword(self.secondary+0x10,0x12121212)
        self.qword(legacy.CTX+0x80,0);self.qword(legacy.CTX+0x178,0x17817817);self.qword(legacy.CTX+0x150,0x15015015)
        self.locks=locks;self.lock_owned=set();self.releases=[]
    def hook(self,u,a,n,unused):
        if a in [legacy.STUB+0xb00,legacy.STUB+0xc00,legacy.STUB+0x1100]:
            handle=u.reg_read(UC_ARM64_REG_X1);value=0
            if a==legacy.STUB+0xb00:
                assert struct.unpack('<q',u.mem_read(u.reg_read(UC_ARM64_REG_X2),8))[0]==-300000000
                value=self.locks[0 if handle==0x17817817 else 1]
                if value==0:self.lock_owned.add(handle)
            elif a==legacy.STUB+0xc00:
                assert handle in self.lock_owned,('Foreign wait-lock release',hex(handle),self.locks)
                self.lock_owned.remove(handle);self.releases.append(handle)
            else:
                assert self.uc.mem_read(legacy.CTX+0xf1,1)==b'\1','Flush admitted new I/O'
                self.events.append(dict(operation='flush',stopping=True))
            lr=u.reg_read(UC_ARM64_REG_LR)
            for r in range(UC_ARM64_REG_X0,UC_ARM64_REG_X17+1):u.reg_write(r,0xcccccccccccccccc)
            u.reg_write(UC_ARM64_REG_X0,value);u.reg_write(UC_ARM64_REG_PC,lr);return
        return super().hook(u,a,n,unused)
    def run_d0(self,reason):
        u=self.uc
        for r,v in legacy.nv.items():u.reg_write(r,v)
        u.reg_write(UC_ARM64_REG_SP,legacy.STACK+0x8000);u.reg_write(UC_ARM64_REG_LR,legacy.STOP)
        u.reg_write(UC_ARM64_REG_X0,0x20202020);u.reg_write(UC_ARM64_REG_X1,reason)
        u.emu_start(self.base+0x12da0,legacy.STOP,count=100000)
        assert u.reg_read(UC_ARM64_REG_PC)==legacy.STOP
        assert u.reg_read(UC_ARM64_REG_SP)==legacy.STACK+0x8000
        assert all(u.reg_read(r)==v for r,v in legacy.nv.items())
        assert not self.lock_owned
        assert any(e['operation']=='flush' for e in self.events)
        closed=[e for e in self.events if e['operation']=='backend-close']
        assert len(closed)==1 and closed[0]['transport_owner']==3
        return u.reg_read(UC_ARM64_REG_W0)

def main():
    cases=0;drains=[];d0_rows=[]
    statuses=[(0,0),(0,1),(0,4),(0xc0000001,0),(0xc0000185,4),(0x102,0),(0x103,0)]
    for base,wpp,method,ready,busy,stopping,(nt,vendor) in itertools.product(
        [0x140000000,0x180000000,0x7ffb12340000],[False,True],
        ['read','write','set-role','set-power','transmit','command','get-status'],
        [0,1],[0,1,2], [0,1],statuses):
        m=Calls(nt,vendor,base=base,trace=wpp,ready=ready,busy=busy,stopping=stopping)
        value=0x99 if method=='command' else (0 if method=='transmit' else 0x4a)
        result=m.call(method,value)
        expected=0xc0000010 if busy else (0xc0000182 if not ready or stopping else
                    (nt if nt&0x80000000 else (0xc0000185 if nt or vendor else 0)))
        assert result['status']==expected,(method,result,hex(expected))
        assert result['lock']==busy
        if busy or not ready or stopping:assert not m.calls
        if method=='get-status' and expected:assert result['outputInformation'] is None
        cases+=1
    for base,wpp,busy,release in itertools.product(
        [0x140000000,0x180000000,0x7ffb12340000],[False,True],[0,1,2],[1,99,100,150,1000]):
        m=Drain(busy,release,base=base,trace=wpp);row=m.run()
        assert row['teardown_owned_transport'];assert all(e.get('transport_owner',3)==3 for e in row['events'] if e['operation'] in ['backend-close','target-close','target-dereference'])
        drains.append(dict(base=hex(base),wpp=wpp,busy=busy,release=release,yields=m.stalls))
    # Permanent foreign owner: execute a bounded *test* instruction budget.
    # Production remains in a sleeping ownership drain and closes nothing.
    m=Drain(1,None);u=m.uc
    for r,v in legacy.nv.items():u.reg_write(r,v)
    u.reg_write(UC_ARM64_REG_SP,legacy.STACK+0x8000);u.reg_write(UC_ARM64_REG_LR,legacy.STOP);u.reg_write(UC_ARM64_REG_X0,0x20202020)
    u.emu_start(m.base+0x110d0,legacy.STOP,count=20000)
    assert u.reg_read(UC_ARM64_REG_PC)!=legacy.STOP
    assert m.busy()==1 and not any(e['operation'] in ['backend-close','target-close','target-dereference'] for e in m.events)
    for base,busy,release,reason,locks in itertools.product(
        [0x140000000,0x180000000,0x7ffb12340000],[0,1,2],[1,100,150],[4,5],
        [(0,0),(0x102,0),(0,0x102),(0xc0000001,0),(0,0xc0000001)]):
        m=D0(busy,release,base=base,locks=locks);status=m.run_d0(reason)
        assert len(m.releases)==sum(s==0 for s in locks)
        d0_rows.append(dict(base=hex(base),busy=busy,release=release,reason=reason,locks=locks,status=hex(status)))
    with (ROOT/'build/client-unwind-fixtures.bin').open('wb') as f:
        f.write(struct.pack('<II',0x3157444e,len(fixtures)))
        for pc,sp,regs,mem in fixtures.values():f.write(struct.pack('<II31Q',pc,sp,*regs)+mem)
    report=dict(cases=cases,fullCleanupCases=len(drains),permanentOwnerProtected=True,
                sha256=hashlib.sha256(PATH.read_bytes()).hexdigest(),actualPatchedPE=True,
                nativeYieldExecuted=True,SPAndNonvolatileChecked=True,hardwareAccess=False,kernelExecution=False,
                ddiMocks=True,fullD0ExitCases=len(d0_rows),nativeFlushExecuted=True,
                fixtureCount=len(fixtures),drains=drains,d0=d0_rows)
    (ROOT/'build/client-emulation.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k not in ['drains','d0']},indent=2))
if __name__=='__main__':main()
