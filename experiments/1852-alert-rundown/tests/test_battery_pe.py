"""Actual 17EE8 path, original vs patched stale-cache replay; devices mocked."""
import hashlib,itertools,json,struct,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'support/tests'))
from test_original_backend import Backend,CTX,TABLE,STUB
from unicorn.arm64_const import *
import pefile
class Battery(Backend):
    def __init__(self,patched=True,base=0x140000000,state=2,status=0,vendor=0,count=4):
        super().__init__(base=base)
        self.u.mem_write(base,pefile.PE(str(ROOT/('build' if patched else 'reference')/'qcbattmngr8150.sys')).get_memory_mapped_image())
        self.qword(base+0x28958,TABLE);self.qword(base+0x28988,0x12345000)
        self.qword(base+0x28168,CTX+0x6000);self.qword(base+0x286b0,CTX+0x7000)
        self.qword(CTX+0x7000,CTX+0x2000);self.u.mem_write(CTX+0x7190,struct.pack('<I',2))
        self.qword(base+0x26110,next(a for a,n in self.stubs.items() if n=='guard'))
        self.u.mem_write(CTX+0xa88,struct.pack('<I',state));self.u.mem_write(CTX+0xc24,struct.pack('<I',1))
        self.u.mem_write(base+0x2911b,b'\1');self.u.mem_write(base+0x29121,b'\0');self.u.mem_write(base+0x2911a,b'\0')
        self.u.mem_write(base+0x29123,b'\0');self.u.mem_write(base+0x29107,b'\1')
        self.status=status;self.vendor=vendor;self.count=count;self.policy=[];self.physical=[1,1]
        self.stubs[STUB+0x1f000]='battery_send';self.qword(TABLE+0x5d0,STUB+0x1f000)
    def hook(self,u,a,n,unused):
        r=a-self.base
        if r==0x21a28:self.ret();return
        if self.stubs.get(a)=='battery_send':
            args=[u.reg_read(UC_ARM64_REG_X0+i) for i in range(8)]
            def desc(p):
                kind,pad,buf,size=struct.unpack('<IIQQ',u.mem_read(p,24));assert kind==1 and pad==0
                return buf,size
            inp,ni=desc(args[4]);out,no=desc(args[5]);assert args[3]==0x801b0fe4 and ni==8 and no==4
            index,usb,dc=struct.unpack('<IBB',u.mem_read(inp,6));assert index==1
            self.policy.append([usb,dc]);u.mem_write(out,struct.pack('<I',self.vendor));self.qword(args[7],self.count)
            if self.status==self.vendor==0 and self.count==4:self.physical=[usb,dc]
            self.ret(self.status);return
        if r in [0x18e0,0x19a8,0x1940]:self.ret();return
        return super().hook(u,a,n,unused)
    def run(self):return self.call(0x17ee8,args=[CTX])
def main():
    rows=[]
    for base,state in itertools.product([0x140000000,0x180000000,0x7ffb12340000],[1,2,3,4,5,7,9]):
        m=Battery(base=base,state=state);s=m.run()
        desired=[0,1] if state==1 else ([1,1] if state==9 else [0,0])
        assert s==0 and m.policy==[desired] and m.physical==desired
        old=Battery(False,base,state);old.run()
        if desired==[0,0]:assert old.policy==[] and old.physical==[1,1]
        rows.append(dict(case='stale replay',base=hex(base),state=state,desired=desired))
    for base,status,vendor,count in itertools.product(
        [0x140000000,0x180000000,0x7ffb12340000],[0,0x103,0x102,0xc0000185],[0,1],[0,4,8]):
        m=Battery(base=base,status=status,vendor=vendor,count=count);s=m.run()
        success=status==vendor==0 and count==4
        assert (s==0)==success,(hex(status),vendor,count,hex(s))
        assert m.physical==([0,0] if success else [1,1])
        rows.append(dict(case='contract',base=hex(base),ntstatus=hex(status),vendor=vendor,count=count))
    report=dict(cases=len(rows),actualPatchedPE=True,actualOriginalCounterexample=True,
                sha256=hashlib.sha256((ROOT/'build/qcbattmngr8150.sys').read_bytes()).hexdigest(),
                batteryPolicyPreserved=True,hardwareAccess=False,kernelExecution=False,ddiMocks=True,results=rows)
    (ROOT/'build/battery-emulation.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k!='results'},indent=2))
if __name__=='__main__':main()
