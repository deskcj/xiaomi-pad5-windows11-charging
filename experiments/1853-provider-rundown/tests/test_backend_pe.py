"""Execute patched PE paths in Unicorn. All WDF/NT/device calls are mocks."""
import itertools,json,struct,sys,hashlib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'support/tests'))
from test_original_backend import Backend,CTX,TABLE,STUB,STACK
from unicorn.arm64_const import *
META=json.loads((ROOT/'build/backend-build.json').read_text())
SYMS=META['symbols']
fixtures={}
class Machine(Backend):
    def __init__(self,base=0x140000000,tracing=False):
        super().__init__(base=base,tracing=tracing)
        self.u.mem_write(base,( __import__('pefile').PE(str(ROOT/'build/qcpmictcc8150.sys'))).get_memory_mapped_image())
        self.qword(base+0x1a6d8,TABLE);self.qword(base+0x1a708,0x12345000)
        self.qword(base+0x1a0e0,CTX+0x8000 if tracing else base+0x1a0e0)
        self.qword(base+0x1a0d8,CTX+0x8100);self.qword(CTX+0x8140,0x55667700)
        self.u.mem_write(CTX+0x8148,b'\1\0')
        self.qword(base+0x1aa30,CTX+0x1000);self.u.mem_write(base+0x1aa40,b'\1')
        self.qword(base+0x1aa18,CTX+0x2000);self.u.mem_write(base+0x1a81c,b'\1')
        self.u.mem_write(base+0x1aa28,b'\1')
        self.qword(base+0x1a820,0)
        for d in self.pe.DIRECTORY_ENTRY_IMPORT:
            for imp in d.imports:
                nm=imp.name.decode() if imp.name else None
                if nm:
                    stub=next(a for a,n in self.stubs.items() if n==nm)
                    self.qword(base+imp.address-self.pe.OPTIONAL_HEADER.ImageBase,stub)
        self.qword(base+0x18160,next(a for a,n in self.stubs.items() if n=='guard'))
        for off,name in [(0x5d0,'ioctl'),(0xa00,'timer_stop')]:
            stub=STUB+0x1e000+off;self.stubs[stub]=name;self.qword(TABLE+off,stub)
        self.qword(base+META['external']['__imp_ZwWaitForSingleObject'],STUB+0x1f000)
        self.stubs[STUB+0x1f000]='join'
        self.voltage=0;self.adc_status=0;self.adc_vendor=0;self.adc_bytes=20
        self.resolve_status=0;self.resolve_vendor=0;self.resolve_bytes=8;self.channel=37
        self.pmic_status=0;self.pmic_vendor=0;self.pmic_bytes=4
        self.io=[];self.signals=[];self.held=set();self.inject=None;self.capture=False
        self.handler_errors={};self.handler_calls=[]
        self.call(SYMS['RepairInitialize'],args=[0,0,0,0,0,0,0,0])
    def hook(self,u,a,n,unused):
        r=a-self.base
        if self.capture and self.base==0x140000000 and (0x20000<=r<0x22000 or r in [0xa578,0xaf20,0x69d0,0x4ed0,0x107a8,0x100a0,0x1d050]):
            sp=u.reg_read(UC_ARM64_REG_SP);regs=[u.reg_read(UC_ARM64_REG_X0+i) for i in range(29)]
            regs += [u.reg_read(UC_ARM64_REG_FP),u.reg_read(UC_ARM64_REG_LR)]
            fixtures.setdefault((r,sp,tuple(regs[19:])),(r,sp-0x207000,regs,bytes(u.mem_read(0x207000,8192))))
        if r in [0x1c4f8,0x10c68]:self.ret();return
        if r==0xaf20:return # execute the patched power gate, not the old mock
        if r in [0x7618,0x7148,0x6ec8,0x64a0,0x6088,0x7388]:
            self.handler_calls.append(r);self.ret(self.handler_errors.get(r,0));return
        name=self.stubs.get(a)
        if name=='ioctl':
            args=[u.reg_read(UC_ARM64_REG_X0+i) for i in range(8)]
            def desc(at):
                typ,pad,buf,size=struct.unpack('<IIQQ',u.mem_read(at,24));assert typ==1 and pad==0
                return buf,size
            inp,ni=desc(args[4]);out,no=desc(args[5]);code=args[3]
            sz,flags,timeout=struct.unpack('<IIq',u.mem_read(args[6],16))
            assert sz>=16 and flags&1 and timeout==-10000000,(sz,flags,timeout)
            self.io.append(code)
            if code==0x8adc2000:
                assert ni==7 and no==8 and bytes(u.mem_read(inp,7))==b'USB_IN\0'
                u.mem_write(out,struct.pack('<II',self.resolve_vendor,self.channel));status=self.resolve_status;count=self.resolve_bytes
            elif code==0x8adc2004:
                assert ni==4 and no==20
                u.mem_write(out,struct.pack('<IIIII',self.adc_vendor,0,0,self.voltage,0));status=self.adc_status;count=self.adc_bytes
                if self.inject:
                    kind=self.inject;self.inject=None
                    if kind=='cancel':
                        epoch=self.base+SYMS['Epoch'];val=struct.unpack('<I',u.mem_read(epoch,4))[0]
                        u.mem_write(epoch,struct.pack('<I',val+1));u.mem_write(self.base+SYMS['Pending'],b'\0')
                    elif kind=='stop':u.mem_write(self.base+0x1a81c,b'\0')
            else:
                assert code in [0x801c0fa8,0x801c0fac] and ni==no==4
                assert self.base+SYMS['PowerGate'] in self.held
                value=struct.unpack('<I',u.mem_read(inp,4))[0]
                if code==0x801c0fac:self.events.append(dict(request='OTG',enable=value))
                u.mem_write(out,struct.pack('<I',self.pmic_vendor));status=self.pmic_status;count=self.pmic_bytes
            self.qword(args[7],count);self.ret(status);return
        if name=='KeInitializeEvent':
            obj=u.reg_read(UC_ARM64_REG_X0);u.mem_write(obj,bytes(24));self.ret();return
        if name=='KeWaitForMultipleObjects':
            assert u.reg_read(UC_ARM64_REG_X0)==1
            obj=struct.unpack('<Q',u.mem_read(u.reg_read(UC_ARM64_REG_X1),8))[0]
            assert obj not in self.held;self.held.add(obj);self.ret();return
        if name=='KeSetEvent':
            obj=u.reg_read(UC_ARM64_REG_X0)
            self.held.discard(obj);self.signals.append(obj);self.ret();return
        if name=='KeGetCurrentIrql':self.ret();return
        if name=='KeGetCurrentThread':self.ret(0x11223344);return
        if name=='timer_stop':self.events.append(dict(request='TIMER_STOP'));self.ret(1);return
        if name=='join':self.events.append(dict(request='JOIN'));self.ret();return
        if name=='ZwClose':self.events.append(dict(request='CLOSE'));self.ret();return
        if r==0xf178 and u.reg_read(UC_ARM64_REG_W1)==0x70:
            u.mem_write(CTX+0x80,bytes(u.mem_read(u.reg_read(UC_ARM64_REG_X3),2)));self.ret();return
        super().hook(u,a,n,unused)
    def command(self,cmd):return self.call(0x69d0,cmd)
    def dispatch(self):return self.call(SYMS['RepairDispatch'],args=[CTX])
    def otg(self):return [e['enable'] for e in self.events if e['request']=='OTG']
    def timer(self):return self.call(0x4ed0)

def main():
    rows=[]
    for base,wpp in itertools.product([0x140000000,0x180000000,0x7ffb12340000],[False,True]):
        for uv in [0,799999,800000,800001,5000000]:
            m=Machine(base,wpp);m.capture=True;m.voltage=uv
            assert m.command(0x77)==0 and not m.otg()
            m.dispatch();assert m.otg()==([1] if uv<=800000 else [])
            assert not m.held
            rows.append(dict(case='source threshold',base=hex(base),wpp=wpp,uv=uv,otg=m.otg()))
        for kind,values in [('adc_status',[0x103,0x102,0xc0000185]),('adc_vendor',[1,2,0xffffffff]),
                            ('adc_bytes',[0,4,19,21]),('resolve_status',[0x103,0x102,0xc0000185]),
                            ('resolve_vendor',[1]),('resolve_bytes',[0,4,7,9]),('channel',[0x20000,0xffffffff])]:
            for value in values:
                m=Machine(base,wpp);m.capture=True;setattr(m,kind,value);m.command(0x77);m.dispatch()
                assert m.otg()==[];assert not m.held
                out=CTX+0x1800;m.u.mem_write(out,struct.pack('<I',0xdeadbeef))
                assert m.call(0xa578,args=[CTX+0x1000,out])!=0
                assert struct.unpack('<I',m.u.mem_read(out,4))[0]==0xdeadbeef
                rows.append(dict(case=kind,value=hex(value),base=hex(base),wpp=wpp))
        m=Machine(base,wpp);m.capture=True;m.voltage=5000000
        m.command(0x77);m.dispatch();assert m.timer_armed
        m.command(0x66);m.dispatch();m.voltage=0;m.timer();m.dispatch()
        assert m.otg()==[0];assert not m.held
        rows.append(dict(case='77 high ->66 ->old timer',base=hex(base),wpp=wpp,otg=m.otg()))
        for cmd in [0x44,0x55]:
            m=Machine(base,wpp);m.capture=True;m.command(0x77);m.command(cmd);m.timer();m.dispatch()
            assert m.otg()==[0];assert not m.held
            rows.append(dict(case='source cancelled by sink',cmd=cmd,base=hex(base)))
        for injection in ['cancel','stop']:
            m=Machine(base,wpp);m.capture=True;m.inject=injection;m.command(0x77);m.dispatch()
            assert not m.otg();assert not m.held
            rows.append(dict(case='inflight ADC '+injection,base=hex(base),wpp=wpp))
        m=Machine(base,wpp);m.capture=True;m.adc_vendor=1;m.command(0x77)
        for i in range(10):m.dispatch();m.timer()
        assert m.otg()==[0];assert m.u.mem_read(base+SYMS['Pending'],1)==b'\0'
        rows.append(dict(case='bounded invalid ADC retries',base=hex(base),wpp=wpp))
        m=Machine(base,wpp);m.capture=True;m.qword(base+0x1a820,0x55556666)
        m.command(0x77);m.call(0x107a8,args=[CTX]);m.timer();m.dispatch()
        assert m.otg()==[0];assert [e['request'] for e in m.events][:3]==['JOIN','CLOSE','TIMER_STOP']
        assert m.u.mem_read(base+0x1a820,8)==bytes(8);assert not m.held
        rows.append(dict(case='stop drain',base=hex(base),wpp=wpp))
        for kind,values in [('pmic_status',[0x103,0x102,0xc0000185]),('pmic_vendor',[1,2]),('pmic_bytes',[0,3,5])]:
            for value in values:
                m=Machine(base,wpp);m.capture=True;setattr(m,kind,value);m.command(0x77);m.dispatch()
                assert 1 not in m.otg();assert not m.held
                rows.append(dict(case=kind,value=hex(value),base=hex(base),wpp=wpp))
        m=Machine(base,wpp);m.capture=True
        m.call(SYMS['RepairThreadIdentity']);assert m.call(0x107a8,args=[CTX])==0xc0000184
        assert m.u.mem_read(base+0x1a81c,1)==b'\1' and not m.held
        rows.append(dict(case='self join rejected',base=hex(base),wpp=wpp))
        for unavailable in [0x1aa28,0x1aa40]:
            m=Machine(base,wpp);m.capture=True;m.u.mem_write(base+unavailable,b'\0')
            m.u.mem_write(CTX+0x33,b'\x77');m.u.mem_write(CTX+0x210,struct.pack('<I',0x10))
            assert m.call(0x3550,args=[CTX,0x10])==0xc00000a3
            assert struct.unpack('<I',m.u.mem_read(CTX+0x210,4))[0]==0x10 and not m.io
            rows.append(dict(case='provider not ready propagated',field=unavailable,base=hex(base)))
        m=Machine(base,wpp);m.capture=True;m.adc_vendor=1
        m.u.mem_write(CTX+0x210,struct.pack('<I',0x100));m.u.mem_write(CTX+0x80,b'\xa5\x5a')
        assert m.call(0x3550,args=[CTX,0x100])==0xc0000185
        assert m.u.mem_read(CTX+0x80,2)==b'\xa5\x5a'
        assert struct.unpack('<I',m.u.mem_read(CTX+0x210,4))[0]==0x100
        m.adc_vendor=0;m.voltage=5000000
        assert m.call(0x3550,args=[CTX,0x100])==0
        assert struct.unpack('<H',m.u.mem_read(CTX+0x80,2))[0]==200
        rows.append(dict(case='ADC error not overwritten by ack, retry succeeds',base=hex(base)))
        m=Machine(base,wpp);m.capture=True;m.handler_errors[0x7148]=0xc0000185
        m.u.mem_write(CTX+0x210,struct.pack('<I',0x41))
        assert m.call(0x3550,args=[CTX,0x41])==0xc0000185
        assert struct.unpack('<I',m.u.mem_read(CTX+0x210,4))[0]==0x40
        rows.append(dict(case='first handler error preserved',base=hex(base)))
        m=Machine(base,wpp);m.capture=True;m.qword(base+0x1a820,0x12345678)
        m.command(0x66)
        assert m.call(SYMS['RepairResetBackend'],args=[CTX])==0
        assert m.otg()==[0] and m.u.mem_read(base+0x1aa28,1)==b'\0'
        n=len(m.io);assert m.call(0x107a8,args=[CTX])==0 and len(m.io)==n
        rows.append(dict(case='stop OFF before reset, later stop idempotent',base=hex(base)))
        m=Machine(base,wpp);m.capture=True;m.pmic_vendor=1
        assert m.call(SYMS['RepairResetBackend'],args=[CTX])==0xc0000185
        assert m.u.mem_read(base+0x1aa28,1)==b'\1'
        m.pmic_vendor=0;assert m.call(SYMS['RepairResetBackend'],args=[CTX])==0
        rows.append(dict(case='failed OFF does not reset target, retry succeeds',base=hex(base)))
    fixture_path=ROOT/'build/native-unwind-fixtures.bin'
    with fixture_path.open('wb') as f:
        f.write(struct.pack('<II',0x3157444e,len(fixtures)))
        for pc,sp,regs,mem in fixtures.values():f.write(struct.pack('<II31Q',pc,sp,*regs)+mem)
    report=dict(cases=len(rows),sha256=hashlib.sha256((ROOT/'build/qcpmictcc8150.sys').read_bytes()).hexdigest(),
                actualPatchedPE=True,fixtureCount=len(fixtures),nonvolatileAndSPChecked=True,
                hardwareAccess=False,kernelExecution=False,ddiMocks=True,multicoreKernelModelTested=False,results=rows)
    (ROOT/'build/backend-emulation.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k!='results'},indent=2))
if __name__=='__main__':main()
