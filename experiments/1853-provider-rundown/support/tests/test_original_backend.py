"""Execute pinned original ARM64 instructions only in Unicorn.

AF20 is an intercepted boundary: no real IOCTL, PMIC, or kernel call executes.
The trace records REQUESTED OTG writes, not an electrical result.
"""
from pathlib import Path
import hashlib, itertools, json, struct, sys
sys.path.insert(0, r'H:\Vlad\Charging\research\2026-10-26\tools\python-deps')
import pefile
from unicorn import Uc, UcError, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm64_const import *

ROOT = Path(__file__).resolve().parents[1]
CTX, TABLE, STACK, STUB, STOP = 0x40000000, 0x40010000, 0x200000, 0x50000000, 0x60000000
NV = {r: 0xabc0000000000000+i for i,r in enumerate(range(UC_ARM64_REG_X19, UC_ARM64_REG_X28+1))}
NV[UC_ARM64_REG_FP] = 0xabc1234567890000
NV[UC_ARM64_REG_X18] = 0x1818181818181818

class Backend:
    def __init__(self, base=0x140000000, measure_error=0, copy_error=False, context_valid=True, tracing=False):
        binary = ROOT/'reference/qcpmictcc8150.sys'
        assert hashlib.sha256(binary.read_bytes()).hexdigest() == 'be9850ce5ab8a9e5ead615de592ff8177154bde9496320910210dc503b2b46e9'
        self.pe = pefile.PE(str(binary)); self.base=base
        self.measure_error=measure_error; self.copy_error=copy_error
        self.context_valid=context_valid; self.events=[]; self.timer_armed=False
        self.provider_error=0xc0000001
        self.stubs={}; self.trace_enabled=tracing
        self.u=Uc(UC_ARCH_ARM64, UC_MODE_ARM); u=self.u
        for addr, size in [(base,0x30000),(CTX,0x20000),(STACK,0x10000),(STUB,0x20000),(STOP,0x1000)]:u.mem_map(addr,size)
        u.mem_write(base,self.pe.get_memory_mapped_image())
        self.qword(base+0x1a6d8,TABLE); self.qword(base+0x1a708,0x12345000)
        trace=CTX+0x8000
        self.qword(base+0x1a0e0,trace if tracing else base+0x1a0e0)
        self.qword(base+0x1a0d8,trace+0x100)
        self.qword(trace+0x140,0x55667700)
        u.mem_write(trace+0x148,b'\x01\x00')
        self.qword(CTX+0x218,0x11112222); self.qword(CTX+0x230,0x33334444)
        self.qword(base+0x1a910,CTX)
        u.mem_write(base+0x1a81c,b'\x01')
        for offset, name in [(0xa08,'parent'),(0x650,'context'),(0x9e0,'lock'),(0x9e8,'unlock'),(0x9f8,'timer_start')]:
            addr=STUB+len(self.stubs)*0x100;self.stubs[addr]=name;self.qword(TABLE+offset,addr)
        guard=STUB+len(self.stubs)*0x100;self.stubs[guard]='guard';self.qword(base+0x18160,guard)
        for dll in self.pe.DIRECTORY_ENTRY_IMPORT:
            for imp in dll.imports:
                addr=STUB+len(self.stubs)*0x100
                self.stubs[addr]=imp.name.decode() if imp.name else f'ordinal{imp.ordinal}'
                self.qword(base+imp.address-self.pe.OPTIONAL_HEADER.ImageBase,addr)
        self.u.hook_add(UC_HOOK_CODE,self.hook)

    def qword(self,addr,value):self.u.mem_write(addr,struct.pack('<Q',value))
    def ret(self,value=0,preserve=False):
        u=self.u;lr=u.reg_read(UC_ARM64_REG_LR)
        if not preserve:
            for r in range(UC_ARM64_REG_X0,UC_ARM64_REG_X17+1):u.reg_write(r,0xcccccccccccccccc)
        u.reg_write(UC_ARM64_REG_X0,value & 0xffffffffffffffff)
        u.reg_write(UC_ARM64_REG_PC,lr)
    def hook(self,u,addr,size,unused):
        rva=addr-self.base
        if rva==0xdb80:self.ret();return
        if rva in [0xe8b0,0xeb68]:self.ret(self.provider_error);return
        if rva==0xaf20:
            self.events.append({'request':'OTG','enable':u.reg_read(UC_ARM64_REG_W2),
                                'driver_active':u.mem_read(self.base+0x1a81c,1)[0],
                                'last_source_state':struct.unpack('<I',u.mem_read(CTX+0x2ec,4))[0]})
            self.ret();return
        if rva==0x1b28:
            if not self.measure_error:u.mem_write(CTX+0x80,struct.pack('<H',40))
            self.ret(self.measure_error);return
        if rva==0xf178:
            assert u.reg_read(UC_ARM64_REG_W1)==0x23
            length=u.reg_read(UC_ARM64_REG_W2);buf=u.reg_read(UC_ARM64_REG_X3)
            u.mem_write(CTX+0x33,bytes(u.mem_read(buf,length)))
            self.ret();return
        if rva in [0x15b0,0x1698,0x9f70]:self.ret();return
        if addr not in self.stubs:return
        name=self.stubs[addr]
        assert u.reg_read(UC_ARM64_REG_SP)%16==0
        if name=='guard':
            u.reg_write(UC_ARM64_REG_PC,u.reg_read(UC_ARM64_REG_LR));return
        if name=='parent':self.ret(0x22223333)
        elif name=='context':self.ret(CTX if self.context_valid else 0)
        elif name in ['lock','unlock']:self.ret()
        elif name=='timer_start':
            self.timer_armed=True;self.events.append({'request':'TIMER_START'});self.ret(1)
        elif name=='memcpy_s':
            dest,capacity,source,count=[u.reg_read(UC_ARM64_REG_X0+i) for i in range(4)]
            if self.copy_error and capacity==2:self.ret(22)
            else:
                assert count<=capacity and count<=16
                u.mem_write(dest,bytes(u.mem_read(source,count)));self.ret()
        elif name=='KeSetEvent':self.ret()
        else:raise AssertionError(f'Unexpected original call {name} at {addr:x}')

    def call(self,rva,command=None,args=None):
        u=self.u
        if command is not None:u.mem_write(CTX+0x33,bytes([command]))
        for reg,value in NV.items():u.reg_write(reg,value)
        u.reg_write(UC_ARM64_REG_SP,STACK+0x8000);u.reg_write(UC_ARM64_REG_LR,STOP)
        u.reg_write(UC_ARM64_REG_X0,CTX if rva==0x69d0 else 0x99990000)
        if args is not None:
            for index,value in enumerate(args):u.reg_write(UC_ARM64_REG_X0+index,value)
        u.emu_start(self.base+rva,STOP,count=30000)
        assert u.reg_read(UC_ARM64_REG_PC)==STOP
        assert u.reg_read(UC_ARM64_REG_SP)==STACK+0x8000
        assert all(u.reg_read(reg)==value for reg,value in NV.items())
        return u.reg_read(UC_ARM64_REG_W0)

def main():
    results=[]
    for base,tracing in itertools.product([0x140000000,0x180000000,0x7ffb12340000],[False,True]):
        m=Backend(base=base,tracing=tracing)
        m.call(0x69d0,0x77);assert m.timer_armed
        m.call(0x69d0,0x66);assert m.timer_armed
        assert m.events[-1]['enable']==0
        m.call(0x4ed0)
        assert m.events[-1]['enable']==1
        results.append({'case':'77 ->66 ->old timer','base':hex(base),'tracing':tracing,'events':m.events})
    for measure_error,copy_error,active in [(0xc0000001,False,True),(0,True,True),(0,False,False)]:
        m=Backend(measure_error=measure_error,copy_error=copy_error)
        if not active:m.u.mem_write(m.base+0x1a81c,b'\0')
        m.call(0x4ed0);assert m.events[-1]['enable']==1
        results.append({'case':'timer-error-or-stopping','measurement_error':hex(measure_error),
                        'copy_error':copy_error,'driver_active':active,'events':m.events})
    for command in [0x44,0x55]:
        m=Backend();m.call(0x69d0,command)
        assert not m.events and m.u.mem_read(CTX+0x33,1)==b'\0'
        results.append({'case':'Sink command acknowledged without physical operation','command':hex(command),'events':m.events})
    for error,copy_error,tracing in [(0xc0000001,False,False),(0,True,False),(0,True,True)]:
        m=Backend(measure_error=error,copy_error=copy_error,tracing=tracing)
        m.call(0x69d0,0x77)
        assert m.events[-1]['enable']==1
        results.append({'case':'failed VBUS read/copy treated as zero by77',
                        'measurement_error':hex(error),'copy_error':copy_error,'tracing':tracing,'events':m.events})
    for entry in [0xdf20,0xde30]:
        m=Backend();vendor=CTX+0x780;buffer=CTX+0x700
        m.u.mem_write(vendor,b'\xa5'*4)
        status=m.call(entry,args=[0x1a,1,buffer,vendor])
        out=struct.unpack('<I',m.u.mem_read(vendor,4))[0]
        assert status==0xc0000001 and out==0
        results.append({'case':'real dual-status wrapper','entry':hex(entry),'ntstatus':hex(status),'vendor_status':out})
    m=Backend(context_valid=False)
    try:m.call(0x4ed0)
    except UcError:
        assert m.events[-1]['enable']==1
        results.append({'case':'null context','requested_otg_before_unmapped_dereference':True,'events':m.events})
    else:raise AssertionError('Expected invalid emulated context access')
    report={'cases':len(results),'actual_original_code_executed_in_emulator':True,
            'SP_LR_and_nonvolatile_checked_on_return':True,'real_kernel_calls':False,
            'hardware_tested':False,'causal_path_of_tablet_failure_proven':False,'results':results}
    (ROOT/'build/original-backend-counterexamples.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k!='results'},indent=2))
if __name__=='__main__':main()
