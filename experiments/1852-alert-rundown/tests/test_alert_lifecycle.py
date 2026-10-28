"""Execute the final ARM64 PE, not a Python copy of its state machine.

DDIs are mocks; scheduled interleavings are not a physical SMP/kernel test.
Both call-site adapters and actual1851 backend E108 are exercised.
"""
import hashlib,itertools,json,struct,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,r'H:\Vlad\Charging\research\2026-10-26\tools\python-deps')
import pefile
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn.arm64_const import *

PATH=ROOT/'build/qcusbctcpm8150.sys'
META=json.loads((ROOT/'build/client-build.json').read_text())
SYM=META['symbols']
BACKEND=Path(r'H:\Vlad\Charging\candidate-1851-stock-repair\package\qcpmictcc8150.sys').read_bytes()
assert hashlib.sha256(BACKEND).hexdigest()=='7cc45346517c7dbe65ca0fbe68ee8d2f38cfc2168e2e6a038182998a4aae9737'
A=0x60000000;S=0x200000;F=0x400000;END=F+0xff0;B=0x160000000
DEVICE=A+0x2000;CONTEXT=A+0x5000;CONTROLLER=A+0x6000;ALERTS=A+0x7000
NV={UC_ARM64_REG_X19+i:0xabc0000000000000+i for i in range(10)}
NV.update({UC_ARM64_REG_FP:0xabc1234567890000,UC_ARM64_REG_X18:0x18181818})
fixtures={}

class Machine:
    def __init__(self,base=0x140000000,context=True,controller=True):
        self.base=base;self.context=context;self.controller=controller
        self.events=[];self.start_status=0;self.entry_status=0;self.exit_status=0
        self.on_start=None;self.on_delay=None;self.lookup_action=None;self.on_alert=None
        self.u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u=self.u
        self.pe=pefile.PE(str(PATH))
        for address,size in [(base,0x30000),(B,0x30000),(A,0x10000),(S,0x10000),(F,0x1000)]:u.mem_map(address,size)
        u.mem_write(base,self.pe.get_memory_mapped_image())
        u.mem_write(B,pefile.PE(data=BACKEND).get_memory_mapped_image())
        self.q(base+0xc498,A+0x4000);self.q(base+0xc4c8,A+0x3000)
        self.q(A+0x4650,F+0x10);self.q(base+0xc270,F+0x20);self.q(base+0xc278,A+0x3100)
        self.q(CONTEXT+0x80,CONTROLLER if controller else 0)
        self.q(base+0xb110,F);self.q(base+0xc108,base+0xc108)
        self.q(B+0x18160,F);self.q(B+0x1a0e0,B+0x1a0e0)
        self.q(B+0x1a910,A+0x1000);u.mem_write(A+0x1310,b'\1\0')
        u.mem_write(B+0x1a818,b'\1');self.q(B+0x1a808,base+0x89e0);self.q(B+0x1a810,DEVICE)
        for desc in self.pe.DIRECTORY_ENTRY_IMPORT:
            for imp in desc.imports:
                if imp.name==b'KeDelayExecutionThread':self.q(base+imp.address-self.pe.OPTIONAL_HEADER.ImageBase,F+0x50)
        self.adapters={a['name']:a['rva'] for a in META['adapters']}
        u.hook_add(UC_HOOK_CODE,self.hook)
    def q(self,address,value):self.u.mem_write(address,struct.pack('<Q',value))
    def get(self,sym):return struct.unpack('<Q',self.u.mem_read(self.base+SYM[sym],8))[0]
    def put(self,sym,value,width=8):self.u.mem_write(self.base+SYM[sym],int(value).to_bytes(width,'little'))
    def reg(self,i):return self.u.reg_read(UC_ARM64_REG_X0+i)
    def ret(self,value=0):
        u=self.u;lr=u.reg_read(UC_ARM64_REG_LR)
        for i in range(18):u.reg_write(UC_ARM64_REG_X0+i,0xcccccccccccccccc)
        u.reg_write(UC_ARM64_REG_X0,value);u.reg_write(UC_ARM64_REG_PC,lr)
    def hook(self,u,address,size,_):
        r=address-self.base
        if self.base==0x140000000 and getattr(self,'capture_enabled',True) and 0x17000<=r<0x18000:
            regs=[self.reg(i) for i in range(29)]+[u.reg_read(UC_ARM64_REG_FP),u.reg_read(UC_ARM64_REG_LR)]
            sp=u.reg_read(UC_ARM64_REG_SP)
            expected=[self.expected[UC_ARM64_REG_X19+i] for i in range(10)]+[self.expected[UC_ARM64_REG_FP],self.expected[UC_ARM64_REG_X18]]
            key=(r,sp,tuple(regs[19:]),tuple(expected))
            if key not in fixtures:fixtures[key]=(r,sp-0x207000,regs,bytes(u.mem_read(0x207000,8192)),expected)
        if address==F:u.reg_write(UC_ARM64_REG_PC,u.reg_read(UC_ARM64_REG_LR));return
        if address==F+0x10:
            assert self.reg(0)==A+0x3000 and self.reg(1)==DEVICE
            self.events.append('lookup')
            if self.lookup_action:self.lookup_action(self)
            self.ret(CONTEXT if self.context else 0)
        elif address==F+0x20:
            assert self.reg(0)==A+0x3100 and self.reg(1)==CONTROLLER
            assert self.reg(2)==ALERTS and 1<=self.reg(3)<=12
            assert self.get('AlertState')&~1>=2
            assert self.get('LifeLock')&0xffffffff==0,'Class alert held lifecycle lock'
            self.events.append('alert')
            if self.on_alert:self.on_alert(self)
            self.ret()
        elif address==F+0x30:
            assert self.reg(0)==A+0x3100 and self.reg(1)==CONTROLLER
            self.events.append('start')
            if self.on_start:self.on_start(self)
            self.ret(self.start_status)
        elif address==F+0x40:
            assert self.get('AlertState')==1 and self.get('LiveDevice')==0
            assert self.reg(0)==A+0x3100 and self.reg(1)==CONTROLLER
            self.events.append('stop');self.ret()
        elif address==F+0x50:
            assert self.reg(0)==0 and self.reg(1)==0
            assert struct.unpack('<q',u.mem_read(self.reg(2),8))[0]==-10000
            self.events.append('delay')
            if self.on_delay:self.on_delay(self)
            self.ret()
        elif r in [0x1c10,0x1e50]:
            assert self.reg(0)==DEVICE and self.reg(1) in [0,4,5]
            self.events.append('d0-entry' if r==0x1c10 else 'd0-exit')
            if r==0x1e50:assert self.get('AlertState')==1 and self.get('LiveDevice')==0
            self.ret(self.entry_status if r==0x1c10 else self.exit_status)
    def call(self,name,*args,budget=100000):
        u=self.u
        # The native unwind checker maps one image. Backend-chain execution
        # remains an emulation regression, not a single-client unwind fixture.
        self.capture_enabled=name!='backend'
        for reg,value in NV.items():u.reg_write(reg,value)
        u.reg_write(UC_ARM64_REG_SP,S+0x8000);u.reg_write(UC_ARM64_REG_LR,END)
        for i,arg in enumerate(args):u.reg_write(UC_ARM64_REG_X0+i,arg)
        if name in self.adapters:
            u.reg_write(UC_ARM64_REG_X19,F+(0x30 if name=='RepairClassStart' else 0x40))
            if name=='RepairClassStart':u.reg_write(UC_ARM64_REG_X26,DEVICE)
            nv_override={UC_ARM64_REG_X19:u.reg_read(UC_ARM64_REG_X19),UC_ARM64_REG_X26:u.reg_read(UC_ARM64_REG_X26)}
            target=self.base+self.adapters[name]
        else:nv_override={};target=B+0xe108 if name=='backend' else self.base+(0x89e0 if name=='alert' else SYM[name])
        self.expected=dict(NV,**{})
        self.expected.update(nv_override)
        u.emu_start(target,END,count=budget)
        assert u.reg_read(UC_ARM64_REG_PC)==END,(name,hex(u.reg_read(UC_ARM64_REG_PC)))
        assert u.reg_read(UC_ARM64_REG_SP)==S+0x8000
        assert all(u.reg_read(reg)==nv_override.get(reg,value) for reg,value in NV.items()),name
        return u.reg_read(UC_ARM64_REG_W0)
    def start(self):
        assert self.call('RepairD0Entry',DEVICE,4)==0
        assert self.call('RepairClassStart',A+0x3100,CONTROLLER)==0
        assert self.get('AlertState')==0 and self.get('LiveDevice')==DEVICE
    def alert(self,device=DEVICE,count=1,alerts=ALERTS):return self.call('alert',device,count,alerts)

def main():
    rows=[]
    for base,context,controller,count in itertools.product([0x140000000,0x180000000,0x7ffb12340000],[False,True],[False,True],[0,1,12,13]):
        m=Machine(base,context,controller)
        m.alert();assert not m.events,'Closed admission touched WDF'
        m.start();m.events=[];m.alert(count=count)
        expected=count in [1,12]
        assert ('lookup' in m.events)==expected
        assert ('alert' in m.events)==(expected and context and controller)
        assert m.get('AlertState')==0
        rows.append(dict(case='admission-null-context-controller-count',base=hex(base),context=context,controller=controller,count=count))
    for base in [0x140000000,0x180000000,0x7ffb12340000]:
        for field,value in [('device',0),('device',DEVICE+8),('alerts',0)]:
            m=Machine(base);m.start();m.events=[];m.alert(**{field:value});assert not m.events
            rows.append(dict(case='invalid-alert-argument',base=hex(base),field=field,value=value))
        for status in [0xc0000001,0xc0000185,0x102,0x103]:
            m=Machine(base);m.call('RepairD0Entry',DEVICE,4);m.start_status=status
            assert m.call('RepairClassStart',A+0x3100,CONTROLLER)==status
            m.events=[];m.alert();assert not m.events and m.get('AlertState')==1
            rows.append(dict(case='start-nonsuccess-keeps-closed',base=hex(base),status=hex(status)))
        for status in [0xc0000001,0xc0000185]:
            m=Machine(base);m.entry_status=status
            assert m.call('RepairD0Entry',DEVICE,4)==status
            m.events=[];assert m.call('RepairClassStart',A+0x3100,CONTROLLER)==0xc0000120
            assert not m.events
            rows.append(dict(case='failed-d0-entry-rejects-start',base=hex(base),status=hex(status)))
        for path in ['RepairD0Exit','RepairClassStop']:
            m=Machine(base);m.start();m.events=[]
            # One in-flight alert; scheduler completes it during passive wait.
            m.put('AlertState',2)
            def release(machine):
                assert machine.get('AlertState')==3
                assert not any(e in machine.events for e in ['stop','d0-exit'])
                machine.put('AlertState',1)
            m.on_delay=release
            m.call(path,DEVICE if path=='RepairD0Exit' else A+0x3100,5 if path=='RepairD0Exit' else CONTROLLER)
            assert 'delay' in m.events
            m.events=[];m.alert();assert not m.events
            assert m.call('RepairClassStart',A+0x3100,CONTROLLER)==0xc0000120
            m.start();m.alert();assert 'alert' in m.events
            rows.append(dict(case='drain-before-stop-and-reentry',base=hex(base),path=path))
        m=Machine(base);m.call('RepairD0Entry',DEVICE,4)
        def stop_during_start(machine):
            machine.put('StopRequested',1,4);machine.put('AlertState',machine.get('AlertState')|1)
        m.on_start=stop_during_start
        m.call('RepairClassStart',A+0x3100,CONTROLLER);m.events=[];m.alert()
        assert not m.events and m.get('AlertState')==1
        rows.append(dict(case='stop-during-start-prevents-publication',base=hex(base)))
        for context in [False,True]:
            m=Machine(base,context=context);m.start();m.events=[]
            m.call('backend',1,ALERTS)
            assert m.events==(['lookup','alert'] if context else ['lookup'])
            rows.append(dict(case='actual1851-backend-to1852-client',base=hex(base),context=context))
        m=Machine(base);m.start()
        def reentrant_io(machine):
            # Synchronous class I/O may run while the alert lease is active.
            assert machine.get('LifeLock')&0xffffffff==0
            machine.events.append('class-reentrant-io-allowed')
        m.on_alert=reentrant_io;m.alert();assert 'class-reentrant-io-allowed' in m.events
        rows.append(dict(case='class-call-holds-no-lifecycle-lock',base=hex(base)))
        m=Machine(base);m.start();m.put('AlertState',2)
        # Never release the old alert: production must wait, not stop/delete.
        m.u.reg_write(UC_ARM64_REG_SP,S+0x8000);m.u.reg_write(UC_ARM64_REG_LR,END)
        m.u.reg_write(UC_ARM64_REG_X0,DEVICE);m.u.reg_write(UC_ARM64_REG_X1,5)
        m.u.emu_start(base+SYM['RepairD0Exit'],END,count=4000)
        assert m.u.reg_read(UC_ARM64_REG_PC)!=END and 'd0-exit' not in m.events
        assert m.get('AlertState')==3
        rows.append(dict(case='permanent-alert-owner-never-forced-closed',base=hex(base)))
    with (ROOT/'build/alert-unwind-fixtures.bin').open('wb') as f:
        f.write(struct.pack('<II',0x3257444e,len(fixtures)))
        for pc,sp,regs,mem,expected in fixtures.values():f.write(struct.pack('<II31Q',pc,sp,*regs)+mem+struct.pack('<12Q',*expected))
    report=dict(scope='FINAL_PE_WITH_MOCKED_WDF_CLASS_DDIS_AND_SCHEDULED_INTERLEAVINGS',
        sha256=hashlib.sha256(PATH.read_bytes()).hexdigest(),cases=len(rows),rows=rows,fixtures=len(fixtures),
        original0x7eNullContextPathBlocked=True,actualStartStopAdaptersExecuted=True,
        actualBackend1851Executed=True,SPNonvolatileAndX18Preserved=True,
        backendChainExcludedFromSingleImageUnwind=True,
        physicalSMPTest=False,kernelExecution=False,hardwareIO=False,installed=False)
    (ROOT/'build/alert-lifecycle-emulation.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k!='rows'},indent=2))
if __name__=='__main__':main()
