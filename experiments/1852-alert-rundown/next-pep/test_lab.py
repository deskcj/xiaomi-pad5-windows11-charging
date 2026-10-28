"""Execute compiled laboratory C + actual PEP2140 + actual TCPM provider.
DDI/allocator/platform/security-helper ABI are mocks, MMIO is inert RAM.
No output SYS, PE integration, native unwind, driver load or hardware IO.
"""
from pathlib import Path
import hashlib,importlib.util,json,struct,sys
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT.parent/'tools'))
from link_backend import coff,branch,signed
OLD=ROOT/'reference'
spec=importlib.util.spec_from_file_location('original_pep_test',OLD/'saved_pep_machine.py')
old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old)
import pefile
from unicorn import UcError
from unicorn.arm64_const import *
C=0x150000000;M=0x50000000;LAB=old.BASE+0x250000;HELPER=old.BASE+0x27f000
CLIENT=(ROOT.parent/'reference/qcusbctcpm8150.sys').read_bytes()
assert hashlib.sha256(CLIENT).hexdigest()=='7c63f4a4b8a9ee0f49b427b6ac94867d2475e02f85d92d5fbcfe4a8aa1804067'
OBJ=(ROOT/'build/pep_lifetime.obj').read_bytes()
IDENTITY=json.loads((ROOT/'build/identity.json').read_text(encoding='utf-8-sig'))
assert hashlib.sha256(OBJ).hexdigest()==IDENTITY['objectSHA256'].lower()
assert hashlib.sha256((ROOT/'pep_lifetime.c').read_bytes()).hexdigest()==IDENTITY['sourceSHA256'].lower()

class Lab(old.Machine):
    def __init__(self):
        super().__init__(old.SOURCE)
        self.u.mem_map(LAB,0x30000)
        self.u.mem_map(C,0x20000);self.u.mem_write(C,pefile.PE(data=CLIENT).get_memory_mapped_image())
        self.u.mem_map(M,0x40000)
        self.w64(C+0xc108,C+0xc108);self.w64(C+0xb110,old.STUB+0x300)
        self.w64(C+0xc520,M+0x20000);self.w64(C+0xc528,M+0x10000);self.w64(C+0xc530,M)
        self.w64(C+0xc538,M);self.w64(C+0xb000,old.STUB+0x920)
        self.u.mem_write(old.AUX+0x3200,'\\_SB.URS0\0'.encode('utf-16-le'))
        self.w64(old.BASE+0x16a280,old.STUB+0x900)
        self.provider=[];self.ref=0;self.deref=0;self.platform=[];self.unmapped=[];self.on_delay=None;self.on_platform=None
        cp=pefile.PE(data=CLIENT)
        for descriptor in cp.DIRECTORY_ENTRY_IMPORT:
            for imp in descriptor.imports:
                if imp.name==b'MmUnmapIoSpace':self.w64(C+imp.address-cp.OPTIONAL_HEADER.ImageBase,old.STUB+0x940)
        self.query_resume=0;self.close_during_provider=False
        self.link_object()
    def link_object(self):
        sections,symbols=coff(OBJ);placements={};cursor=LAB
        kept=[]
        for s in sections:
            if s['name'] in ['.text$mn','.text','.bss','.data','.rdata','.pdata','.xdata'] and s['data']:
                cursor=(cursor+15)&~15;placements[s['index']]=cursor;cursor+=len(s['data']);kept.append(s)
            else:assert s['name'] in ['.debug$S','.debug$T','.chks64','.drectve','.gfids$y','.giats$y','.gljmp$y'] or not s['data']
        assert cursor<HELPER
        external={
          'SkPepInterface':old.BASE+0x1c8b98,'SkPepTarget':old.TARGET,'SkPepPacket':old.PTR,
          'SkPepPlatform':old.BASE+0x1c8f08,'SkPepControllers':old.BASE+0x1c9230,
          'SkPepMode':old.BASE+0x1c8c1c,'SkPepIndex':old.BASE+0x1c8f04,
          'OriginalPepNotify':old.BASE+0x380d0,'OriginalPepPower':old.BASE+0x1fb0,
          'OriginalTargetClose':old.BASE+0x4488,'OriginalObjectDelete':old.BASE+0x3ba0,
          '__imp_KeDelayExecutionThread':old.BASE+0x16a280,'__imp_ExFreePoolWithTag':old.BASE+0x16a098,
          '__guard_check_icall_fptr':old.BASE+0x16a468,
          '__security_push_cookie':HELPER,'__security_pop_cookie':HELPER+0x10,'__GSHandlerCheck':HELPER+0x20}
        for s in kept:
            for offset,index,kind in s['relocs']:
                sym=symbols[index]
                target=placements[sym['section']]+sym['value'] if sym['section']>0 else external[sym['name']]
                place=placements[s['index']]+offset;word=struct.unpack_from('<I',s['data'],offset)[0]
                if kind==2:word=(word+target-old.BASE)&0xffffffff
                elif kind==3:word=branch(place,target+signed(word&0x3ffffff,26)*4,bool(word&0x80000000))
                elif kind==4:
                    addend=signed((((word>>5)&0x7ffff)<<2)|((word>>29)&3),21)
                    imm=((((target+addend)&~4095)-(place&~4095))//4096)&0x1fffff
                    word=(word&~((0x7ffff<<5)|(3<<29)))|((imm&3)<<29)|((imm>>2)<<5)
                elif kind in [6,7]:
                    scale=0 if kind==6 else (word>>30)&3
                    value=(target+(((word>>10)&0xfff)<<scale))&4095
                    assert value%(1<<scale)==0
                    word=(word&~(0xfff<<10))|((value>>scale)<<10)
                else:raise AssertionError(('Unhandled relocation',kind))
                struct.pack_into('<I',s['data'],offset,word)
            self.u.mem_write(placements[s['index']],bytes(s['data']))
        self.symbols={s['name']:placements[s['section']]+s['value'] for s in symbols if s and s['section'] in placements}
    def get_gate(self):return self.r64(self.symbols['PowerGate'])
    def set_gate(self,value):self.w64(self.symbols['PowerGate'],value)
    def code(self,u,at,size,data):
        if at==old.STUB+0x300:
            u.reg_write(UC_ARM64_REG_PC,u.reg_read(UC_ARM64_REG_LR));return
        if at==HELPER:
            sp=u.reg_read(UC_ARM64_REG_SP)-16;u.reg_write(UC_ARM64_REG_SP,sp)
            self.w64(sp+8,sp^0xa5a5a5a5);self.finish_preserve();return
        if at==HELPER+0x10:
            sp=u.reg_read(UC_ARM64_REG_SP);assert self.r64(sp+8)==sp^0xa5a5a5a5
            u.reg_write(UC_ARM64_REG_SP,sp+16);self.finish_preserve();return
        if at==HELPER+0x20:raise AssertionError('Unexpected exception-handler execution')
        if at==old.STUB+0x900:
            assert struct.unpack('<q',u.mem_read(u.reg_read(UC_ARM64_REG_X2),8))[0]==-10000
            if self.on_delay:self.on_delay(self)
            self.finish();return
        if at==old.STUB+0x920:self.finish();return # simulated bounded MMIO polling delay
        if at==old.STUB+0x940:
            self.unmapped.append((u.reg_read(UC_ARM64_REG_X0),u.reg_read(UC_ARM64_REG_X1)))
            self.finish();return # record logical unmap, no physical MMIO access
        if at==old.BASE+0x2c1e0 and self.queryStatus==0:
            self.queries+=1
            u.mem_write(old.BASE+0x1c8b98,struct.pack('<HHI4Q',40,1,0,old.AUX,C+0x44d0,C+0x45b0,C+0x2e50))
            self.query_resume=u.reg_read(UC_ARM64_REG_LR)
            u.reg_write(UC_ARM64_REG_LR,old.STUB+0x700);u.reg_write(UC_ARM64_REG_PC,C+0x44d0);return
        if at==old.STUB+0x700:
            u.reg_write(UC_ARM64_REG_LR,self.query_resume);self.finish();return
        if at==C+0x44d0:self.ref+=1
        elif at==C+0x45b0:self.deref+=1
        elif at==C+0x2e50:
            p=u.reg_read(UC_ARM64_REG_X0)
            assert self.get_gate()&~1>=2 and self.r64(old.TARGET)!=0
            assert old.STACK<=p<old.STACK+0x20000,'Provider packet is not per-call stack storage'
            length,maximum=struct.unpack('<HH',u.mem_read(p+8,4));nameptr=self.r64(p+16)
            name=bytes(u.mem_read(nameptr,length)).decode('utf-16-le')
            assert length==18 and maximum==20 and name in ['\\_SB.URS0','\\_SB.URS1']
            self.provider.append(dict(enabled=bytes(u.mem_read(p,1))[0],name=name))
            if self.close_during_provider:self.set_gate(self.get_gate()|1)
        elif at==old.STUB+0x600:
            assert self.get_gate()&~1==0,'Lease crosses reentrant platform call'
            self.platform.append(u.reg_read(UC_ARM64_REG_X2))
            if self.on_platform:self.on_platform(self)
            self.finish();return
        if C<=at<C+0x20000 or LAB<=at<LAB+0x30000:return
        super().code(u,at,size,data)
    def finish_preserve(self):self.u.reg_write(UC_ARM64_REG_PC,self.u.reg_read(UC_ARM64_REG_LR))
    def invoke(self,name,a0,a1):return self.call(self.symbols[name]-old.BASE,a0,a1)
    def event(self,guid):
        self.u.mem_write(old.AUX+0x100,bytes(0x40));self.u.mem_write(old.AUX+0x104,guid)
        self.w64(old.AUX+0x128,old.AUX+0x1000)
        return self.invoke('RepairPepNotify',old.AUX+0x100,old.AUX)
    def power(self,on):return self.invoke('RepairPepPower',old.AUX,int(on))

def main():
    rows=[]
    for cycles in [1,2,10,100,256]:
        m=Lab()
        m.power(True);m.power(False);assert len(m.platform)==2 and not m.provider
        for _ in range(cycles):
            assert m.event(old.ARRIVAL)==0
            m.power(True);m.power(False)
            assert m.event(old.REMOVAL)==0
            assert m.r64(old.PTR)==0 and m.r64(old.TARGET)==0 and m.get_gate()==1
            m.power(True);m.power(False)
        assert m.allocations==m.frees==m.ref==m.deref==cycles
        assert sum(m.live.values())==0 and len(m.provider)==cycles*2 and len(m.platform)==cycles*4+2
        assert bytes(m.u.mem_read(C+0xc590,1))==b'\0'
        rows.append(dict(case='real-PEP-provider-balanced-cycles',cycles=cycles,allocations=m.allocations,frees=m.frees,references=m.ref,dereferences=m.deref))
    for field in ['createStatus','openStatus','queryStatus','failAllocation']:
        m=Lab();setattr(m,field,True if field=='failAllocation' else 0xc0000001)
        status=m.event(old.ARRIVAL)
        assert status&0x80000000 and m.r64(old.PTR)==m.r64(old.TARGET)==0 and m.get_gate()==1
        assert m.ref==m.deref
        setattr(m,field,False if field=='failAllocation' else 0)
        assert m.event(old.ARRIVAL)==0
        m.power(True);assert len(m.provider)==1
        m.event(old.REMOVAL);assert m.ref==m.deref and m.allocations==m.frees
        rows.append(dict(case='failure-cleanup-and-retry',field=field,status=hex(status)))
    m=Lab();assert m.event(old.ARRIVAL)==0 and m.event(old.ARRIVAL)==0
    assert m.queries==m.ref==m.allocations==1
    m.event(old.REMOVAL);m.event(old.REMOVAL)
    assert m.frees==m.deref==1
    rows.append(dict(case='duplicate-arrival-removal-idempotent'))
    m=Lab();m.event(old.ARRIVAL)
    for name in ['\\_SB.URS0','\\_SB.URS1','\\_SB.URS0']:
        m.u.mem_write(old.AUX+0x3200,(name+'\0').encode('utf-16-le'))
        m.power(True);assert m.provider[-1]['name']==name
    rows.append(dict(case='name-current-on-first-flag1-and-each-port-change'))
    m=Lab();m.event(old.ARRIVAL);m.close_during_provider=True
    m.power(True);assert m.get_gate()==1 and len(m.provider)==1
    m.power(False);assert len(m.provider)==1
    m.event(old.REMOVAL);assert m.ref==m.deref==1
    rows.append(dict(case='gate-close-during-provider-defers-free'))
    m=Lab();m.event(old.ARRIVAL)
    def close_at_platform(machine):machine.set_gate(machine.get_gate()|1)
    m.on_platform=close_at_platform;m.power(False)
    assert not m.provider and m.platform==[0]
    rows.append(dict(case='platform-can-close-admission-with-no-held-lease'))
    m=Lab();m.event(old.ARRIVAL);m.set_gate(2);waits=[]
    def release_at_wait(machine):
        assert machine.get_gate()==3 and machine.frees==machine.deref==0
        waits.append(1);machine.set_gate(1)
    m.on_delay=release_at_wait;m.event(old.REMOVAL)
    assert waits and m.allocations==m.frees==m.ref==m.deref==1
    rows.append(dict(case='removal-waits-before-dereference-and-free'))
    for mode in [0,3]:
        m=Lab();m.u.mem_write(old.BASE+0x1c8c1c,struct.pack('<I',mode));m.power(True);m.power(False)
        assert m.platform==[1,0] and not m.provider
        rows.append(dict(case='non-TypeC-delegates-original-power',mode=mode))
    # Deliberately adverse inter-module ordering: the real provider releases
    # mappings before PEP sees removal. Its interface reference is still1.
    # This is a code-level counterexample, NOT observed Windows PnP ordering.
    m=Lab();m.event(old.ARRIVAL)
    m.call(C+0x2d08-old.BASE,0,0)
    assert len(m.unmapped)==4 and m.ref==1 and m.deref==0
    assert bytes(m.u.mem_read(C+0xc590,1))==b'\1'
    assert all(m.r64(C+offset)==0 for offset in [0xc520,0xc528,0xc530,0xc538])
    try:m.power(True)
    except UcError:
        assert m.u.reg_read(UC_ARM64_REG_PC)==C+0x3240
    else:raise AssertionError('Expected ungated provider MMIO access after external release')
    remaining=[dict(case='provider-release-before-pep-notification',interfaceReferencesStillHeld=1,
        actualUnmapHelperExecuted=True,unmapCalls=4,providerFaultRVA='0x3240',
        runtimePnPOrderingObserved=False,repairStillRequired=True)]
    report=dict(status='LAB_OWN_LIFETIME_TESTS_PASSED_EXTERNAL_PROVIDER_COUNTEREXAMPLE_REMAINS',
        sourceSHA256=IDENTITY['sourceSHA256'],objectSHA256=IDENTITY['objectSHA256'],
        testScriptSHA256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        savedMachineSHA256=hashlib.sha256((OLD/'saved_pep_machine.py').read_bytes()).hexdigest(),
        coffParserSHA256=hashlib.sha256((ROOT.parent/'tools/link_backend.py').read_bytes()).hexdigest(),
        actualOriginalPEPSHA256=hashlib.sha256(old.SOURCE).hexdigest(),actualClientProviderSHA256=hashlib.sha256(CLIENT).hexdigest(),
        cases=len(rows),rows=rows,remainingUnsafeCounterexamples=remaining,
        noSharedHeapPowerPacket=True,firstFlag1Initialized=True,
        actualPEPNotificationBodyExecuted=True,actualTCPMProviderExecuted=True,
        mockKernelDDIs=True,mockSecurityHelperABI=True,physicalSMPTested=False,
        finalPEProduced=False,nativePEPUnwindTested=False,kernelExecuted=False,hardwareMMIOExecuted=False,installed=False,
        openItems=['Provider MMIO lifetime vs ReleaseHardware','PnP registration and all power call-site integration','Real PEP IRQL contract','Shutdown/unregister and unload lifetime','Full native unwind and CFG/ASLR/package checks'])
    (ROOT/'build/lab-results.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k!='rows'},indent=2))
if __name__=='__main__':main()
