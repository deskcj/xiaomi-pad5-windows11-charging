"""Actual1853 PE: original Prepare/Release/INTERFACE registration/provider.
Allocator, WDF and MMIO are modeled; no real MMIO, kernel or SMP execution.
"""
from pathlib import Path
import hashlib,itertools,json,struct
import test_alert_lifecycle as base
from test_alert_lifecycle import Machine,ROOT,META,SYM,CODE,A,S,F,END,DEVICE,CONTEXT,NV
from unicorn.arm64_const import *
MMIO=0x70000000
PHYSICAL=[(0x88e8000,0x3c,MMIO+0x100000),(0x100000,0x200000,MMIO),
          (0x88e0000,0x14000,MMIO+0x40000),(0xa600000,0x200000,MMIO+0x80000),
          (0xa800000,0x200000,MMIO+0xc0000)]
PACKET=A+0x7000;NAME=A+0x7200
SYM.update(RegisterInterface=0x41f0,ReleaseHardware=0xe9e0,MapEntry=0x2bd0,UnmapEntry=0x2d08,
           InterfaceReference=0x44d0,InterfaceDereference=0x45b0)
fixtures={}

class Hardware(Machine):
    def __init__(self,base_address=0x140000000,fail_at=None):
        super().__init__(base_address)
        self.u.mem_map(MMIO,0x110000)
        self.maps=[];self.unmaps=[];self.live={};self.fail_at=fail_at
        self.provider_entries=0;self.mapping_delay=None;self.close_during_provider=False
        self.original_prepare_override=None;self.interface_adds=0
        for d in self.pe.DIRECTORY_ENTRY_IMPORT:
            for i in d.imports:
                if i.name in [b'MmMapIoSpaceEx',b'MmUnmapIoSpace',b'KeStallExecutionProcessor']:
                    self.q(self.base+i.address-self.pe.OPTIONAL_HEADER.ImageBase,
                           F+{b'MmMapIoSpaceEx':0x60,b'MmUnmapIoSpace':0x70,b'KeStallExecutionProcessor':0x80}[i.name])
        self.q(A+0x4268,F+0x90);self.q(A+0x4720,F+0xa0)
        self.set_packet()
    def set_packet(self,enabled=1,name='\\_SB.URS0',length=18,maximum=20,buffer=NAME):
        self.u.mem_write(PACKET,struct.pack('<B7xHHIQ',enabled,length,maximum,0,buffer))
        self.u.mem_write(NAME,(name+'\0').encode('utf-16-le'))
    def mapping_state(self):return self.get('MappingState')
    def unmap_count(self):return len(self.unmaps)
    def capture(self,u,address):
        r=address-self.base
        if self.base!=0x140000000:return
        if not (CODE['rva']<=r<CODE['rva']+CODE['size'] or r in [0x2bd0,0x2d08] or
                0x2e50<=r<0x41ec or 0xe7a0<=r<0xec2c or 0x41f0<=r<0x44bc):return
        if not hasattr(self,'expected'):return
        regs=[self.reg(i) for i in range(29)]+[u.reg_read(UC_ARM64_REG_FP),u.reg_read(UC_ARM64_REG_LR)]
        sp=u.reg_read(UC_ARM64_REG_SP)
        expected=[self.expected[UC_ARM64_REG_X19+i] for i in range(10)]+[self.expected[UC_ARM64_REG_FP],self.expected[UC_ARM64_REG_X18]]
        key=(r,sp,tuple(regs[19:]),tuple(expected))
        if key not in fixtures:fixtures[key]=(r,sp-0x207000,regs,bytes(u.mem_read(0x207000,8192)),expected)
    def hook(self,u,address,size,_):
        r=address-self.base
        self.capture(u,address)
        if address==F+0x60:
            physical=self.reg(0);length=self.reg(1)
            assert self.reg(2)==0x204
            definition=next(v for v in PHYSICAL if v[0]==physical)
            assert length==definition[1]
            self.maps.append((physical,length))
            if self.fail_at==len(self.maps):self.ret(0);return
            virtual=definition[2];assert not self.live.get(virtual,False),'Mapping allocated twice'
            self.live[virtual]=True;self.ret(virtual);return
        if address==F+0x70:
            virtual,length=self.reg(0),self.reg(1)
            assert virtual and self.live.get(virtual,False),'NULL/foreign/double unmap'
            assert any(v==virtual and n==length for p,n,v in PHYSICAL)
            assert self.mapping_state()==1,'Unmap with live provider/admission'
            self.live[virtual]=False;self.unmaps.append((virtual,length));self.ret();return
        if address==F+0x80:self.ret();return
        if address==F+0x90:self.ret();return # WdfDeviceCreateDeviceInterface
        if address==F+0xa0:
            config=self.reg(2)
            assert self.r64(config+8)==self.base+0xc5a0
            assert self.r64(self.base+0xc5c0)==self.base+SYM['RepairProvider']
            self.interface_adds+=1;self.ret();return
        if address==F+0x50 and self.mapping_delay:
            assert struct.unpack('<q',u.mem_read(self.reg(2),8))[0]==-10000
            self.mapping_delay(self);self.ret();return
        if r==0x27a0:self.ret();return # Original non-MMIO WDF query-interface cleanup
        if r==0xe7a0 and self.original_prepare_override is not None:
            self.ret(self.original_prepare_override);return
        if r==0x2e50:
            self.provider_entries+=1
            assert self.mapping_state()&~1>=2 and self.get('MappingLock')&0xffffffff==0
            assert all(self.r64(self.base+v) for v in [0xc520,0xc528,0xc530,0xc538])
            if self.close_during_provider:self.put('MappingState',self.mapping_state()|1)
        return super().hook(u,address,size,_)
    def r64(self,address):return struct.unpack('<Q',self.u.mem_read(address,8))[0]
    def prepare(self):return self.call('RepairPrepareHardware',DEVICE,A+0x9000,A+0x9100)
    def release(self):return self.call('ReleaseHardware',DEVICE,A+0x9100)
    def register(self):
        # Execute the original callback-address construction fragment. This
        # is deliberately not captured as a whole DeviceAdd unwind context.
        self.u.reg_write(UC_ARM64_REG_SP,S+0x8000)
        self.u.emu_start(self.base+0xe140,self.base+0xe158,count=8)
        assert self.r64(S+0x8000+0xd0)==self.base+SYM['RepairPrepareHardware']
        assert self.r64(S+0x8000+0xd8)==self.base+0xe9e0
        assert self.call('RegisterInterface',DEVICE)==0
        assert self.interface_adds==1
    def provider(self):
        # Execute the callback address actually published by original41F0.
        address=self.r64(self.base+0xc5c0)
        assert address==self.base+SYM['RepairProvider']
        return self.call('RepairProvider',PACKET)

def main():
    rows=[]
    for address in [0x140000000,0x180000000,0x7ffb12340000]:
        m=Hardware(address);m.register()
        assert m.provider()==0xc00000a3 and m.provider_entries==0
        assert m.prepare()==0 and len(m.maps)==5 and m.mapping_state()==0
        for name,enabled in itertools.product(['\\_SB.URS0','\\_SB.URS1'],[0,1]):
            m.set_packet(name=name,enabled=enabled)
            assert m.provider()==0
            rows.append(dict(case='actual-registered-provider',base=hex(address),name=name,enabled=enabled))
        before=len(m.maps);m.call('MapEntry');assert len(m.maps)==before
        m.call('InterfaceReference',CONTEXT)
        assert bytes(m.u.mem_read(address+0xc590,1))==b'\1'
        assert m.release()==0 and not any(m.live.values()) and m.mapping_state()==1
        entries=m.provider_entries
        assert m.provider()==0xc00000a3 and m.provider_entries==entries
        m.call('InterfaceDereference',CONTEXT)
        assert bytes(m.u.mem_read(address+0xc590,1))==b'\0'
        m.call('UnmapEntry');assert len(m.unmaps)==5
        assert m.prepare()==0 and m.provider()==0
        m.release()
        rows.append(dict(case='release-with-held-interface-no-late-MMIO-and-reprepare',base=hex(address)))
        for fail in [1,2,3,4,5]:
            m=Hardware(address,fail);m.register()
            assert m.prepare()==0xc000009a
            assert m.mapping_state()==1 and m.provider()==0xc00000a3
            assert sum(m.live.values())==(0 if fail==1 else 1)
            assert m.release()==0 and not any(m.live.values())
            m.fail_at=None;assert m.prepare()==0 and m.provider()==0
            m.release();assert not any(m.live.values())
            rows.append(dict(case='each-map-failure-cleanup-release-and-retry',base=hex(address),failedAllocation=fail))
        for changes in [dict(enabled=2),dict(length=0),dict(maximum=19),dict(buffer=0)]:
            m=Hardware(address);m.register();m.prepare();m.set_packet(**changes)
            assert m.provider()==0xc000000d and m.provider_entries==0
            m.release();rows.append(dict(case='malformed-packet-no-original-provider',base=hex(address),changes=changes))
        m=Hardware(address);m.register();m.prepare();m.close_during_provider=True
        assert m.provider()==0 and m.mapping_state()==1
        assert m.provider()==0xc00000a3 and m.provider_entries==1
        m.call('UnmapEntry');assert len(m.unmaps)==4
        m.release();assert len(m.unmaps)==5
        rows.append(dict(case='close-during-provider-drains-before-unmap',base=hex(address)))
        m=Hardware(address);m.register();m.prepare();m.put('MappingState',2);waits=[]
        def finish_old_provider(machine):
            assert machine.mapping_state()==3 and not machine.unmaps
            waits.append(1);machine.put('MappingState',1)
        m.mapping_delay=finish_old_provider;m.release()
        assert waits and len(m.unmaps)==5
        rows.append(dict(case='passive-release-waits-for-owner',base=hex(address)))
        m=Hardware(address);m.register();m.prepare();m.put('MappingState',2)
        for reg,value in NV.items():m.u.reg_write(reg,value)
        m.expected=dict(NV)
        m.u.reg_write(UC_ARM64_REG_SP,S+0x8000);m.u.reg_write(UC_ARM64_REG_LR,END)
        m.u.emu_start(address+0x2d08,END,count=5000)
        assert m.u.reg_read(UC_ARM64_REG_PC)!=END
        assert m.mapping_state()==3 and not m.unmaps and sum(m.live.values())==5
        rows.append(dict(case='permanent-owner-never-forced-unmapped',base=hex(address)))
        for status in [0xc0000001,0xc0000185]:
            m=Hardware(address);m.original_prepare_override=status
            assert m.prepare()==status and m.mapping_state()==1 and not m.maps and not m.unmaps
            rows.append(dict(case='original-prepare-error-propagated',base=hex(address),status=hex(status)))
    with (ROOT/'build/provider-unwind-fixtures.bin').open('wb') as f:
        f.write(struct.pack('<II',0x3257444e,len(fixtures)))
        for pc,sp,regs,mem,expected in fixtures.values():f.write(struct.pack('<II31Q',pc,sp,*regs)+mem+struct.pack('<12Q',*expected))
    report=dict(status='ACTUAL_1853_PE_OFFLINE_PROVIDER_TESTS_PASSED',cases=len(rows),rows=rows,fixtures=len(fixtures),
        sha256=hashlib.sha256(base.PATH.read_bytes()).hexdigest(),
        testSourceSHA256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        originalPrepareAndReleaseBodiesExecuted=True,originalInterfaceRegistrationExecuted=True,
        callbackAddressConstructionFragmentChecked=True,
        actualOriginalProviderExecuted=True,heldInterfaceCounterexampleBlocked=True,
        failedMapReturnStatusCorrect=True,nullOrDoubleUnmap=False,SPNonvolatileX18Checked=True,
        mockDDIs=True,mockMMIO=True,physicalSMPTested=False,kernelExecuted=False,installed=False)
    (ROOT/'build/provider-emulation.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k!='rows'},indent=2))
if __name__=='__main__':main()
