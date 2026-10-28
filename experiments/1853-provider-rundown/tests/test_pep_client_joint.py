"""Compiled PEP laboratory module -> actual1853 published private INTERFACE.
Tests cross-module callback lifetime only; hardware/MMIO behavior is modeled.
"""
import hashlib,importlib.util,json,struct,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
PEP_LAB=ROOT.parent/'candidate-1852-alert-rundown/next-pep'
sys.path.insert(0,str(PEP_LAB))
spec=importlib.util.spec_from_file_location('saved_pep_joint',PEP_LAB/'test_lab.py')
lab=importlib.util.module_from_spec(spec);spec.loader.exec_module(lab)
from unicorn.arm64_const import *
CLIENT=(ROOT/'build/qcusbctcpm8150.sys').read_bytes()
lab.CLIENT=CLIENT
SYMBOLS=json.loads((ROOT/'build/client-build.json').read_text())['symbols']
C=lab.C;MMIO=lab.M;P=lab.old;F=P.STUB;CTX=P.AUX+0x9000
MAPS=[(0x100000,0x200000,MMIO),(0x88e0000,0x14000,MMIO+0x200000),
      (0xa600000,0x200000,MMIO+0x400000),(0xa800000,0x200000,MMIO+0x600000)]

class Joint(lab.Lab):
    def __init__(self):
        super().__init__()
        self.u.mem_map(MMIO+0x40000,0x7c0000)
        self.map_calls=0;self.map_fail_at=None;self.mapping_live={};self.validated_unmaps=0
        for offset in [0xc520,0xc528,0xc530,0xc538]:self.w64(C+offset,0)
        self.w64(C+0xb0b0,F+0x960)
        self.w64(C+0xc498,P.AUX+0x8000);self.w64(C+0xc4c8,P.AUX+0x7800)
        for offset,address in [(0x650,F+0x980),(0x268,F+0x990),(0x720,F+0x9a0)]:self.w64(P.AUX+0x8000+offset,address)
        assert self.call(C+0x41f0-P.BASE,P.AUX+0x4800,0)==0
        assert self.r64(C+0xc5c0)==C+SYMBOLS['RepairProvider']
    def state(self):return self.r64(C+SYMBOLS['MappingState'])
    def map(self):return self.call(C+0x2bd0-P.BASE,0,0)
    def unmap(self):return self.call(C+0x2d08-P.BASE,0,0)
    def code(self,u,at,size,data):
        if at==F+0x960:
            physical,length=u.reg_read(UC_ARM64_REG_X0),u.reg_read(UC_ARM64_REG_X1)
            assert u.reg_read(UC_ARM64_REG_X2)==0x204
            entry=next(v for v in MAPS if v[0]==physical);assert length==entry[1]
            self.map_calls+=1
            if self.map_calls==self.map_fail_at:self.finish(0);return
            assert not self.mapping_live.get(entry[2],False)
            self.mapping_live[entry[2]]=True;self.finish(entry[2]);return
        if at==F+0x940:
            virtual,length=u.reg_read(UC_ARM64_REG_X0),u.reg_read(UC_ARM64_REG_X1)
            assert self.state()==1 and self.mapping_live.get(virtual,False)
            assert any(n==length and v==virtual for p,n,v in MAPS)
            self.mapping_live[virtual]=False;self.validated_unmaps+=1
        if at in [F+0x980,F+0x990,F+0x9a0]:
            if at==F+0x9a0:
                assert self.r64(u.reg_read(UC_ARM64_REG_X2)+8)==C+0xc5a0
            self.finish(CTX if at==F+0x980 else 0);return
        if at==P.BASE+0x2c1e0 and self.queryStatus==0:
            self.queries+=1
            u.mem_write(P.BASE+0x1c8b98,bytes(u.mem_read(C+0xc5a0,40)))
            self.query_resume=u.reg_read(UC_ARM64_REG_LR)
            u.reg_write(UC_ARM64_REG_LR,F+0x700);u.reg_write(UC_ARM64_REG_PC,C+0x44d0);return
        return super().code(u,at,size,data)

def main():
    rows=[]
    for cycles in [1,10,100,256]:
        m=Joint()
        for _ in range(cycles):
            m.map();assert m.state()==0
            assert m.event(P.ARRIVAL)==0
            m.power(True);m.power(False)
            entries=len(m.provider)
            m.unmap()
            assert bytes(m.u.mem_read(C+0xc590,1))==b'\1'
            m.power(True);m.power(False)
            assert len(m.provider)==entries,'Late power call entered unmapped provider'
            m.map();m.power(True);assert len(m.provider)==entries+1
            m.event(P.REMOVAL);m.unmap()
        assert m.ref==m.deref==m.allocations==m.frees==cycles
        assert m.map_calls==m.validated_unmaps==8*cycles and not any(m.mapping_live.values())
        assert bytes(m.u.mem_read(C+0xc590,1))==b'\0'
        rows.append(dict(cycles=cycles,heapAllocations=m.allocations,heapFrees=m.frees,
            references=m.ref,dereferences=m.deref,mapCalls=m.map_calls,unmapCalls=m.validated_unmaps,
            actualProviderCalls=len(m.provider),lateCallsBlocked=True))
    for failure in [1,2,3,4]:
        m=Joint();m.map_fail_at=failure;m.map()
        assert m.state()==1 and not any(m.mapping_live.values())
        assert m.event(P.ARRIVAL)==0
        m.power(True);assert not m.provider
        m.map_fail_at=None;m.map();m.power(True);assert len(m.provider)==1
        m.event(P.REMOVAL);m.unmap()
        assert m.ref==m.deref==1 and not any(m.mapping_live.values())
        rows.append(dict(case='partial-mapping-failure-and-retry-with-held-PEP-interface',failure=failure))
    report=dict(status='COMPILED_PEP_AND_ACTUAL_1853_CLIENT_JOINT_OFFLINE_TESTS_PASSED',
        clientSHA256=hashlib.sha256(CLIENT).hexdigest(),pepObjectSHA256=lab.IDENTITY['objectSHA256'],
        pepSourceSHA256=lab.IDENTITY['sourceSHA256'],testSourceSHA256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        harnessSHA256=hashlib.sha256((PEP_LAB/'test_lab.py').read_bytes()).hexdigest(),
        cases=len(rows),rows=rows,actualInterfaceRegistrationAndReferenceCallbacks=True,
        actualPEPNotifyBody=True,originalProviderBody=True,providerLateMMIOCounterexampleBlocked=True,
        sharedHeapPEPPacketUsed=False,ddiAndSecurityMocks=True,electricalMMIOModeled=False,
        physicalSMPTested=False,kernelExecuted=False,installed=False,completeChargingFixProven=False)
    (ROOT/'build/pep-client-joint.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k!='rows'},indent=2))
if __name__=='__main__':main()
