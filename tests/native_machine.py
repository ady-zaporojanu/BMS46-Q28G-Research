"""Bounded M68020 execution fixture, NOT a CPU32/TPU hardware emulator."""
import ctypes
import unicorn as uc
import unicorn.m68k_const as mc

STOP=0x14000
SP=0xFF9C00
REGS=[getattr(mc,'UC_M68K_REG_D'+str(n)) for n in range(8)]+[getattr(mc,'UC_M68K_REG_A'+str(n)) for n in range(7)]
REG_VALUES=[0x10203040+0x10101*n for n in range(15)]


class Machine:
    def __init__(self, rom):
        self.u=uc.Uc(uc.UC_ARCH_M68K,uc.UC_MODE_BIG_ENDIAN)
        self.u.ctl_set_cpu_model(mc.UC_CPU_M68K_M68020)
        self.u.mem_map(0,0x40000)
        self.u.mem_write(0,rom)
        self.u.mem_protect(0,0x40000,uc.UC_PROT_READ|uc.UC_PROT_EXEC)
        self.ram=ctypes.create_string_buffer(65536)
        # CPU32 short absolute operands sign-extend; model 24-bit bus aliases.
        for address in (0xFF0000,0xFFFF0000):
            self.u.mem_map_ptr(address,65536,uc.UC_PROT_ALL,ctypes.addressof(self.ram))
        self.reset()

    def reset(self):
        ctypes.memset(ctypes.addressof(self.ram),0,65536)
        self.u.reg_write(mc.UC_M68K_REG_SR,0x2700)
        for r,v in zip(REGS,REG_VALUES):self.u.reg_write(r,v)
        self.u.reg_write(mc.UC_M68K_REG_A7,SP)

    def put(self,address,value):
        self.u.mem_write(address,bytes([value]) if isinstance(value,int) else value)

    def get(self,address,size=1):return bytes(self.u.mem_read(address,size))

    def run(self,start,end=STOP):
        self.u.reg_write(mc.UC_M68K_REG_A7,SP)
        self.put(SP,STOP.to_bytes(4,'big'))
        self.u.emu_start(start,end,count=20000)
        assert self.u.reg_read(mc.UC_M68K_REG_PC)==end, f'Unexpected stop at {self.u.reg_read(mc.UC_M68K_REG_PC):X}'
        assert self.u.reg_read(mc.UC_M68K_REG_A7)==SP+(4 if end==STOP else 0)

    def intact(self):
        assert [self.u.reg_read(r) for r in REGS]==REG_VALUES
