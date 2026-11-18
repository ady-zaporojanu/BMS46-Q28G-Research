"""Execute canonical fan-demand paths offline. Requires a user-supplied ROM.
No vehicle connection, serial access, or firmware modification.
"""
import argparse, hashlib, json, random
from pathlib import Path
from itertools import product
import native_machine as h

if not __debug__:
    raise RuntimeError('Run without -O: test assertions must be enabled')
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--rom', type=Path, required=True)
p.add_argument('--output', type=Path, default=Path(__file__).resolve().parents[1]/'local-work/native')
a = p.parse_args()
ROOT = a.output.resolve()
SHA = 'd3c3abb5236240906a9d8851b31802e0751c233ebe0bba58d2c51f66e137679d'
rom = a.rom.read_bytes()
if len(rom) != 262144 or hashlib.sha256(rom).hexdigest() != SHA:
    raise ValueError('Exact canonical Q28G firmware required')
ROOT.mkdir(parents=True, exist_ok=True)
def save(name, obj):
    (ROOT/name).write_text(json.dumps(obj, indent=2)+'\n', encoding='utf-8')
m = h.Machine(rom)
def put(a,v,n=1): m.put(a,v.to_bytes(n,'big'))
def get(a,n=1): return int.from_bytes(m.get(a,n),'big')

# Prove index7 dispatches through the ten-byte ROM record containing ID0615.
record=0x35186+7*10
assert record==0x351cc and rom[record:record+6]==bytes.fromhex('061500033cfa')
m.reset();put(h.SP,h.STOP,4);put(h.SP+4,7,4)
m.u.emu_start(0x32dba,0x33cfa,count=500)
assert m.u.reg_read(h.mc.UC_M68K_REG_PC)==0x33cfa
sp=m.u.reg_read(h.mc.UC_M68K_REG_A7);context=get(sp+4,4)
assert get(context)==7 and get(context+1)==8 and get(context+2,4)==record and get(context+6,4)==0xff89ce
save('receive_dispatch.json',{'index':7,'record':hex(record),'record_hex':rom[record:record+10].hex(),'descriptor_id':'0x615','handler':'0x33CFA','context_hex':m.get(context,10).hex(),'scope':'Native dispatcher reaches handler; not a live CAN/controller test. Descriptor ID encoding is used at32D4E..32D66.'})

# Execute the decode slice after receive/DTC processing, stopping before temperature.
# Caller frame, MMIO acquisition and DTC calls are deliberately outside this fixture.
decode_cases=0
for b1,pattern in product(range(256),(0,0x55,0xaa,0xff)):
    m.reset();message=0xff9000;b0=(b1*167+pattern)&255
    m.put(message,bytes([b0,b1,0,0,0,0,0,0]))
    m.u.reg_write(h.mc.UC_M68K_REG_A3,message);m.u.reg_write(h.mc.UC_M68K_REG_A5,message)
    for a in (0xff8554,0xff85d0,0xff85d1,0xff846a):put(a,pattern)
    put(0xff8804,0xe7)
    m.run(0x33d5a,0x33de4)
    assert get(0xff8804)==b1>>4
    assert get(0xff85de)==b0&31
    assert get(0xff8554)==(pattern&~16)|(16 if b0&32 else 0)
    assert get(0xff85d0)==(pattern&~128)|(128 if b0&64 else 0)
    assert get(0xff85d1)==(pattern&~1)|(1 if b0&128 else 0)
    assert get(0xff846a)==(pattern&~16)|(16 if b1&1 else 0)
    decode_cases+=1
for old in range(256):
    m.reset();put(0xff96a4,1<<30,4);put(0xff8804,old)
    m.run(0x33d5a,0x33ea0)
    assert get(0xff8804)==old

def curve(address):
    count=int.from_bytes(rom[address+8:address+10],'big')
    return {'descriptor':address,'input':int.from_bytes(rom[address:address+4],'big'),'output':int.from_bytes(rom[address+4:address+8],'big'),'axis':list(rom[address+10:address+10+count]),'values':list(rom[address+10+count:address+10+2*count])}
curves=[curve(a) for a in (0x8198,0x81b6,0x81d4)]
assert [(c['input'],c['output']) for c in curves]==[(0xff8804,0xff8812),(0xff8328,0xff8813),(0xff832d,0xff8814)]
def interpolate(c,x):
    a,v=c['axis'],c['values']
    if x<=a[0]:return v[0]
    if x>=a[-1]:return v[-1]
    i=max(i for i in range(len(a)-1) if a[i]<=x)
    span=max(1,a[i+1]-a[i]);delta=v[i+1]-v[i]
    step=((span//2)+(x-a[i])*abs(delta))//span
    return v[i]+(step if delta>=0 else -step)
for c,x in product(curves,range(256)):
    m.reset();put(c['input'],x);put(h.SP+4,c['descriptor'],4)
    m.run(0x15a42)
    assert get(c['output'])==interpolate(c,x)
save('calibration_curves.json',curves)

def normalize(filtered,voltage):
    scaled=min(255,filtered*rom[0x81f1]//(voltage+1))
    transformed=scaled*153//128
    demand=max(0,transformed-76)
    command=0 if demand<3 else min(rom[0x81e7],max(rom[0x81e8],demand))
    return demand,command
# Exhaust all filtered byte / raw voltage pairs in the original normalization slice.
normalization_outputs=set()
for filtered,voltage in product(range(256),repeat=2):
    m.reset();m.u.reg_write(h.mc.UC_M68K_REG_A2,0xff880b)
    put(0xff880d,filtered);put(0xff832c,voltage)
    m.run(0x23d1c,0x23ed0)
    want,command=normalize(filtered,voltage)
    assert (get(0xff880b),get(0xff880e))==(want,command),(filtered,voltage)
    normalization_outputs.add(command)
expected_outputs={normalize(n,145)[1] for n in range(256)}
assert normalization_outputs==expected_outputs and len(normalization_outputs)==169
assert normalization_outputs<={0}|set(range(29,229))
save('normalization_output_domain.json',{'reachable':sorted(normalization_outputs),'skipped_within_bounds':sorted(set(range(29,229))-normalization_outputs),'interpretation':'Raw normal-command outputs of canonical normalization; diagnostic override may select other bytes.'})

def step_model(level,temp,speed,voltage,extra,high,low,old):
    a=interpolate(curves[0],level);b=interpolate(curves[1],temp);s=interpolate(curves[2],speed)
    extra_value=rom[0x81ea] if extra else 0
    demand=max(a,b,extra_value);raw=demand*s//256
    band=rom[0x81ed]
    if raw>=high:high=raw;low=max(0,raw-band)
    if raw<=low:low=raw;high=0 if raw==0 else min(255,raw+band)
    delta=(high-old)*rom[0x81e6]+128
    signed=((delta+32768)&65535)-32768
    change=signed>>8
    if high!=old and change==0:change=1 if high>old else -1
    filtered=(old+change)&255
    transformed,command=normalize(filtered,voltage)
    return {0xff8805:a,0xff8806:b,0xff8807:extra_value,0xff8808:demand,0xff8809:raw,0xff880a:high,0xff880b:transformed,0xff880d:filtered,0xff880e:command,0xff8812:a,0xff8813:b,0xff8814:s,0xff8815:high,0xff8816:low}

# Execute entire canonical demand routine plus its real interpolation/filter callees,
# then run the native output routine. All16 received levels x all256 temperature bytes.
rng=random.Random(20261118)
for level,temp in product(range(16),range(256)):
    speed,voltage=rng.randrange(256),rng.randrange(256)
    extra=bool(rng.randrange(2));low=rng.randrange(256);high=rng.randrange(low,256);old=rng.randrange(256)
    expected=step_model(level,temp,speed,voltage,extra,high,low,old)
    m.reset()
    for a,v in [(0xff8a40,1),(0xff8804,level),(0xff8328,temp),(0xff832d,speed),(0xff832c,voltage),(0xff8815,high),(0xff8816,low),(0xff880d,old)]:put(a,v)
    put(0xff96a4,(1<<23) if extra else 0,4)
    m.run(0x23bd2)
    for a,v in expected.items():assert get(a)==v,(level,temp,hex(a),get(a),v)
    m.run(0x23ef2)
    c=expected[0xff880e]
    assert get(0xff8818)==c and get(0xffffc4,2)==(1136 if not c else 1136*(255-c)//256)

# Explicit disabled/suppressed branch: normal state cleared while history stays retained.
gate_cases=0
for gate,suppress,old in product(range(2),range(2),range(256)):
    if gate and not suppress:continue
    m.reset();put(0xff8a40,gate);put(0xff84a2,suppress)
    for a in (0xff880c,0xff880d,0xff880e,0xff8815,0xff8816):put(a,old)
    m.run(0x23bd2)
    assert all(get(a)==0 for a in (0xff880c,0xff880d,0xff880e))
    assert get(0xff8815)==old and get(0xff8816)==old
    gate_cases+=1

# Multi-call scenarios show state/history behavior; time axis is calls, never milliseconds.
scenarios=[]
for level,temp,speed,voltage,extra in [(0,0,0,145,False),(15,0,0,145,False),(0,224,0,145,False),(15,224,170,145,False),(0,0,0,145,True)]:
    m.reset();put(0xff8a40,1)
    for a,v in [(0xff8804,level),(0xff8328,temp),(0xff832d,speed),(0xff832c,voltage)]:put(a,v)
    put(0xff96a4,(1<<23) if extra else 0,4)
    timeline=[]
    high=low=old=0
    for tick in range(1,321):
        expected=step_model(level,temp,speed,voltage,extra,high,low,old)
        m.run(0x23bd2);m.run(0x23ef2)
        for a,v in expected.items():assert get(a)==v
        high,low,old=expected[0xff8815],expected[0xff8816],expected[0xff880d]
        if tick in (1,2,10,50,100,200,320):timeline.append({'call':tick,'filtered':old,'command':get(0xff8818),'tpu_parameter':get(0xffffc4,2)})
    scenarios.append({'inputs':{'received_level':level,'temperature_raw':temp,'speed_raw':speed,'voltage_raw':voltage,'extra_request':extra},'timeline':timeline})
save('scenarios.json',scenarios)
counts={'dispatcher':1,'decode_slice':decode_cases,'decode_inhibit':256,'curve_lookup':768,'voltage_normalization':65536,'complete_demand_and_output':4096,'disabled_or_suppressed':gate_cases,'sequential_steps':1600}
save('test_results.json',{'status':'PASS','cases':counts,'total':sum(counts.values()),'rom_sha256':SHA,'emulator':'Unicorn '+h.uc.__version__+' M68020 common instruction subset','limits':['No real CAN reception or external controller simulation.','Decode tests begin after receive/DTC calls; error path not fully executed.','No TPU microcode, waveform, interrupt timing or physical units tested.','All calibration bytes are canonical, unmodified.','Voltage tests use raw FF832C, not volts.','Sequential steps are task invocations, not milliseconds.']})


print('PASS native fan-demand cases:', sum(counts.values()))
