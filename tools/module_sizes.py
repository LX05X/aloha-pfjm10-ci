import sys, io, contextlib, struct, uuid
from pathlib import Path
import lzma, uuid
LZMA=uuid.UUID('EE4E5898-3914-4259-9D6E-DC7BD79403CF').bytes_le
def expand_lzma(blob):
    out=blob; off=0
    while True:
        i=out.find(LZMA,off)
        if i<0: return out
        sec=i-4; off=i+16
        if sec<0: continue
        c=struct.unpack_from('<I',out,sec)[0]; t=(c>>24)&0xFF; size=c&0xFFFFFF
        if t!=2 or size<32 or sec+size>len(out): continue
        doff=struct.unpack_from('<H',out,sec+20)[0]
        try: inner=lzma.LZMADecompressor(format=lzma.FORMAT_ALONE).decompress(out[sec+doff:sec+size])
        except Exception: continue
        out=out+inner
def exp(b):
    with contextlib.redirect_stdout(io.StringIO()):
        return expand_lzma(b)
def modules(blob):
    res={}; pos=0
    while True:
        i=blob.find(b'_FVH',pos)
        if i<0: break
        fv=i-0x28; pos=i+4
        if fv<0: continue
        try:
            length=struct.unpack_from('<Q',blob,fv+0x20)[0]; hdr=struct.unpack_from('<H',blob,fv+0x30)[0]; ext=struct.unpack_from('<H',blob,fv+0x34)[0]
        except struct.error: continue
        if not (0x48<length<=len(blob)-fv): continue
        p=fv+hdr
        if ext:
            try:
                esz=struct.unpack_from('<I',blob,fv+ext+16)[0]
                if 0<esz<0x1000: p=fv+ext+esz
            except struct.error: pass
        while p+4<=fv+length and blob[p:p+4]==b'\xff\xff\xff\xff': p+=4
        end=fv+length
        while p+24<=end:
            g=blob[p:p+16]
            if g==b'\xff'*16: break
            sz=int.from_bytes(blob[p+20:p+23],'little')
            if sz==0xffffff: sz=struct.unpack_from('<Q',blob,p+24)[0]
            if sz<24 or p+sz>end: break
            ui=''; q=p+24; e=p+sz
            while q+4<=e:
                ss=int.from_bytes(blob[q:q+3],'little'); st=blob[q+3]
                if ss<4 or q+ss>e: break
                if st==0x15: ui=blob[q+4:q+ss].decode('utf-16-le','ignore').rstrip('\0'); break
                q+=(ss+3)&~3
            res.setdefault(ui or str(uuid.UUID(bytes_le=g)).upper(), sz)
            p+=(sz+7)&~7
    return res
m=modules(exp(Path(sys.argv[1]).read_bytes()))
tgt={'BdsDxe':0x5568e,'MsBootPolicy':0x4da3c,'BootMenu':0x4b0d6,'AcpiTables':0x264fa}
for k,v in tgt.items():
    got=m.get(k)
    mark='MATCH' if got==v else f'diff {got-v:+#x}' if got else 'missing'
    print(f'{k:14} ours {got if got is None else hex(got)}  theirs {hex(v)}  {mark}')
print('total modules', len(m))
