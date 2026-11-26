#!/usr/bin/env python3
"""Report FFS module sizes and hashes from a built firmware image.

Used by CI to compare a build against a known-good image: sizes catch layout
changes, hashes catch source/code differences.
"""
import hashlib
import lzma
import struct
import sys
import uuid
from pathlib import Path

LZMA = uuid.UUID('EE4E5898-3914-4259-9D6E-DC7BD79403CF').bytes_le
TARGET_SIZES = {'BdsDxe': 0x5568e, 'MsBootPolicy': 0x4da3c, 'BootMenu': 0x4b0d6, 'AcpiTables': 0x264fa}
WATCH = ['SimpleFbDxe', 'RamPartitionDxe', 'ArmCpuDxe', 'LinuxLoader', 'SmBiosTableDxe']
TARGET_HASHES = {
    'SimpleFbDxe': '9f1fc9f9c4',
    'RamPartitionDxe': '93d99a261c',
    'ArmCpuDxe': '5fd346d226',
    'LinuxLoader': 'f1949e7033',
    'SmBiosTableDxe': '335d728cf3',
}


def expand(blob):
    out = blob
    off = 0
    while True:
        i = out.find(LZMA, off)
        if i < 0:
            return out
        sec = i - 4
        off = i + 16
        if sec < 0:
            continue
        c = struct.unpack_from('<I', out, sec)[0]
        if (c >> 24) & 0xFF != 2:
            continue
        size = c & 0xFFFFFF
        if size < 32 or sec + size > len(out):
            continue
        doff = struct.unpack_from('<H', out, sec + 20)[0]
        try:
            inner = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE).decompress(out[sec + doff:sec + size])
        except Exception:
            continue
        out = out + inner


def modules(blob):
    res = {}
    pos = 0
    while True:
        i = blob.find(b'_FVH', pos)
        if i < 0:
            return res
        fv = i - 0x28
        pos = i + 4
        if fv < 0:
            continue
        try:
            length = struct.unpack_from('<Q', blob, fv + 0x20)[0]
            hdr = struct.unpack_from('<H', blob, fv + 0x30)[0]
            ext = struct.unpack_from('<H', blob, fv + 0x34)[0]
        except struct.error:
            continue
        if not (0x48 < length <= len(blob) - fv):
            continue
        p = fv + hdr
        if ext:
            try:
                esz = struct.unpack_from('<I', blob, fv + ext + 16)[0]
                if 0 < esz < 0x1000:
                    p = fv + ext + esz
            except struct.error:
                pass
        while p + 4 <= fv + length and blob[p:p + 4] == b'\xff\xff\xff\xff':
            p += 4
        end = fv + length
        while p + 24 <= end:
            g = blob[p:p + 16]
            if g == b'\xff' * 16:
                break
            sz = int.from_bytes(blob[p + 20:p + 23], 'little')
            if sz == 0xffffff:
                sz = struct.unpack_from('<Q', blob, p + 24)[0]
            if sz < 24 or p + sz > end:
                break
            ui = ''
            q = p + 24
            e = p + sz
            while q + 4 <= e:
                ss = int.from_bytes(blob[q:q + 3], 'little')
                st = blob[q + 3]
                if ss < 4 or q + ss > e:
                    break
                if st == 0x15:
                    ui = blob[q + 4:q + ss].decode('utf-16-le', 'ignore').rstrip('\0')
                    break
                q += (ss + 3) & ~3
            key = ui or str(uuid.UUID(bytes_le=g)).upper()
            res.setdefault(key, (sz, hashlib.sha1(blob[p:p + sz]).hexdigest()[:10]))
            p += (sz + 7) & ~7


def main():
    m = modules(expand(Path(sys.argv[1]).read_bytes()))
    for name, want in TARGET_SIZES.items():
        got = m.get(name)
        size = None if got is None else got[0]
        mark = 'MATCH' if size == want else (f'diff {size - want:+#x}' if size else 'missing')
        print(f'{name:14} ours {"-" if size is None else hex(size)} theirs {hex(want)} {mark}')
    print('--- watched module hashes (size sha1)')
    for name in WATCH:
        got = m.get(name)
        want = TARGET_HASHES.get(name, 'TBD')
        line = 'missing' if got is None else f'{hex(got[0])} {got[1]}'
        mark = 'MATCH' if got and got[1] == want else 'differs'
        print(f'  {name:18} {line:26} reference {want}  {mark}')
    print('total modules', len(m))


if __name__ == '__main__':
    main()
