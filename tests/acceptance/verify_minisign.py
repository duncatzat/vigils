#!/usr/bin/env python3
# Verify tauri-updater minisign signatures. Pure Python (pynacl), no minisign binary.
# Tauri uses prehashed 'ED' = Ed25519 over Blake2b-512(file). Usage:
#   verify_minisign.py <pubkey_b64> <artifact1> <sig1> [<artifact2> <sig2> ...]
import sys, base64, hashlib
from nacl.signing import VerifyKey

def parse_pubkey(b64):
    blob = base64.b64decode(base64.b64decode(b64).decode().splitlines()[1])
    return blob[:2], blob[2:10], blob[10:42]  # alg, keyid, ed25519_pk

def parse_sig(path):
    lines = base64.b64decode(open(path, "rb").read()).decode().splitlines()
    sb = base64.b64decode(lines[1]); tc = lines[2].split("trusted comment:", 1)[1].strip()
    return sb[:2], sb[2:10], sb[10:74], tc, base64.b64decode(lines[3])  # alg,keyid,sig,tc,globalsig

_, pkid, pk = parse_pubkey(sys.argv[1]); vk = VerifyKey(pk); allok = True
args = sys.argv[2:]
for i in range(0, len(args), 2):
    art, sig = args[i], args[i+1]
    alg, kid, s, tc, g = parse_sig(sig)
    data = open(art, "rb").read()
    msg = hashlib.blake2b(data, digest_size=64).digest() if alg == b"ED" else data
    kok = kid == pkid
    try: vk.verify(msg, s); fok = True
    except Exception: fok = False
    try: vk.verify(s + tc.encode(), g); gok = True
    except Exception: gok = False
    print(f"  {art.split('/')[-1]:36s} keyid={'ok' if kok else 'BAD'} file_sig={'ok' if fok else 'BAD'} tc_sig={'ok' if gok else 'BAD'}")
    allok = allok and kok and fok and gok
sys.exit(0 if allok else 1)
