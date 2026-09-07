#!/usr/bin/env python3
import hashlib, os, pathlib, urllib.request
ROOT=pathlib.Path(__file__).resolve().parents[1]
SHA='c3b4f5410e608af03a5eb0aaac84a4313d8da131248e08ff1759ac70c79d1644'

def setup():
    path=pathlib.Path(os.environ.get('COSIGN',str(ROOT/'.tools/cosign-2.6.5'))).resolve()
    if not path.exists():
        path.parent.mkdir(exist_ok=True)
        urllib.request.urlretrieve('https://github.com/sigstore/cosign/releases/download/v2.6.5/cosign-linux-amd64',path)
    if hashlib.sha256(path.read_bytes()).hexdigest()!=SHA: raise RuntimeError('Cosign binary checksum mismatch')
    path.chmod(0o755); return path

if __name__=='__main__': print(setup())
