#!/usr/bin/env python3
import hashlib, os, pathlib, urllib.request
ROOT=pathlib.Path(__file__).resolve().parents[1]
SHA='064954c5d8c7e3b28188eee5b1727b31c411550bc5fefd41aa672d3c761d103a'

def setup():
    path=pathlib.Path(os.environ.get('COSIGN',str(ROOT/'.tools/cosign'))).resolve()
    if not path.exists():
        path.parent.mkdir(exist_ok=True)
        urllib.request.urlretrieve('https://github.com/sigstore/cosign/releases/download/v2.6.1/cosign-linux-amd64',path)
    if hashlib.sha256(path.read_bytes()).hexdigest()!=SHA: raise RuntimeError('Cosign binary checksum mismatch')
    path.chmod(0o755); return path

if __name__=='__main__': print(setup())
