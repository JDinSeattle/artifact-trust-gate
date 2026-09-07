"""Offline Cosign gate: snapshot once, authorize signer, verify, promote identical bytes."""
import fcntl
import hashlib
import json
import os
import pathlib
import stat
import subprocess
import tempfile

class Rejected(ValueError): pass

def sha(data): return hashlib.sha256(data).hexdigest()

def load_json(data):
    def unique(pairs):
        out={}
        for k,v in pairs:
            if k in out: raise Rejected('duplicate JSON key')
            out[k]=v
        return out
    try: return json.loads(data,object_pairs_hook=unique)
    except (ValueError,TypeError) as e: raise Rejected('invalid JSON') from e

def read_regular(path,limit):
    try:
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,'rb') as f:
            info=os.fstat(f.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size>limit: raise Rejected('invalid file type or size')
            data=f.read(limit+1)
            if len(data)>limit: raise Rejected('oversized input')
            return data
    except OSError as e: raise Rejected('unreadable or symlink input') from e

def verify_signature(tool,key,signature,blob,timeout):
    argv=[str(tool),'verify-blob','--offline','--insecure-ignore-tlog','--key',str(key),
          '--signature',str(signature),'--signature-digest-algorithm','sha256',str(blob)]
    try: p=subprocess.run(argv,capture_output=True,text=True,timeout=timeout)
    except (OSError,subprocess.TimeoutExpired) as e: raise Rejected('verifier unavailable or timed out') from e
    if p.returncode: raise Rejected('signature verification failed')
    return {'exit_code':p.returncode,'stderr':p.stderr.strip()}

def promote(*,artifact,manifest,artifact_signature,manifest_signature,key,policy,store,tool,timeout=5):
    # All untrusted bytes are read once. No verify(path)/later-copy(path) race.
    snapshots={
        'artifact':read_regular(artifact,16*1024*1024),'manifest.json':read_regular(manifest,65536),
        'artifact.sig':read_regular(artifact_signature,16384),'manifest.sig':read_regular(manifest_signature,16384),
        'signer.pub':read_regular(key,16384),'policy.json':read_regular(policy,65536)}
    pol=load_json(snapshots['policy.json']); m=load_json(snapshots['manifest.json'])
    if not isinstance(pol,dict) or set(pol)!={'version','public_key_sha256','builder','predicate_type','signature_format','digest_algorithm'}:
        raise Rejected('policy schema')
    if pol['version']!=1 or type(pol['version']) is not int: raise Rejected('policy version')
    if pol['signature_format']!='cosign-detached-v1' or pol['digest_algorithm']!='sha256': raise Rejected('unsupported signature format or algorithm')
    if sha(snapshots['signer.pub'])!=pol['public_key_sha256']: raise Rejected('signer not authorized')
    if not isinstance(m,dict) or set(m)!={'schema','subject_sha256','builder','predicate_type','source_sha256','signature_format','digest_algorithm'}:
        raise Rejected('provenance schema')
    if m['schema']!=1 or type(m['schema']) is not int: raise Rejected('provenance version')
    for field in ['builder','predicate_type','signature_format','digest_algorithm']:
        if m[field]!=pol[field]: raise Rejected('provenance policy mismatch: '+field)
    for field in ['subject_sha256','source_sha256']:
        if not isinstance(m[field],str) or len(m[field])!=64 or any(c not in '0123456789abcdef' for c in m[field]): raise Rejected('digest syntax')
    actual=sha(snapshots['artifact'])
    if actual!=m['subject_sha256']: raise Rejected('artifact/provenance digest mismatch')
    with tempfile.TemporaryDirectory(prefix='trust-gate-') as td:
        tmp=pathlib.Path(td)
        for name,data in snapshots.items(): (tmp/name).write_bytes(data)
        signatures=[verify_signature(tool,tmp/'signer.pub',tmp/'artifact.sig',tmp/'artifact',timeout),
                    verify_signature(tool,tmp/'signer.pub',tmp/'manifest.sig',tmp/'manifest.json',timeout)]
    destination=pathlib.Path(store); destination.mkdir(mode=0o700,parents=True,exist_ok=True)
    if destination.is_symlink(): raise Rejected('symlink store')
    record={'schema':1,'artifact_sha256':actual,'policy_sha256':sha(snapshots['policy.json']),
        'signer_sha256':sha(snapshots['signer.pub']),'manifest_sha256':sha(snapshots['manifest.json']),
        'verifier_sha256':sha(read_regular(tool,256*1024*1024)),
        'builder':m['builder'],'signature_results':signatures,'artifact_path':'objects/'+actual}
    with open(destination/'.lock','a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        objects=destination/'objects'; objects.mkdir(exist_ok=True)
        if objects.is_symlink(): raise Rejected('symlink object directory')
        target=objects/actual
        if target.exists() or target.is_symlink():
            if sha(read_regular(target,16*1024*1024))!=actual: raise Rejected('existing deployment object corrupted')
        else:
            with tempfile.NamedTemporaryFile(dir=objects,delete=False) as f:
                pending=pathlib.Path(f.name); f.write(snapshots['artifact']); f.flush(); os.fsync(f.fileno()); os.fchmod(f.fileno(),0o500)
            os.replace(pending,target)
        with tempfile.NamedTemporaryFile(dir=destination,mode='w',delete=False) as f:
            pending=pathlib.Path(f.name); json.dump(record,f,indent=2); f.write('\n'); f.flush(); os.fsync(f.fileno())
        os.replace(pending,destination/'deployment.json')
        directory_fd=os.open(destination,os.O_RDONLY|os.O_DIRECTORY)
        try: os.fsync(directory_fd)
        finally: os.close(directory_fd)
    return record

def consume(store,arguments):
    store=pathlib.Path(store); record=load_json(read_regular(store/'deployment.json',65536))
    digest=record['artifact_sha256']
    if len(digest)!=64 or any(c not in '0123456789abcdef' for c in digest): raise Rejected('deployment digest syntax')
    path=store/'objects'/digest
    # Execute the same opened inode whose bytes were hashed (Linux /proc/self/fd).
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        with os.fdopen(os.dup(fd),'rb') as f:
            if sha(f.read())!=digest: raise Rejected('deployment digest mismatch')
        return subprocess.run([f'/proc/self/fd/{fd}',*arguments],pass_fds=(fd,),capture_output=True,text=True,timeout=5,check=True).stdout
    finally: os.close(fd)

if __name__=='__main__':
    import argparse
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ['artifact','manifest','artifact-signature','manifest-signature','key','policy','store','tool']:
        ap.add_argument('--'+name,required=True,type=pathlib.Path)
    args=vars(ap.parse_args())
    try: print(json.dumps(promote(**args),indent=2))
    except Rejected as e: ap.exit(1,'REJECT: '+str(e)+'\n')
