#!/usr/bin/env python3
import argparse, copy, json, os, pathlib, shutil, subprocess, sys, tempfile
ROOT=pathlib.Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT))
from gate import Rejected, consume, promote, verify_signature
from evidence import command, digest, fresh, seal, write
from scripts.setup import setup

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--out',default='.runs/latest'); args=ap.parse_args()
    out=fresh(ROOT,args.out)
    tool=setup(); (ROOT/'build').mkdir(exist_ok=True)
    historical=ROOT/'evidence/local';compatibility=[]
    for blob,sig in [('artifact.bin','artifact.sig'),('provenance.json','provenance.sig')]:
        compatibility.append({'signed_with':'Cosign 2.6.1','verified_with':'Cosign 2.6.5','blob_sha256':digest(historical/blob),
            'result':verify_signature(tool,historical/'allowed.pub',historical/sig,historical/blob,5)})
    write(out/'historical-signature-compatibility.json',compatibility)
    source=ROOT/'vendor/gemm.cpp'; artifact=ROOT/'build/gemm'
    assert digest(source)==json.loads((ROOT/'vendor/lock.json').read_text())['sha256']
    command(['g++','-std=c++17','-O3',str(source),'-o',str(artifact)])
    # Private test keys live in a temporary directory and are removed even on failure.
    with tempfile.TemporaryDirectory(prefix='artifact-trust-test-') as td:
        temp=pathlib.Path(td); env=dict(os.environ,COSIGN_PASSWORD='')
        for identity in ['allowed','foreign']:
            command([str(tool),'generate-key-pair','--output-key-prefix',str(temp/identity)],env=env)
            shutil.copyfile(temp/(identity+'.pub'),out/(identity+'.pub'))
        manifest={'schema':1,'subject_sha256':digest(artifact),'builder':'local:gemm-release-builder',
            'predicate_type':'https://example.invalid/clinic/build/v1','source_sha256':digest(source),
            'signature_format':'cosign-detached-v1','digest_algorithm':'sha256'}
        policy={'version':1,'public_key_sha256':digest(out/'allowed.pub'),'builder':manifest['builder'],
            'predicate_type':manifest['predicate_type'],'signature_format':manifest['signature_format'],'digest_algorithm':'sha256'}
        write(out/'policy.json',policy); write(out/'provenance.json',manifest)
        shutil.copyfile(artifact,out/'artifact.bin')
        signing=[]
        def sign(file,sig,identity='allowed'):
            signing.append({'blob':file.name,'signature':sig.name,'identity':identity,
                'stdout':command([str(tool),'sign-blob','--key',str(temp/(identity+'.key')),'--tlog-upload=false',
                    '--output-signature',str(sig),str(file)],env=env)})
        sign(out/'artifact.bin',out/'artifact.sig'); sign(out/'provenance.json',out/'provenance.sig')
        base=dict(artifact=out/'artifact.bin',manifest=out/'provenance.json',artifact_signature=out/'artifact.sig',
            manifest_signature=out/'provenance.sig',key=out/'allowed.pub',policy=out/'policy.json',tool=tool)
        results=[]
        def attempt(name,expected,**changes):
            params=dict(base,store=out/'deployments'/name); params.update(changes)
            try:
                record=promote(**params); actual='allow'; reason=record
            except Rejected as e: actual='reject'; reason=str(e)
            results.append({'case':name,'expected':expected,'actual':actual,'reason':reason})
            assert actual==expected,results[-1]
            if actual=='reject': assert not (params['store']/'deployment.json').exists()
            return params
        good=attempt('valid','allow')
        answer=json.loads(consume(good['store'],['optimized','1','1','1','1','0','generated']))
        assert answer['values']==[99/64]
        write(out/'consumed.json',answer)
        attempt('idempotent','allow',store=good['store'])
        changed=out/'tampered.bin'; data=bytearray(artifact.read_bytes()); data[-1]^=1; changed.write_bytes(data)
        attempt('byte_tamper','reject',artifact=changed)
        attempt('tag_retarget_old_signature','reject',artifact=changed)
        attempt('unauthorized_key','reject',key=out/'foreign.pub')
        sign(out/'artifact.bin',out/'foreign-artifact.sig','foreign')
        sign(out/'provenance.json',out/'foreign-provenance.sig','foreign')
        write(out/'foreign-math-valid.json',verify_signature(tool,out/'foreign.pub',out/'foreign-artifact.sig',out/'artifact.bin',5))
        attempt('valid_math_unauthorized_signer','reject',key=out/'foreign.pub',artifact_signature=out/'foreign-artifact.sig',manifest_signature=out/'foreign-provenance.sig')
        attempt('wrong_signature','reject',artifact_signature=out/'foreign-artifact.sig')
        for name,field,value in [('provenance_mismatch','subject_sha256','0'*64),('wrong_builder','builder','local:unknown'),
                                ('unknown_algorithm','digest_algorithm','md5'),('unknown_format','signature_format','unknown'),
                                ('wrong_predicate','predicate_type','untrusted')]:
            m=dict(manifest); m[field]=value; mp=out/(name+'.json'); sp=out/(name+'.sig'); write(mp,m); sign(mp,sp)
            attempt(name,'reject',manifest=mp,manifest_signature=sp)
        corrupt=out/'corrupt.sig'; corrupt.write_text('not-base64')
        attempt('corrupt_signature','reject',artifact_signature=corrupt)
        attempt('verifier_crash','reject',tool=pathlib.Path('/bin/false'))
        sleeper=temp/'sleep-verifier'; sleeper.write_text('#!/bin/sh\nexec sleep 2\n'); sleeper.chmod(0o700)
        attempt('verifier_timeout','reject',tool=sleeper,timeout=.05)
        link=temp/'artifact-link'; link.symlink_to(out/'artifact.bin'); attempt('symlink_input','reject',artifact=link)
        # The consumer catches modifications after promotion, before execution.
        target=good['store']/'objects'/manifest['subject_sha256']; target.chmod(0o700); target.write_bytes(changed.read_bytes())
        try: consume(good['store'],['--version']); raise AssertionError('tampered deployment ran')
        except Rejected: results.append({'case':'post_promotion_tamper','expected':'reject','actual':'reject','reason':'consumer rehash before exec'})
        target.write_bytes(artifact.read_bytes()); target.chmod(0o500)
        write(out/'signing.json',signing); write(out/'matrix.json',results)
    # Binary artifacts are small and owned. Only public keys and signatures are retained.
    assert not list(out.rglob('*.key'))
    seal(ROOT,out,{'cosign':command([str(tool),'version']),'cosign_binary_sha256':digest(tool),
        'scope':'offline detached blob signatures; test-only ephemeral ECDSA key; transparency log deliberately excluded',
        'not_claimed':['keyless identity','registry/admission','vulnerability-free','SLSA level','power-loss atomicity'],
        'cases':len(results)})
    print(json.dumps({'matrix_cases':len(results),'all_expected':True,'consumed_values':answer['values']},indent=2))

if __name__=='__main__': main()
