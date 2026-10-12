#!/usr/bin/env python3
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
"""T081 command-boundary fixtures. No real daemon, credentials or network.

The subprocess runs the real driver/installer. Only external executables and
urllib's transport are replaced, inside an isolated copied source tree. Fixture
pins identify those recording executables; production has no test-mode switch.
Real Compose/OCI/crypto compatibility remains a separately required check.
"""
import copy
import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import tarfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[3]
C = "a" * 40
E = "b" * 40
VERSION = "v0.1.0"
SERVICES = ("stargate-dp", "stargate-control", "tor", "tor-observer")
REPOS = ("stargate-dp", "stargate-control", "stargate-tor", "stargate-tor-observer")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def write_json(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, sort_keys=True, separators=(",", ":")) + "\n")


def source_shape():
    # A deliberately narrow recording-parser fixture for THIS source YAML, not
    # a production YAML parser. Every current field feeds the topology assertions.
    lines = []
    for line in (ROOT / "compose/docker-compose.local.yml").read_text().splitlines():
        if line.strip() and not line.lstrip().startswith("#"):
            lines.append((len(line) - len(line.lstrip()), line.strip()))

    def scalar(s):
        if s in ("true", "false") or s.isdigit() or s.startswith('"'):
            return json.loads(s)
        return s

    def block(i, indent):
        result = [] if lines[i][1].startswith("- ") else {}
        while i < len(lines) and lines[i][0] == indent:
            text = lines[i][1]
            i += 1
            if isinstance(result, list):
                if not text.startswith("- "):
                    raise AssertionError("fixture parser needs updating")
                result.append(scalar(text[2:]))
            else:
                key, value = text.split(":", 1)
                if value.strip():
                    result[key] = scalar(value.strip())
                elif i < len(lines) and lines[i][0] > indent:
                    result[key], i = block(i, lines[i][0])
                else:
                    result[key] = None
        return result, i

    obj, end = block(0, 0)
    assert end == len(lines)
    return obj


RECORDER = r'''#!/usr/bin/python3
import hashlib,json,os,pathlib,shutil,sys,zipfile
root=pathlib.Path(os.environ['T081_FIXTURE'])
name=pathlib.Path(sys.argv[0]).name
args=sys.argv[1:]
with (root/'calls.jsonl').open('a') as f:f.write(json.dumps([name,*args])+'\n')
config=json.loads((root/'fixture.json').read_text())
if name=='id':print('1000');sys.exit(0)
if name=='timeout':sys.exit(0)
if name in ('sudo','iptables','ip6tables','apparmor_parser'):
 if config.get('host_ready') and name=='sudo':
  command=args[2:]
  if command[:1]==['cat']:print('yes');sys.exit(0)
  if command[:1]==['grep']:sys.exit(0)
  if command[:1]==['apparmor_parser']:
   if '-S' in command:print('without' if command[-1].endswith('without-denies') else 'with denies')
   sys.exit(0)
  if command[0] in ('iptables','ip6tables'):
   if '-C' in command and 'OUTPUT' in command:sys.exit(1)
   if '-S' in command:
    if command[-1]=='OUTPUT':print('-A OUTPUT -m owner --uid-owner 5102 -j STARGATE_DP_OUT')
    else:print('-A STARGATE_DP_OUT -o lo -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n-A STARGATE_DP_OUT -j DROP')
   sys.exit(0)
 sys.exit(73)
if name=='docker-compose':
 if 'config' in args:
  file=pathlib.Path(args[args.index('-f')+1])
  if file.name=='docker-compose.local.yml':print((root/'canonical.json').read_text())
  else:print(file.read_text())
  sys.exit(0)
 sys.exit(74)
if name=='cosign':
 if config.get('bad_signature'):sys.exit(9)
 if '--signing-config' in args:
  shutil.copyfile(args[args.index('--signing-config')+1],root/'observed-signing-config.json')
 if 'sign-blob' in args:
  pathlib.Path(args[args.index('--bundle')+1]).write_text('{"fixture":"bundle"}')
 print('Verified OK');sys.exit(0)
if name=='crane':
 if 'push' in args and config.get('push_failure'):sys.exit(8)
 print(args[-1].split('@')[-1]);sys.exit(0)
if name=='git':
 if args[:2]==['rev-parse','--show-toplevel']:print(root)
 elif args[:2]==['rev-parse','HEAD']:print(config.get('head','a'*40))
 elif args and args[0]=='rev-parse':print(config.get('tag','a'*40))
 elif args and args[0]=='status':print(' M scripts/release.py' if config.get('dirty') else '',end='')
 elif args[:2]==['ls-files','--others']:print('extra.py' if config.get('untracked') else '',end='')
 elif args and args[0]=='ls-tree':
  for p in sorted(root.rglob('*')):
   if p.is_file() and p.relative_to(root).as_posix().startswith(('scripts/','compose/')):
    b=p.read_bytes();oid=hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()
    mode='100755' if p.stat().st_mode & 0o111 else '100644'
    sys.stdout.buffer.write((mode+' blob '+oid+'\t'+p.relative_to(root).as_posix()).encode()+b'\0')
 elif args and args[0]=='hash-object':
  b=(root/args[-1]).read_bytes();print(hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest())
 elif args and args[0]=='diff':sys.exit(1 if config.get('dirty') else 0)
 elif args and args[0]=='archive':
  destination=next(a.split('=',1)[1] for a in args if a.startswith('--output='))
  shutil.copyfile(root/'retained/source.tar',destination)
 else:sys.exit(75)
 sys.exit(0)
if name=='go' and config.get('prepare_fixture'):
 if args==['version']:print('go version go1.26.3 linux/amd64');sys.exit(0)
 if args[:1]==['build']:
  pathlib.Path(args[args.index('-o')+1]).write_bytes(b'arm64-cross-only');sys.exit(0)
 sys.exit(77)
if name=='bash' and config.get('prepare_fixture') and args==['scripts/verify.sh']:
 (root/'verify-env.json').write_text(json.dumps({'BUILDX_BUILDER':os.environ.get('BUILDX_BUILDER'),
                                                 'DOCKER_CONFIG':os.environ.get('DOCKER_CONFIG')}))
 destination=root/'target/verify.log';destination.parent.mkdir(parents=True,exist_ok=True)
 destination.write_text('\n'.join('  [PASS] '+x for x in ('license-headers','ground-check','shell-quality','go-workspace','extension-tests','mvnw-verify'))+'\n')
 print('recorded verifier');sys.exit(0)
if name=='docker':
 if args[:2]==['context','show']:
  print(os.environ.get('DOCKER_CONTEXT',config.get('current_context','default')));sys.exit(0)
 if args[:2]==['context','inspect']:
  if config.get('malformed_context'):print('not-json');sys.exit(0)
  selected=os.environ.get('DOCKER_CONTEXT',config.get('current_context','default'))
  endpoint=config.get('endpoint','unix:///var/run/docker.sock')
  if selected!='default':endpoint=config.get('remote_endpoint','ssh://fixture.invalid/docker')
  elif os.environ.get('DOCKER_HOST'):endpoint=os.environ['DOCKER_HOST']
  print(json.dumps(endpoint));sys.exit(0)
 if args[:2]==['info','--format']:
  print(json.dumps(config.get('security_options',['name=seccomp,profile=builtin'])));sys.exit(0)
 if args[:2] in (['compose','version'],) or args==['info']:sys.exit(0)
 if config.get('observer_fixture'):
  if args[:1]==['build']:sys.exit(0)
  if args[:1]==['create']:
   count=sum(1 for line in (root/'calls.jsonl').read_text().splitlines() if json.loads(line)[:2]==['docker','create'])
   print('observer-fixture-'+str(count));sys.exit(0)
  if args[:1]==['cp']:
   number=int(args[1].split(':')[0].rpartition('-')[-1])
   pathlib.Path(args[2]).write_bytes(b'expected-observer' + (b'-changed' if config.get('observer_difference') and number==2 else b''))
   sys.exit(0)
  if args[:2] in (['rm',args[1] if len(args)>1 else ''],['image','rm']):sys.exit(0)
 # The old init ignores --release-dir and reaches this mutating stop call.
 if 'stop' in args:sys.exit(0)
 if config.get('package_fixture'):
  if args[:2]==['image','inspect']:print('sha256:'+'1'*64);sys.exit(0)
  if args[:2]==['image','rm']:sys.exit(1 if config.get('missing_tag_on_cleanup') else 0)
  if args[:1]==['run']:
   if 'sha256sum' in args:
    hashes={'/usr/bin/zip':'f718b59a4b1a647d2a9ce52fdec4011b626f581d5fd34ba598aae333611600ce',
            '/lib/x86_64-linux-gnu/libbz2.so.1.0.4':'e4f501c8bd22390e42422691093d8af4e744a3e854809b809948055e8b08bda5'}
    for path in args[args.index('sha256sum')+1:]:print(hashes[path]+'  '+path)
    sys.exit(0)
   mount=args[args.index('--mount')+1]
   source=pathlib.Path(next(v[4:] for v in mount.split(',') if v.startswith('src=')))
   output=source/'dist/stargate-extension.zip';output.parent.mkdir(exist_ok=True)
   with zipfile.ZipFile(output,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
    for p in sorted(source.rglob('*')):
     if not p.is_file() or 'dist' in p.relative_to(source).parts[:1] or p.name in ('package.sh','.keep'):continue
     info=zipfile.ZipInfo(p.relative_to(source).as_posix(),date_time=(1980,1,1,0,0,0));info.create_system=3;info.external_attr=0o100644<<16;info.compress_type=zipfile.ZIP_DEFLATED
     z.writestr(info,p.read_bytes(),compress_type=zipfile.ZIP_DEFLATED,compresslevel=9)
   sys.exit(0)
 if config.get('host_ready'):
  if args[:2]==['image','inspect']:sys.exit(0)
  if args[:2]==['volume','ls']:
   value=next(a for a in args if a.startswith('label=com.docker.compose.volume='))
   print('stargate_'+value.split('=')[-1]);sys.exit(0)
  if args[:2]==['volume','inspect']:
   print('local|tmpfs|tmpfs|size=64k,uid=5103,gid=5103,mode=0700,noexec,nosuid,nodev');sys.exit(0)
  if args[:1]==['run']:
   if 'n=0; for f in cp.priv' in args[-1]:print(config.get('key_count','6'))
   elif 'n=0; for f in observer.priv' in args[-1]:print('2')
   sys.exit(0)
  if args[:1]==['compose']:
   if 'ps' in args:print('container-'+args[-1]);sys.exit(0)
   if '--check-ready' in args:sys.exit(1 if config.get('observer_not_ready') else 0)
   if 'up' in args:sys.exit(0)
  if args[:1]==['inspect']:
   if 'State.Running' in args[2]:print('true')
   elif 'State.Health' in args[2]:print('none')
   elif 'NetworkMode' in args[2]:print('none')
   sys.exit(0)
 sys.exit(76)
if name=='docker-buildx' and (config.get('package_fixture') or config.get('prepare_fixture')):
 if args[:2]==['inspect','default']:
  print('Name: default\nDriver: '+('docker-container' if config.get('nonloading_default') else 'docker'))
  sys.exit(0)
 if config.get('package_build_failure') and 'build' in args:
  print('fixture primary build failure',file=sys.stderr);sys.exit(12)
 if '--metadata-file' in args:pathlib.Path(args[args.index('--metadata-file')+1]).write_text(json.dumps({'containerimage.config.digest':'sha256:'+'1'*64}))
 if config.get('prepare_fixture') and '--output' in args:
  recipe=args[args.index('--file')+1]
  service={'data-plane/Dockerfile':'stargate-dp','control-plane/Dockerfile':'stargate-control',
           'sidecars/tor/Dockerfile':'tor','sidecars/tor-observer/Dockerfile':'tor-observer'}[recipe]
  destination=pathlib.Path(next(v[5:] for v in args[args.index('--output')+1].split(',') if v.startswith('dest=')))
  source=root/'retained/oci'/service
  if config.get('different_second_image') and service=='stargate-dp':
   builds=[json.loads(line) for line in (root/'calls.jsonl').read_text().splitlines()]
   if sum('data-plane/Dockerfile' in row for row in builds)==2:source=root/'alternate-dp'
  shutil.copytree(source,destination)
 sys.exit(0)
sys.exit(77)
'''

BOOTSTRAP = r'''
import base64,datetime,hashlib,importlib.util,io,json,os,pathlib,sys,urllib.request,urllib.error
root=pathlib.Path(os.environ['T081_FIXTURE'])
spec=importlib.util.spec_from_file_location('release',root/'scripts/release.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
fixture=json.loads((root/'transport.json').read_text())
m.now=lambda:datetime.datetime.fromisoformat(fixture['now'].replace('Z','+00:00'))
class Response(io.BytesIO):
 def __init__(self,data,headers=None,status=200):
  super().__init__(data);self.headers=headers or {};self.status=status
seen={}
def urlopen(request,**kw):
 url=request.full_url
 with (root/'http.jsonl').open('a') as f:f.write(json.dumps([request.get_method(),url])+'\n')
 if request.get_method() in ('POST','PATCH') and '/assets?' not in url and hasattr(request,'data') and request.data:
  with (root/'http-bodies.jsonl').open('a') as f:f.write(json.dumps([url,request.data.decode()])+'\n')
 if url=='https://api.github.com/graphql':
  with (root/'graphql.jsonl').open('a') as f:f.write(request.data.decode()+'\n')
 if url.startswith('https://uploads.github.com/repos/zcat-app/stargate/releases/99/assets?name='):
  if fixture.get('upload_failure'):raise urllib.error.HTTPError(url,500,'fixture upload failure',{},None)
  data=request.data.read() if hasattr(request.data,'read') else request.data
  name=url.rsplit('name=',1)[1]
  if name in ('candidate.json','release.json'):(root/('uploaded-'+name)).write_bytes(data)
  return Response(json.dumps({'state':'uploaded','size':len(data),'digest':'sha256:'+hashlib.sha256(data).hexdigest()}).encode())
 if fixture.get('row_shift') and '/releases?per_page=100&page=' in url:
  page=int(url.rsplit('page=',1)[1]); rows=fixture['row_shift']
  if page==2 and not seen.get('shifted'):
   rows.pop(0);seen['shifted']=True
  value={'__value':rows[(page-1)*100:page*100]}
  if page==1:value['__headers']={'Link':'<https://api.github.com/repos/zcat-app/stargate/releases?per_page=100&page=2>; rel="next"'}
  return Response(json.dumps(value['__value']).encode(),value.get('__headers'))
 if url not in fixture['responses']:
  raise AssertionError('unrecorded network: '+url)
 else:value=fixture['responses'][url]
 if isinstance(value,dict) and '__sequence' in value:
  index=seen.get(url,0);seen[url]=index+1
  value=value['__sequence'][min(index,len(value['__sequence'])-1)]
 if isinstance(value,dict) and '__status' in value:raise urllib.error.HTTPError(url,value['__status'],'fixture refusal',{},None)
 if isinstance(value,dict) and '__bytes' in value:return Response(base64.b64decode(value['__bytes']))
 if isinstance(value,dict) and '__value' in value:
  return Response(json.dumps(value['__value']).encode(),value.get('__headers'),value.get('__http_status',200))
 return Response(json.dumps(value).encode())
urllib.request.urlopen=urlopen
class Opener:
 def open(self,request,**kw):return urlopen(request,**kw)
urllib.request.build_opener=lambda *args:Opener()
sys.argv=['release.py',*sys.argv[1:]]
try:m.main()
except (m.Refusal,OSError,ValueError,KeyError,TypeError) as e:
 print('release: refusing: '+str(e),file=sys.stderr);sys.exit(1)
'''


class Fixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="stargate-t081-fixture-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for relative in ("scripts/stargate", "scripts/subcommands/init", "scripts/lib/compose.sh",
                         "compose/docker-compose.local.yml", "compose/apparmor/stargate-dp",
                         "specs/001-tor-route/live-e2e/README.md",
                         "scripts/release.py", "scripts/release/inputs.json",
                         "scripts/release/extension.Dockerfile"):
            source = ROOT / relative
            if source.exists():
                target = self.root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, target)
        (self.root / "bin").mkdir()
        (self.root / "target/release-tools").mkdir(parents=True)
        for name in ("docker", "git", "id", "sudo", "iptables", "ip6tables", "apparmor_parser", "timeout"):
            self.executable(self.root / "bin" / name, RECORDER)
        for name in ("docker-compose", "docker-buildx", "cosign", "crane"):
            self.executable(self.root / "target/release-tools" / name, RECORDER)
        self.config = {}
        self.shape = source_shape()
        self.images = {s: "ghcr.io/zcat-app/" + r + "@sha256:" + str(i + 1) * 64
                       for i, (s, r) in enumerate(zip(SERVICES, REPOS))}
        write_json(self.root / "canonical.json", self.shape)
        write_json(self.root / "images.json", self.images)
        self.env = {k: v for k, v in os.environ.items()
                    if not k.startswith(("STARGATE_", "COMPOSE_", "DOCKER_", "GITHUB_", "ACTIONS_"))}
        self.env.update(PATH=str(self.root / "bin") + ":" + os.environ.get("PATH", "/usr/bin:/bin"),
                        T081_FIXTURE=str(self.root), STARGATE_ENV_FILE=str(self.root / "local.env"))
        pins = self.root / "scripts/release/inputs.json"
        if pins.exists():
            self.pins = json.loads(pins.read_text())
            for name, record in self.pins["tools"].items():
                if name == "trusted-root":
                    data = b'{"fixture":"trusted-root"}\n'
                    (self.root / "target/release-tools/trusted-root.json").write_bytes(data)
                else:
                    data = RECORDER.encode()
                record["installed_sha256"] = sha(data)
            write_json(pins, self.pins)

    @staticmethod
    def executable(path, text):
        path.write_text(text)
        path.chmod(0o755)

    def invoke(self, *args, init=False, env=None):
        write_json(self.root / "fixture.json", self.config)
        command = (["bash", str(self.root / "scripts/stargate"), "init"] if init
                   else [sys.executable, str(self.root / "scripts/release.py")])
        return subprocess.run([*command, *map(str, args)], cwd=self.root,
                              env=self.env | (env or {}), text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)

    def calls(self):
        p = self.root / "calls.jsonl"
        return [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []

    def with_transport(self, *args):
        write_json(self.root / "fixture.json", self.config)
        write_json(self.root / "transport.json", self.transport)
        bootstrap = self.root / "bootstrap.py"
        bootstrap.write_text(BOOTSTRAP)
        return subprocess.run([sys.executable, "-B", str(bootstrap), *map(str, args)],
                              cwd=self.root, env=self.env, text=True, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=15)

    def assertNoMutation(self):
        forbidden = {"stop", "up", "build", "run", "volume", "push", "sign", "sign-blob"}
        mutations = [call for call in self.calls()
                     if call[0] in {"sudo", "iptables", "ip6tables", "apparmor_parser"}
                     or forbidden.intersection(call[1:])]
        self.assertEqual(mutations, [], "invalid data reached a host/daemon/signing mutation")
        self.assertFalse((self.root / "local.env").exists(), "invalid data created installer state")

    def release(self):
        directory = self.root / "release"
        generated = copy.deepcopy(self.shape)
        for name, service in generated["services"].items():
            service["image"] = self.images[name]
            service.pop("build", None)
            if service.get("pull_policy") == "build":
                del service["pull_policy"]
        write_json(directory / "compose.json", generated)
        manifest = {"schema": 1, "version": VERSION, "channel": "feature-preview", "source": C,
                    "platform": "linux/amd64", "images": self.images,
                    "compose_sha256": sha((directory / "compose.json").read_bytes()),
                    "source_files": {p.relative_to(self.root).as_posix(): {"sha256": sha(p.read_bytes()), "mode": "100755" if p.stat().st_mode & 0o111 else "100644"}
                                     for d in ("scripts", "compose")
                                     for p in (self.root / d).rglob("*") if p.is_file()},
                    "artifacts": {}, "pack_sha256": "c" * 64}
        write_json(directory / "release.json", manifest)
        write_json(directory / "release.sigstore.json", {"fixture": "bundle"})
        return directory, manifest


class InitTests(Fixture):
    def test_release_manifest_requires_feature_preview_channel(self):
        for channel in (None, "stable", "feature-preview-v2"):
            with self.subTest(channel=channel):
                directory, manifest = self.release()
                if channel is None:
                    del manifest["channel"]
                else:
                    manifest["channel"] = channel
                write_json(directory / "release.json", manifest)
                result = self.invoke("verify-install", "--release-dir", directory)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("release: refusing:", result.stderr)
                self.assertNoMutation()

    def test_remote_or_malformed_docker_endpoint_refuses_before_any_mutation(self):
        cases=(("host",{"DOCKER_HOST":"tcp://192.0.2.2:2375"},{}),
               ("context",{"DOCKER_CONTEXT":"remote"},{}),
               ("stored-context",{}, {"current_context":"remote"}),
               ("alternate-unix",{"DOCKER_HOST":"unix:///tmp/docker.sock"},{}),
               ("malformed",{}, {"malformed_context":True}),
               ("rootless",{}, {"security_options":["name=rootless"]}))
        for release_mode in (False,True):
            for label,env,config in cases:
                with self.subTest(release=release_mode,case=label):
                    (self.root/"calls.jsonl").unlink(missing_ok=True)
                    self.config=config.copy()
                    directory=self.release()[0] if release_mode else None
                    args=("--release-dir",directory) if release_mode else ()
                    result=self.invoke(*args,init=True,env=env)
                    self.assertEqual(result.returncode,10,result.stderr)
                    self.assertNoMutation()

    def test_supported_local_docker_socket_reaches_existing_host_boundary(self):
        for endpoint in ("unix:///var/run/docker.sock","unix:///run/docker.sock"):
            with self.subTest(endpoint=endpoint):
                (self.root/"calls.jsonl").unlink(missing_ok=True)
                result=self.invoke(init=True,env={"DOCKER_HOST":endpoint})
                self.assertEqual(result.returncode,60,result.stderr)
                self.assertTrue(any("stop" in row for row in self.calls()))

    def test_complete_release_init_preserves_keys_and_checks_authenticated_readiness(self):
        directory, _ = self.release()
        self.config["host_ready"] = True
        result = self.invoke("--release-dir", directory, init=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("preserving keys and pepper", result.stderr)
        calls = self.calls()
        up = next(c for c in calls if c[0] == "docker" and "up" in c)
        self.assertIn("--no-build", up)
        self.assertFalse(any("build" in c or "--build" in c for c in calls))
        self.assertTrue(any("--check-ready" in c for c in calls))
        self.assertFalse(any(c[0] == "openssl" for c in calls))
        self.assertLess(next(i for i,c in enumerate(calls) if "stop" in c), calls.index(up))

    def test_release_partial_keys_and_unready_observer_still_refuse(self):
        for mutation, code in (("key_count", 20), ("observer_not_ready", 40)):
            with self.subTest(mutation=mutation):
                self.config = {"host_ready": True, mutation: "4" if mutation == "key_count" else True}
                directory, _ = self.release()
                result = self.invoke("--release-dir", directory, init=True, env={"STARGATE_HEALTHCHECK_TIMEOUT": "2"})
                self.assertEqual(result.returncode, code, result.stderr)

    def test_verified_release_reaches_same_host_boundary_without_build(self):
        directory, _ = self.release()
        result = self.invoke("--release-dir", directory, init=True)
        self.assertEqual(result.returncode, 60, result.stderr)
        self.assertTrue(any("stop" in call for call in self.calls()))
        self.assertFalse(any("build" in call or "--build" in call for call in self.calls()))
        verify = next(call for call in self.calls() if call[:2] == ["cosign", "verify-blob"])
        self.assertIn("--certificate-identity", verify)
        self.assertIn("https://github.com/zcat-app/stargate/.github/workflows/release.yml@refs/tags/" + VERSION, verify)
        self.assertIn("--certificate-github-workflow-sha", verify)
        self.assertIn(C, verify)
        stop = next(call for call in self.calls() if "stop" in call)
        selected = Path(stop[stop.index("-f") + 1])
        self.assertNotEqual(selected, directory / "compose.json", "installer reopens mutable release input after validation")
        self.assertFalse(selected.exists(), "private verified snapshot was not cleaned up")

    def test_release_refusals_precede_mutation(self):
        for mutation in ("source", "tag", "dirty", "untracked", "signature", "topology", "compose-hash", "source-file", "extra-field"):
            with self.subTest(mutation=mutation):
                self.config = {}
                (self.root / "calls.jsonl").unlink(missing_ok=True)
                directory, manifest = self.release()
                if mutation == "source": self.config["head"] = "d" * 40
                elif mutation == "tag": self.config["tag"] = "d" * 40
                elif mutation in ("dirty", "untracked"): self.config[mutation] = True
                elif mutation == "signature": self.config["bad_signature"] = True
                elif mutation == "topology":
                    shape = json.loads((directory / "compose.json").read_text())
                    shape["services"]["stargate-dp"]["privileged"] = True
                    write_json(directory / "compose.json", shape)
                    manifest["compose_sha256"] = sha((directory / "compose.json").read_bytes())
                elif mutation == "compose-hash": manifest["compose_sha256"] = "0" * 64
                elif mutation == "source-file": manifest["source_files"]["scripts/subcommands/init"] = "0" * 64
                else: manifest["command"] = "accept"
                write_json(directory / "release.json", manifest)
                result = self.invoke("--release-dir", directory, init=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertNoMutation()

    def test_release_override_refuses(self):
        directory, _ = self.release()
        for name in ("STARGATE_COMPOSE_FILE", "STARGATE_OBSERVER_IMAGE", "COMPOSE_FILE", "STARGATE_KEYGEN_IMAGE"):
            with self.subTest(name=name):
                result = self.invoke("--release-dir", directory, init=True, env={name: "hostile"})
                self.assertNotEqual(result.returncode, 0)
                self.assertNoMutation()

    def test_invalid_release_precedes_mutation(self):
        result = self.invoke("--release-dir", self.root / "absent", init=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertNoMutation()

    def test_unknown_argument_precedes_mutation(self):
        result = self.invoke("--release-dri", self.root / "absent", init=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertNoMutation()

    def test_missing_and_repeated_argument_refuse(self):
        for args in (("--release-dir",), ("--release-dir", "x", "--release-dir", "y")):
            with self.subTest(args=args):
                result = self.invoke(*args, init=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertNoMutation()

    def test_default_init_still_reaches_mandatory_host_boundary(self):
        result = self.invoke(init=True)
        self.assertEqual(result.returncode, 60, result.stderr)
        self.assertTrue(any("stop" in call for call in self.calls()))
        self.assertFalse(any("up" in call for call in self.calls()))


class DriverTests(Fixture):
    def test_real_git_crlf_checkout_matches_canonical_archive_and_rejects_tamper(self):
        repo=self.root/"crlf-git"
        (repo/"scripts").mkdir(parents=True)
        shutil.copy2(ROOT/"scripts/release.py",repo/"scripts/release.py")
        (repo/".gitattributes").write_text("*.cmd text eol=crlf\n")
        file=repo/"script.cmd"
        file.write_bytes(b"alpha\r\nbeta\r\n")
        def git(*args):
            return subprocess.check_output(["git",*args],cwd=repo,stderr=subprocess.DEVNULL).decode().strip()
        git("init");git("config","user.email","fixture@example.invalid");git("config","user.name","T081 fixture")
        git("add",".");git("commit","-qm","CRLF source");source=git("rev-parse","HEAD");git("tag",VERSION)
        self.assertEqual(file.read_bytes(),b"alpha\r\nbeta\r\n")
        spec=importlib.util.spec_from_file_location("crlf_release",repo/"scripts/release.py")
        module=importlib.util.module_from_spec(spec)
        old=sys.dont_write_bytecode;sys.dont_write_bytecode=True
        try:spec.loader.exec_module(module)
        finally:sys.dont_write_bytecode=old
        self.assertEqual(git("status","--porcelain"),"")
        manifest=module.source_identity(source,VERSION)
        self.assertEqual(manifest["script.cmd"]["sha256"],sha(b"alpha\r\nbeta\r\n"))
        archive=self.root/"crlf-source.tar"
        git("archive","--format=tar","--output="+str(archive),source)
        module.verify_source_archive(archive,manifest)
        git("update-index","--assume-unchanged","script.cmd")
        file.write_bytes(b"changed\r\nbeta\r\n")
        self.assertEqual(git("status","--porcelain"),"")
        with self.assertRaises(module.Refusal):module.source_identity(source,VERSION)
        file.write_bytes(b"alpha\r\nbeta\r\n")
        git("update-index","--no-assume-unchanged","script.cmd")
        git("config","core.filemode","false")
        file.chmod(0o755)
        self.assertEqual(git("status","--porcelain"),"")
        with self.assertRaises(module.Refusal):module.source_identity(source,VERSION)

    def test_real_git_filemode_false_cannot_hide_executable_drift(self):
        repo = self.root / "real-git"
        (repo / "scripts").mkdir(parents=True)
        shutil.copy2(ROOT / "scripts/release.py", repo / "scripts/release.py")
        payload = repo / "payload"
        payload.write_text("reviewed bytes\n")
        payload.chmod(0o644)
        def git(*args):
            return subprocess.check_output(["git", *args], cwd=repo, stderr=subprocess.DEVNULL).decode().strip()
        git("init")
        git("config", "user.email", "fixture@example.invalid")
        git("config", "user.name", "T081 fixture")
        git("add", ".")
        git("commit", "-qm", "fixture source")
        source = git("rev-parse", "HEAD")
        git("tag", VERSION)
        git("config", "core.filemode", "false")
        spec = importlib.util.spec_from_file_location("fixture_release", repo / "scripts/release.py")
        module = importlib.util.module_from_spec(spec)
        # Avoid introducing import bytecode in the candidate source tree.
        old = sys.dont_write_bytecode
        sys.dont_write_bytecode = True
        try: spec.loader.exec_module(module)
        finally: sys.dont_write_bytecode = old
        before = module.source_identity(source, VERSION)
        payload.chmod(0o755)
        self.assertEqual(git("status", "--porcelain"), "")
        with self.assertRaises(module.Refusal): module.source_identity(source, VERSION)
        self.assertEqual(before["payload"]["mode"], "100644")

    def compose(self):
        return self.invoke("compose", "--images", self.root / "images.json",
                           "--output", self.root / "compose.json")

    def test_generated_compose_preserves_actual_source_topology(self):
        before = (self.root / "compose/docker-compose.local.yml").read_bytes()
        result = self.compose()
        self.assertEqual(result.returncode, 0, result.stderr)
        generated = json.loads((self.root / "compose.json").read_text())
        expected = copy.deepcopy(self.shape)
        for name, service in expected["services"].items():
            service["image"] = self.images[name]
            service.pop("build", None)
            if service.get("pull_policy") == "build":
                del service["pull_policy"]
        self.assertEqual(generated, expected)
        self.assertEqual((self.root / "compose/docker-compose.local.yml").read_bytes(), before)
        self.assertNoMutation()

    def test_service_add_remove_mutable_reference_and_relative_mount_refuse(self):
        for mutation in ("extra", "missing", "mutable", "relative-mount"):
            with self.subTest(mutation=mutation):
                shape = copy.deepcopy(self.shape)
                images = self.images.copy()
                if mutation == "extra":
                    shape["services"]["socket-proxy"] = {"image": "evil"}
                elif mutation == "missing":
                    del shape["services"]["tor-observer"]
                elif mutation == "mutable":
                    images["tor"] = "ghcr.io/zcat-app/stargate-tor:latest"
                else:
                    shape["services"]["tor"]["volumes"].append("../keys:/keys")
                write_json(self.root / "canonical.json", shape)
                write_json(self.root / "images.json", images)
                result = self.compose()
                self.assertNotEqual(result.returncode, 0)
                self.assertNoMutation()

    def test_duplicate_and_unknown_image_entries_refuse(self):
        p = self.root / "images.json"
        p.write_text('{"tor":"a","tor":"b"}')
        self.assertNotEqual(self.compose().returncode, 0)
        write_json(p, self.images | {"evil": self.images["tor"]})
        self.assertNotEqual(self.compose().returncode, 0)
        self.assertNoMutation()

    def test_tampered_parser_refuses_before_execution(self):
        p = self.root / "target/release-tools/docker-compose"
        p.write_text(RECORDER + "\n# changed\n")
        result = self.compose()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.calls(), [])


class EvidenceTests(Fixture):
    def setUp(self):
        super().setUp()
        self.make_evidence({"source": C, "version": VERSION,
                            "artifacts": {"stargate-proxy-linux-amd64": {"sha256": "3" * 64, "size": 10}}})

    def make_evidence(self, candidate):
        self.evidence = self.root / "evidence"
        self.evidence.mkdir(exist_ok=True)
        self.candidate = candidate
        write_json(self.root / "candidate.json", self.candidate)
        tracker = (self.root / "specs/001-tor-route/live-e2e/README.md").read_bytes()
        self.rows = {}
        for line in tracker.decode().splitlines():
            if line.startswith("| F") or line.startswith("| R-"):
                self.rows[line.split("|")[1].strip()] = sha(line.encode())
        self.reports = {}
        for name in ("T078", "T079", "external-human"):
            report = name + ".txt"
            (self.evidence / report).write_text("Fixture report body and provenance; not a real review.\n")
            self.reports[name + ".json"] = {"schema": 1, "source": C, "status": "PASS",
                "reviewer": "fixture-reviewer", "observed_at": "2026-10-11T12:00:00Z", "report": report,
                "independent": True, "human": name == "external-human"}
        observations = {}
        for name in ["F1", "F2", "F3", "F4", "F5", "F7", *["R-" + str(i) for i in range(1, 9)]]:
            report = name + ".txt"
            (self.evidence / report).write_text("Fixture observations, controls, provenance and limits for " + name + "\n")
            observations[name] = {"status": "PASS", "scope": "exercised", "report": report,
                                  "contract_sha256": self.rows[name],
                                  "artifact_sha256": {k: v["sha256"] for k, v in self.candidate["artifacts"].items()}}
            if name == "R-7":
                observations[name]["coverage"] = {x: "PASS" for x in ("routed-ipv6", "lan", "vps", "physical-nic", "hypervisor")}
        self.reports["live.json"] = {"schema": 1, "source": C, "version": VERSION,
            "tracker_sha256": sha(tracker), "observations": observations}

    def check(self):
        for name, report in self.reports.items(): write_json(self.evidence / name, report)
        index = {"schema": 1, "source": C, "version": VERSION,
                 "candidate_sha256": sha((self.root / "candidate.json").read_bytes()),
                 "files": {p.name: {"sha256": sha(p.read_bytes()), "size": p.stat().st_size}
                           for p in self.evidence.iterdir() if p.name != "index.json"}}
        write_json(self.evidence / "index.json", index)
        return self.invoke("check-evidence", "--candidate", self.root / "candidate.json", "--evidence-dir", self.evidence)

    def test_complete_data_pack_validates_but_does_not_publish(self):
        result = self.check()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNoMutation()

    def test_missing_r7_unsupported_and_r2_substitution_refuse(self):
        original = copy.deepcopy(self.reports)
        for mutation in ("missing", "unsupported", "na", "r2", "partial"):
            with self.subTest(mutation=mutation):
                self.reports = copy.deepcopy(original)
                obs = self.reports["live.json"]["observations"]
                if mutation == "missing": del obs["R-7"]
                elif mutation == "unsupported": obs["R-7"]["scope"] = "unsupported"
                elif mutation == "na": obs["R-7"]["status"] = "N/A"
                elif mutation == "r2": obs["R-7"] = copy.deepcopy(obs["R-2"])
                else: del obs["R-7"]["coverage"]["hypervisor"]
                result = self.check()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("release: refusing:", result.stderr)
                self.assertNoMutation()


    def test_stale_review_tracker_skipped_and_absent_report_refuse(self):
        original = copy.deepcopy(self.reports)
        for mutation in ("review-source", "review-skip", "tracker", "live-skip", "body", "self-asserted-approval"):
            with self.subTest(mutation=mutation):
                self.reports = copy.deepcopy(original)
                if mutation == "review-source": self.reports["T078.json"]["source"] = E
                elif mutation == "review-skip": self.reports["T079.json"]["status"] = "SKIP"
                elif mutation == "tracker": self.reports["live.json"]["tracker_sha256"] = "0" * 64
                elif mutation == "live-skip": self.reports["live.json"]["observations"]["F1"]["status"] = "SKIP"
                elif mutation == "body": self.reports["T078.json"]["report"] = "missing.txt"
                else: self.reports["external-human.json"]["approved"] = True
                result = self.check()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("release: refusing:", result.stderr)
                self.assertNoMutation()


class PromotionPolicyTests(Fixture):
    def setUp(self):
        super().setUp()
        self.make_policy()

    def make_policy(self):
        self.pack = {"source": C, "version": VERSION, "evidence_commit": E,
                     "artifact_id": 42, "prepare_run_id": 7, "prepare_run_attempt": 1}
        write_json(self.root / "pack.json", self.pack)
        binding = "Approve Stargate pack " + sha((self.root / "pack.json").read_bytes()) + " source " + C + " evidence " + E + " artifact 42 prepare 7/1"
        self.policy = {"id": 5, "name": "stargate-release", "can_admins_bypass": False,
                       "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True},
                       "protection_rules": [{"type": "required_reviewers", "prevent_self_review": True,
                                             "reviewers": [{"type": "User", "reviewer": {"id": 33, "login": "carol"}}]}]}
        self.approvals = [{"state": "approved", "user": {"id": 33, "login": "carol"},
                           "environments": [{"id": 5, "name": "stargate-release"}], "comment": binding}]
        self.transport = {"now": "2026-10-11T13:00:00Z", "responses": {
            "https://api.github.com/repos/zcat-app/stargate/environments/stargate-release": self.policy,
            "https://api.github.com/repos/zcat-app/stargate/environments/stargate-release/deployment-branch-policies?per_page=100":
                {"total_count": 1, "branch_policies": [{"type": "tag", "name": "v*"}]},
            "https://api.github.com/repos/zcat-app/stargate/actions/runs/9/approvals": self.approvals}}
        self.env.update(GITHUB_TOKEN="fixture-token", GITHUB_ACTOR="alice", GITHUB_TRIGGERING_ACTOR="bob",
                        GITHUB_RUN_ID="9", GITHUB_REPOSITORY="zcat-app/stargate")

    def check(self):
        return self.with_transport("check-policy", "--pack", self.root / "pack.json", "--approved")

    def test_exact_protected_approval_is_read_only(self):
        result = self.check()
        self.assertEqual(result.returncode, 0, result.stderr)

        self.assertNoMutation()
        self.assertTrue(all(json.loads(x)[0] == "GET" for x in (self.root / "http.jsonl").read_text().splitlines()))

    def test_absent_unsafe_policy_and_forged_approval_refuse(self):
        original = copy.deepcopy(self.transport)
        for mutation in ("missing-bypass", "bypass", "self-review", "no-reviewers", "branch", "self-approval", "wrong-pack", "wrong-environment", "unconfigured-reviewer"):
            with self.subTest(mutation=mutation):
                self.transport = copy.deepcopy(original)
                policy = self.transport["responses"]["https://api.github.com/repos/zcat-app/stargate/environments/stargate-release"]
                approval = self.transport["responses"]["https://api.github.com/repos/zcat-app/stargate/actions/runs/9/approvals"][0]
                if mutation == "missing-bypass": del policy["can_admins_bypass"]
                elif mutation == "bypass": policy["can_admins_bypass"] = True
                elif mutation == "self-review": policy["protection_rules"][0]["prevent_self_review"] = False
                elif mutation == "no-reviewers": policy["protection_rules"][0]["reviewers"] = []
                elif mutation == "branch": policy["deployment_branch_policy"]["protected_branches"] = True
                elif mutation == "self-approval": approval["user"]["login"] = "alice"
                elif mutation == "wrong-pack": approval["comment"] = "approved"
                elif mutation == "wrong-environment": approval["environments"][0]["id"] = 77
                else: approval["user"]["id"] = 45
                result = self.check()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("release: refusing:", result.stderr)
                self.assertNoMutation()

    def test_expired_selection_refuses_new_approval_but_install_does_not_expire(self):
        self.transport["now"] = "2026-10-18T01:48:18Z"
        result = self.check()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("stale", result.stderr)
        directory, _ = self.release()
        result = self.with_transport("verify-install", "--release-dir", directory)
        self.assertEqual(result.returncode, 0, result.stderr)




class ArchiveTests(Fixture):
    def extract(self, entries, *, digest_override=None):
        archive = self.root / "artifact.zip"
        with zipfile.ZipFile(archive, "w") as z:
            for name, data in entries: z.writestr(name, data)
        return self.invoke("extract-artifact", "--archive", archive, "--sha256",
                           digest_override or sha(archive.read_bytes()), "--output", self.root / "unpacked")

    def test_exact_archive_extracts_without_execution(self):
        result = self.extract([("candidate.json", b"{}\n"), ("oci/tor/index.json", b"{}\n")])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / "unpacked/oci/tor/index.json").read_bytes(), b"{}\n")
        self.assertNoMutation()

    def test_traversal_duplicate_link_and_wrong_archive_hash_refuse(self):
        link = zipfile.ZipInfo("link")
        link.create_system = 3
        link.external_attr = (0o120777 << 16)
        for entries, wrong in (([("../escape", b"x")], None), ([("/absolute", b"x")], None),
                               ([("same", b"1"), ("same", b"2")], None), ([(link, b"/tmp")], None),
                               ([("fine", b"x")], "0" * 64)):
            with self.subTest(entries=entries):
                result = self.extract(entries, digest_override=wrong)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("release: refusing:", result.stderr)
                self.assertFalse((self.root / "unpacked").exists())
                self.assertNoMutation()

    def test_insufficient_disk_refuses_before_extract_directory(self):
        archive = self.root / "artifact.zip"
        with zipfile.ZipFile(archive, "w") as z: z.writestr("payload", b"payload")
        self.transport = {"now": "2026-10-11T13:00:00Z", "responses": {}}
        write_json(self.root / "fixture.json", self.config)
        write_json(self.root / "transport.json", self.transport)
        bootstrap = self.root / "disk-bootstrap.py"
        bootstrap.write_text(BOOTSTRAP.replace("try:m.main()", "m.shutil.disk_usage=lambda p:type('Disk',(),{'free':0})()\ntry:m.main()"))
        result = subprocess.run([sys.executable, "-B", str(bootstrap), "extract-artifact", "--archive", str(archive),
                                 "--sha256", sha(archive.read_bytes()), "--output", str(self.root / "unpacked")],
                                cwd=self.root, env=self.env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("disk", result.stderr)
        self.assertFalse((self.root / "unpacked").exists())


class VerifyGateTests(Fixture):
    def setUp(self):
        super().setUp()
        self.log = self.root / "verify.log"
        self.base = "\n".join("  [PASS] " + x for x in ("license-headers", "ground-check", "shell-quality", "go-workspace", "extension-tests", "mvnw-verify")) + "\n"

    def check(self, text):
        self.log.write_text(text)
        return self.invoke("check-verify", "--log", self.log)

    def test_real_gate_accounting_accepts_only_complete_pass(self):
        result = self.check(self.base)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), [])

    def test_required_gate_skip_missing_duplicate_and_hidden_test_skip_refuse(self):
        for value in (self.base.replace("[PASS] ground-check", "[SKIP] ground-check"),
                      self.base.replace("  [PASS] mvnw-verify\n", ""),
                      self.base + "  [PASS] ground-check\n",
                      self.base + "    test SKIP: github.com/zcat-app/stargate/data-plane/internal/route.TestRequired — unavailable\n"):
            result = self.check(value)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("release: refusing:", result.stderr)

    def test_named_live_cadence_is_pending_not_pass(self):
        file = self.root / "tests/contract/compose/operational_logs_test.sh"
        file.parent.mkdir(parents=True)
        file.write_text("# fixture gate inventory\n")
        result = self.check(self.base + "  [SKIP] contract:operational_logs_test.sh — Docker operational capture; set STARGATE_TEST_TAGS=docker\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), [{"check": "contract:operational_logs_test.sh", "evidence": "F2"}])
        result = self.check(self.base + "  [SKIP] contract:operational_logs_test.sh — docker unavailable\n")
        self.assertNotEqual(result.returncode, 0)

    def test_only_java_owned_go_fixtures_may_skip_under_passed_maven_gate(self):
        fixture = ("    test SKIP: github.com/zcat-app/stargate/data-plane/cmd/tor-observer.TestJavaClientInteropFixture"
                   " — launched by the Java observer client contract test\n"
                   "    test SKIP: github.com/zcat-app/stargate/data-plane/internal/controlclient.TestJavaReloadInteropFixture"
                   " — fixture mode requires T159_JAVA_INTEROP_DIR\n")
        self.assertEqual(self.check(self.base+fixture).returncode,0)
        self.assertNotEqual(self.check(self.base.replace("[PASS] mvnw-verify","[SKIP] mvnw-verify")+fixture).returncode,0)
        self.assertNotEqual(self.check(self.base+fixture.replace("JavaReloadInteropFixture","OtherFixture")).returncode,0)


class OCITests(Fixture):
    def layout(self, mutation=None, *, layout=None, files=None):
        layout = layout or self.root / "layout"
        (layout / "blobs/sha256").mkdir(parents=True, exist_ok=True)
        def blob(data, media):
            data = canonical_fixture(data) if isinstance(data, dict) else data
            (layout / "blobs/sha256" / sha(data)).write_bytes(data)
            return {"mediaType": media, "digest": "sha256:" + sha(data), "size": len(data)}
        config = blob({"architecture": "arm64" if mutation == "platform" else "amd64", "os": "linux",
                       "config": {"Labels": {"org.opencontainers.image.revision": C}}}, "application/vnd.oci.image.config.v1+json")
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            for name, data in (files or {"opt/stargate/stargate-proxy": b"binary!"}).items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                info.mode = 0o644
                tar.addfile(info, io.BytesIO(data))
        layer = blob(buf.getvalue(), "application/vnd.oci.image.layer.v1.tar+gzip")
        manifest = blob({"schemaVersion": 2, "config": config, "layers": [layer]}, "application/vnd.oci.image.manifest.v1+json")
        manifest["platform"] = {"os": "linux", "architecture": "amd64"}
        attestations = []
        for predicate in ("https://spdx.dev/Document", "https://slsa.dev/provenance/v1"):
            if mutation == "missing-provenance" and "slsa" in predicate: continue
            provenance={"buildDefinition": {
                "buildType": "https://github.com/moby/buildkit/blob/master/docs/attestations/slsa-definitions.md",
                "externalParameters": {"configSource": {"path": "Dockerfile"},
                    "request": {"frontend": "dockerfile.v0", "locals": [{"name": "context"}, {"name": "dockerfile"}],
                        "args": {"label:org.opencontainers.image.revision": C},
                        "root": {"request": {"args": {"vcs:revision": C}}}}},
                "resolvedDependencies": []},
                "runDetails": {"metadata": {"buildkit_metadata": {"vcs": {"revision": C}}}}}
            if mutation == "wrong-vcs-revision":
                provenance["buildDefinition"]["externalParameters"]["request"]["root"]["request"]["args"]["vcs:revision"] = "d" * 40
                provenance["note"] = C
            elif mutation == "missing-vcs-revision":
                del provenance["buildDefinition"]["externalParameters"]["request"]["root"]["request"]["args"]["vcs:revision"]
            elif mutation == "wrong-request-label":
                provenance["buildDefinition"]["externalParameters"]["request"]["args"]["label:org.opencontainers.image.revision"] = "d" * 40
            elif mutation == "wrong-build-type":
                provenance["buildDefinition"]["buildType"] = "https://evil.invalid/build"
            elif mutation == "wrong-frontend":
                provenance["buildDefinition"]["externalParameters"]["request"]["frontend"] = "gateway.v0"
            elif mutation == "missing-local-context":
                provenance["buildDefinition"]["externalParameters"]["request"]["locals"] = [{"name": "dockerfile"}]
            elif mutation == "wrong-metadata-revision":
                provenance["runDetails"]["metadata"]["buildkit_metadata"]["vcs"]["revision"] = "d" * 40
            elif mutation == "conflicting-git-material":
                provenance["buildDefinition"]["resolvedDependencies"] = [{
                    "uri": "https://github.com/zcat-app/stargate.git#refs/tags/" + VERSION,
                    "digest": {"sha1": "d" * 40}}]
            elif mutation == "malformed-provenance":
                provenance["buildDefinition"]["externalParameters"]["request"]["root"] = "not-an-object"
            statement = {"_type": "https://in-toto.io/Statement/v0.1",
                         "predicateType": ("https://slsa.dev/provenance/v0.2"
                                           if mutation == "unverified-v02-schema" and "slsa" in predicate else predicate),
                         "subject": ([{"name": "fixture", "digest": {"sha256": "f" * 64}}]
                                     if mutation == "wrong-statement-subject" else []),
                         "predicate": provenance if "slsa" in predicate else {"spdxVersion": "SPDX-2.3"}}
            attestations.append(blob(statement, "application/vnd.in-toto+json"))
        attestation_body={"schemaVersion": 2, "config": config, "layers": attestations,
                          "subject": {key: manifest[key] for key in ("mediaType","digest","size")}}
        if mutation == "missing-graph-subject":del attestation_body["subject"]
        if mutation == "wrong-graph-subject":attestation_body["subject"]["digest"]="sha256:"+"f"*64
        attestation = blob(attestation_body, "application/vnd.oci.image.manifest.v1+json")
        attestation["annotations"] = {"vnd.docker.reference.type": "attestation-manifest", "vnd.docker.reference.digest": manifest["digest"]}
        if mutation == "wrong-annotation":attestation["annotations"]["vnd.docker.reference.digest"]="sha256:"+"f"*64
        attestation["platform"] = {"os": "unknown", "architecture": "unknown"}
        index = blob({"schemaVersion": 2, "manifests": [manifest, attestation]}, "application/vnd.oci.image.index.v1+json")
        write_json(layout / "index.json", {"schemaVersion": 2, "manifests": [index]})
        write_json(layout / "oci-layout", {"imageLayoutVersion": "1.0.0"})
        if mutation == "blob": (layout / "blobs/sha256" / layer["digest"][7:]).write_bytes(b"changed")
        return layout, index["digest"]

    def test_complete_layout_retains_inner_index_digest(self):
        layout, expected = self.layout()
        result = self.invoke("inspect-oci", "--directory", layout, "--source", C)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["digest"], expected)
        self.assertNoMutation()

    def test_corrupt_blob_wrong_platform_missing_provenance_or_binding_refuse(self):
        for mutation in ("blob", "platform", "missing-provenance", "missing-graph-subject",
                         "wrong-graph-subject", "wrong-statement-subject", "wrong-annotation",
                         "wrong-vcs-revision", "missing-vcs-revision", "wrong-request-label",
                         "wrong-build-type", "wrong-frontend", "missing-local-context",
                         "wrong-metadata-revision", "conflicting-git-material", "malformed-provenance",
                         "unverified-v02-schema"):
            with self.subTest(mutation=mutation):
                shutil.rmtree(self.root / "layout", ignore_errors=True)
                layout, _ = self.layout(mutation)
                result = self.invoke("inspect-oci", "--directory", layout, "--source", C)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("release: refusing:", result.stderr)
                self.assertNoMutation()


def canonical_fixture(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


class RetainedMetadataTests(Fixture):
    def setUp(self):
        super().setUp()
        self.artifact = {"id": 42, "name": "stargate-" + VERSION + "-" + C + "-7-1", "expired": False,
                         "expires_at": "2026-10-20T00:00:00Z", "size_in_bytes": 123,
                         "digest": "sha256:" + "c" * 64, "workflow_run": {"id": 7, "head_sha": C}}
        self.run = {"id": 7, "run_attempt": 1, "head_sha": C, "head_branch": VERSION,
                    "path": ".github/workflows/release.yml", "event": "workflow_dispatch", "status": "completed", "conclusion": "success"}
        self.transport = {"now": "2026-10-11T13:00:00Z", "responses": {
            "https://api.github.com/repos/zcat-app/stargate/actions/artifacts/42": self.artifact,
            "https://api.github.com/repos/zcat-app/stargate/actions/runs/7/attempts/1": self.run}}
        self.env.update(GITHUB_TOKEN="fixture-token", GITHUB_REPOSITORY="zcat-app/stargate")

    def check(self):
        return self.with_transport("check-retained", "--artifact-id", "42", "--prepare-run-id", "7",
                                   "--prepare-run-attempt", "1", "--source", C, "--version", VERSION)

    def test_exact_retained_identity(self):
        result = self.check()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["digest"], self.artifact["digest"])

    def test_expired_swapped_source_attempt_run_and_digest_refuse(self):
        original = copy.deepcopy(self.transport)
        for mutation in ("expired", "time", "source", "attempt", "run", "digest", "workflow", "size"):
            with self.subTest(mutation=mutation):
                self.transport = copy.deepcopy(original)
                artifact = self.transport["responses"]["https://api.github.com/repos/zcat-app/stargate/actions/artifacts/42"]
                run = self.transport["responses"]["https://api.github.com/repos/zcat-app/stargate/actions/runs/7/attempts/1"]
                if mutation == "expired": artifact["expired"] = True
                elif mutation == "time": artifact["expires_at"] = "2026-10-10T00:00:00Z"
                elif mutation == "source": artifact["workflow_run"]["head_sha"] = E
                elif mutation == "attempt": run["run_attempt"] = 2
                elif mutation == "run": artifact["workflow_run"]["id"] = 8
                elif mutation == "digest": del artifact["digest"]
                elif mutation == "workflow": run["path"] = "evil.yml"
                else: artifact["size_in_bytes"] = 9 * 1024**3
                result = self.check()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("release: refusing:", result.stderr)
                self.assertNoMutation()


class CandidateBindingTests(Fixture):
    def candidate(self):
        retained = self.root / "retained"
        if retained.exists(): shutil.rmtree(retained)
        retained.mkdir()
        source_files = self.release()[1]["source_files"]
        shutil.copytree(ROOT / "extension", self.root / "extension", ignore=shutil.ignore_patterns("dist"), dirs_exist_ok=True)
        lock = self.root / "sidecars/tor/package-closure.lock"
        lock.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / "sidecars/tor/package-closure.lock", lock)
        lines = [line.split() for line in lock.read_text().splitlines() if line.startswith("amd64 ")]
        status = "\n\n".join("Package: %s\nStatus: install ok installed\nVersion: %s\nArchitecture: %s" % (row[1], row[2], row[3]) for row in lines).encode() + b"\n"
        payloads = {
            "stargate-dp": {"opt/stargate/stargate-proxy": b"binary!"},
            "stargate-control": {"opt/stargate/quarkus-run.jar": b"jar", "opt/stargate/entrypoint.sh": b"start",
                                 "opt/stargate/app/app.jar": b"app", "opt/stargate/lib/lib.jar": b"lib", "opt/stargate/quarkus/q.jar": b"quarkus"},
            "tor": {"usr/local/bin/tor-health-publisher": b"publisher", "var/lib/dpkg/status": status},
            "tor-observer": {"opt/stargate/tor-observer": b"observer"}}
        images = {}
        repro = {}
        for service, files in payloads.items():
            layout, index = OCITests.layout(self, layout=retained / "oci" / service, files=files)
            repo = SERVICES.index(service)
            images[service] = "ghcr.io/zcat-app/" + REPOS[repo] + "@" + index
            compare = ["usr/local/bin/tor-health-publisher"] if service == "tor" else files
            repro[service] = {"tier": "package-set-and-publisher-bytes" if service == "tor" else "all-shipped-payload-bytes",
                              "files": {name: {"sha256": sha(files[name]), "mode": "0o644"} for name in sorted(compare)}}
        (retained / "stargate-proxy-linux-amd64").write_bytes(payloads["stargate-dp"]["opt/stargate/stargate-proxy"])
        (retained / "stargate-proxy-linux-arm64").write_bytes(b"arm64-cross-only")
        repro["arm64"] = {"tier": "cross-build-only-no-runtime-acceptance", "sha256": sha(b"arm64-cross-only")}
        with tarfile.open(retained / "stargate-control.tar", "w") as tf:
            for name, data in payloads["stargate-control"].items():
                info = tarfile.TarInfo(name.removeprefix("opt/stargate/"));info.mode=0o644;info.size=len(data);tf.addfile(info,io.BytesIO(data))
        with zipfile.ZipFile(retained / "stargate-extension.zip", "w") as z:
            for p in sorted((self.root / "extension").rglob("*")):
                if not p.is_file() or p.name in ("package.sh", ".keep"):continue
                info=zipfile.ZipInfo(p.relative_to(self.root / "extension").as_posix(),date_time=(1980,1,1,0,0,0))
                info.create_system=3;info.external_attr=0o100644<<16
                z.writestr(info,p.read_bytes())
        extension_files={p.relative_to(self.root / "extension").as_posix(): sha(p.read_bytes()) for p in (self.root / "extension").rglob("*") if p.is_file()}
        write_json(retained / "stargate-extension.zip.inputs.json", {"schema":1,"environment":self.pins["extension"],
                   "recipe_sha256":sha((self.root / "scripts/release/extension.Dockerfile").read_bytes()),
                   "helper_image_id":"sha256:"+"1"*64,"source_files":extension_files,
                   "output_sha256":sha((retained / "stargate-extension.zip").read_bytes())})
        repro["extension"] = {"tier":"pinned-two-run-byte-identity",
                              "sha256":sha((retained / "stargate-extension.zip").read_bytes())}
        write_json(retained / "tor-packages.json", sorted(" ".join(row[:4]) for row in lines))
        write_json(retained / "reproducibility.json", repro)
        generated=copy.deepcopy(self.shape)
        for service, config in generated["services"].items():
            config["image"]=images[service];config.pop("build",None)
            if config.get("pull_policy")=="build":config.pop("pull_policy")
        write_json(retained / "compose.json", generated)
        (retained / "verify.log").write_text("\n".join("  [PASS] " + x for x in ("license-headers","ground-check","shell-quality","go-workspace","extension-tests","mvnw-verify"))+"\n")
        with tarfile.open(retained / "source.tar", "w") as tf:
            for name, record in source_files.items():
                data=(self.root / name).read_bytes();info=tarfile.TarInfo(name);info.mode=0o755 if record["mode"]=="100755" else 0o644;info.size=len(data);tf.addfile(info,io.BytesIO(data))
        candidate={"schema":1,"source":C,"version":VERSION,"channel":"feature-preview","platform":"linux/amd64","images":images,
                   "source_files":source_files,"artifacts":{p.relative_to(retained).as_posix():{"sha256":sha(p.read_bytes()),"size":p.stat().st_size} for p in retained.rglob("*") if p.is_file()},
                   "pending":[],"prepare_run_id":7,"prepare_run_attempt":1}
        write_json(retained / "candidate.json",candidate)
        return retained,candidate

    def check(self):
        return self.invoke("verify-candidate", "--directory", self.root / "retained", "--source", C, "--version", VERSION)

    def test_delivered_files_match_retained_oci_and_source(self):
        self.candidate()
        result=self.check()
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertNoMutation()

    def test_candidate_requires_feature_preview_channel(self):
        for channel in (None, "stable", "feature-preview-v2"):
            with self.subTest(channel=channel):
                retained, candidate = self.candidate()
                if channel is None:
                    del candidate["channel"]
                else:
                    candidate["channel"] = channel
                write_json(retained / "candidate.json", candidate)
                result = self.check()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("release: refusing:", result.stderr)
                self.assertNoMutation()

    def test_changed_delivered_bytes_with_rehashed_inventory_refuse(self):
        for name in ("stargate-proxy-linux-amd64","stargate-control.tar","stargate-extension.zip","stargate-proxy-linux-arm64","reproducibility.json","tor-packages.json","source.tar"):
            with self.subTest(name=name):
                retained,candidate=self.candidate()
                path=retained/name
                path.write_bytes(b"substituted")
                candidate["artifacts"][name]={"sha256":sha(path.read_bytes()),"size":path.stat().st_size}
                write_json(retained/"candidate.json",candidate)
                result=self.check()
                self.assertNotEqual(result.returncode,0)
                self.assertIn("release: refusing:",result.stderr)
                self.assertNoMutation()

    def test_extension_reproducibility_record_is_required(self):
        retained,candidate=self.candidate()
        repro=json.loads((retained/"reproducibility.json").read_text())
        del repro["extension"]
        write_json(retained/"reproducibility.json",repro)
        candidate["artifacts"]["reproducibility.json"]={"sha256":sha((retained/"reproducibility.json").read_bytes()),
                                                        "size":(retained/"reproducibility.json").stat().st_size}
        write_json(retained/"candidate.json",candidate)
        result=self.check()
        self.assertNotEqual(result.returncode,0)
        self.assertIn("release: refusing:",result.stderr)


class PreparationRefusalTests(Fixture):
    def test_wrong_source_or_signing_authority_precedes_any_build(self):
        self.env.update(GITHUB_REPOSITORY="zcat-app/stargate", GITHUB_SHA=C, GITHUB_WORKFLOW_SHA=C,
                        GITHUB_REF="refs/tags/" + VERSION, GITHUB_EVENT_NAME="workflow_dispatch",
                        GITHUB_WORKFLOW_REF="zcat-app/stargate/.github/workflows/release.yml@refs/tags/" + VERSION,
                        GITHUB_RUN_ID="7", GITHUB_RUN_ATTEMPT="1")
        for mutation in ("source", "oidc", "tag", "skip"):
            with self.subTest(mutation=mutation):
                env = {}
                if mutation == "source": env["GITHUB_SHA"] = E
                elif mutation == "oidc": env["ACTIONS_ID_TOKEN_REQUEST_TOKEN"] = "unexpected-authority"
                elif mutation == "tag": env["GITHUB_REF"] = "refs/heads/main"
                else: env["STARGATE_SKIP_CP"] = "1"
                result = self.invoke("prepare", "--source", C, "--version", VERSION, "--output", self.root / "prepared", env=env)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("release: refusing:", result.stderr)
                self.assertNoMutation()


class PreparationRecordingTests(Fixture):
    def setUp(self):
        super().setUp()
        CandidateBindingTests.candidate(self)
        (self.root/"data-plane").mkdir()
        for name in ("go", "bash"):
            self.executable(self.root / "bin" / name, RECORDER)
        self.config.update(prepare_fixture=True, package_fixture=True)
        self.env.update(GITHUB_REPOSITORY="zcat-app/stargate", GITHUB_SHA=C, GITHUB_WORKFLOW_SHA=C,
                        GITHUB_REF="refs/tags/" + VERSION, GITHUB_EVENT_NAME="workflow_dispatch",
                        GITHUB_WORKFLOW_REF="zcat-app/stargate/.github/workflows/release.yml@refs/tags/" + VERSION,
                        GITHUB_RUN_ID="7", GITHUB_RUN_ATTEMPT="1")

    def prepare_recorded(self):
        write_json(self.root / "fixture.json", self.config)
        return subprocess.run([sys.executable, "-B", str(self.root / "scripts/release.py"), "prepare",
                               "--source", C, "--version", VERSION, "--output", str(self.root / "prepared")],
                              cwd=self.root, env=self.env, text=True, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=60)

    def test_full_preparation_retains_independent_builds_and_unsigned_candidate(self):
        result=self.prepare_recorded()
        self.assertEqual(result.returncode,0,result.stderr)
        prepared=self.root/"prepared"
        candidate=json.loads((prepared/"candidate.json").read_text())
        self.assertEqual(candidate["pending"],[])
        self.assertEqual(candidate["channel"],"feature-preview")
        self.assertIn("stargate-proxy-linux-arm64",candidate["artifacts"])
        self.assertEqual(json.loads((prepared/"reproducibility.json").read_text())["arm64"]["tier"],
                         "cross-build-only-no-runtime-acceptance")
        checked=self.invoke("verify-candidate","--directory",prepared,"--source",C,"--version",VERSION)
        self.assertEqual(checked.returncode,0,checked.stderr)
        calls=self.calls()
        for service in ("data-plane/Dockerfile","control-plane/Dockerfile","sidecars/tor/Dockerfile","sidecars/tor-observer/Dockerfile"):
            self.assertEqual(sum(service in row for row in calls),2,service)
        self.assertEqual(sum(row[:2]==["go","build"] for row in calls),2)
        self.assertEqual(sum(row[:2]==["bash","scripts/verify.sh"] for row in calls),1)
        self.assertEqual(json.loads((self.root/"verify-env.json").read_text())["BUILDX_BUILDER"],"default")
        self.assertTrue(any(row[:3]==["docker-buildx","inspect","default"] for row in calls))
        self.assertEqual(sum(row[:2]==["docker-buildx","build"] and "--load" in row for row in calls),2)
        self.assertFalse(any("push" in row or "sign" in row for row in calls))

    def test_second_valid_image_with_changed_binary_refuses(self):
        OCITests.layout(self,layout=self.root/"alternate-dp",files={"opt/stargate/stargate-proxy":b"changed-binary"})
        self.config["different_second_image"]=True
        result=self.prepare_recorded()
        self.assertNotEqual(result.returncode,0)
        self.assertIn("independent shipped payloads differ",result.stderr)
        self.assertFalse((self.root/"prepared/candidate.json").exists())
        self.assertTrue(any(row[:2]==["docker-buildx","rm"] and "stargate-release-7-1" in row
                            for row in self.calls()))

    def test_verifier_refuses_nonloading_default_driver_before_build(self):
        self.config["nonloading_default"]=True
        result=self.prepare_recorded()
        self.assertNotEqual(result.returncode,0)
        self.assertIn("local Docker builder must load verifier images",result.stderr)
        self.assertFalse((self.root/"verify-env.json").exists())


class CandidatePackTransportTests(Fixture):
    def setUp(self):
        super().setUp()
        retained,candidate=CandidateBindingTests.candidate(self)
        EvidenceTests.make_evidence(self,candidate)
        made=EvidenceTests.check(self)
        self.assertEqual(made.returncode,0,made.stderr)
        archive=self.root/"artifact.zip"
        with zipfile.ZipFile(archive,"w",compression=zipfile.ZIP_DEFLATED) as z:
            for path in sorted(retained.rglob("*")):
                if path.is_file():z.write(path,path.relative_to(retained).as_posix())
        PromotionPolicyTests.make_policy(self)
        self.env.update(GITHUB_SHA=C,GITHUB_WORKFLOW_SHA=C,GITHUB_REF="refs/tags/"+VERSION,
                        GITHUB_EVENT_NAME="workflow_dispatch",
                        GITHUB_WORKFLOW_REF="zcat-app/stargate/.github/workflows/release.yml@refs/tags/"+VERSION,
                        GITHUB_RUN_ATTEMPT="1")
        responses=self.transport["responses"]
        api="https://api.github.com/repos/zcat-app/stargate"
        responses[api+"/commits/"+VERSION]={"sha":C}
        responses[api+"/git/ref/tags/"+VERSION]={"ref":"refs/tags/"+VERSION,
            "object":{"type":"commit","sha":C}}
        responses[api+"/releases/tags/"+VERSION]={"__status":404}
        responses[api+"/actions/artifacts/42"]={"id":42,"name":"stargate-"+VERSION+"-"+C+"-7-1",
            "expired":False,"expires_at":"2026-10-20T00:00:00Z","size_in_bytes":archive.stat().st_size,
            "digest":"sha256:"+sha(archive.read_bytes()),"workflow_run":{"id":7,"head_sha":C}}
        responses[api+"/actions/runs/7/attempts/1"]={"id":7,"run_attempt":1,"head_sha":C,
            "head_branch":VERSION,"path":".github/workflows/release.yml","event":"workflow_dispatch",
            "status":"completed","conclusion":"success"}
        responses[api+"/actions/artifacts/42/zip"]={"__bytes":base64.b64encode(archive.read_bytes()).decode()}
        trees=("1"*40,"2"*40,"3"*40)
        responses[api+"/git/commits/"+E]={"sha":E,"tree":{"sha":trees[0]}}
        responses[api+"/git/trees/"+trees[0]]={"truncated":False,"tree":[{"path":"release-evidence","type":"tree","mode":"040000","sha":trees[1]}]}
        responses[api+"/git/trees/"+trees[1]]={"truncated":False,"tree":[{"path":VERSION,"type":"tree","mode":"040000","sha":trees[2]}]}
        entries=[]
        for path in sorted(self.evidence.iterdir()):
            data=path.read_bytes()
            oid=hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()
            entries.append({"path":path.name,"type":"blob","mode":"100644","sha":oid})
            responses[api+"/git/blobs/"+oid]={"encoding":"base64","sha":oid,"content":base64.b64encode(data).decode()}
        responses[api+"/git/trees/"+trees[2]+"?recursive=1"]={"truncated":False,"tree":entries}

    def pack_recorded(self):
        return self.with_transport("promotion-pack","--source",C,"--version",VERSION,
                                   "--evidence-commit",E,"--artifact-id","42","--prepare-run-id","7",
                                   "--prepare-run-attempt","1","--output",self.root/"pack-result.json")

    def test_full_transport_reconstructs_approval_pack_without_publication(self):
        result=self.pack_recorded()
        self.assertEqual(result.returncode,0,result.stderr)
        pack=json.loads((self.root/"pack-result.json").read_text())
        self.assertEqual(pack["candidate_sha256"],sha((self.root/"retained/candidate.json").read_bytes()))
        self.assertEqual(pack["evidence_commit"],E)
        self.assertNoMutation()
        self.assertFalse(any(method!="GET" for method,_ in
            (json.loads(line) for line in (self.root/"http.jsonl").read_text().splitlines())))

    def test_same_named_branch_cannot_substitute_for_missing_remote_tag_in_pack(self):
        api="https://api.github.com/repos/zcat-app/stargate"
        self.transport["responses"][api+"/git/ref/tags/"+VERSION]={"__status":404}
        result=self.pack_recorded()
        self.assertNotEqual(result.returncode,0)
        self.assertIn("release: refusing:",result.stderr)
        self.assertFalse((self.root/"pack-result.json").exists())

    def test_changed_archive_and_evidence_blob_refuse_before_pack(self):
        api="https://api.github.com/repos/zcat-app/stargate"
        for kind in ("archive","blob"):
            with self.subTest(kind=kind):
                original=copy.deepcopy(self.transport)
                if kind=="archive":
                    self.transport["responses"][api+"/actions/artifacts/42/zip"]["__bytes"]=base64.b64encode(b"wrong").decode()
                else:
                    blob=next(key for key in self.transport["responses"] if "/git/blobs/" in key)
                    self.transport["responses"][blob]["content"]=base64.b64encode(b"wrong").decode()
                result=self.pack_recorded()
                self.assertNotEqual(result.returncode,0)
                self.assertIn("release: refusing:",result.stderr)
                self.assertFalse((self.root/"pack-result.json").exists())
                self.transport=original


class PromotionDispatchTests(PromotionPolicyTests):
    # Exercise the real final orchestration with already-validated immutable
    # inputs at its internal boundary. Transport/validation are tested above;
    # this seam supplies data, never changes upload/sign/finalize behavior.
    def publish(self, failure=None, *, releases=None, permissions=None, graphql=None, rest=None,
                create_response=None, publish_response=None, workflow_override=None,
                tag_ref=None, tag_object=None):
        directory, manifest = self.release()
        (directory / "candidate.json").write_bytes(b'{}\n')
        for name in SERVICES:
            (directory / "oci" / name).mkdir(parents=True, exist_ok=True)
        for name in ("stargate-proxy-linux-amd64", "stargate-proxy-linux-arm64", "stargate-control.tar", "stargate-extension.zip", "stargate-extension.zip.inputs.json", "source.tar", "verify.log", "reproducibility.json", "tor-packages.json"):
            (directory / name).write_bytes(b'fixture\n')
        (directory / "logs").mkdir(exist_ok=True)
        (directory / "logs/verify-command.log").write_bytes(b'fixture\n')
        self.pack["protection"] = {"id": 5, "name": "stargate-release", "can_admins_bypass": False,
                                    "reviewers": [[33, "carol"]], "prevent_self_review": True, "tag_policy": "v*"}
        self.pack["candidate_sha256"] = sha(b'{}\n')
        write_json(self.root / "pack.json", self.pack)
        binding = "Approve Stargate pack " + sha((self.root / "pack.json").read_bytes()) + " source " + C + " evidence " + E + " artifact 42 prepare 7/1"
        self.approvals[0]["comment"] = binding
        responses = self.transport["responses"]
        responses["https://api.github.com/repos/zcat-app/stargate/commits/" + VERSION] = {"sha": C}
        responses["https://api.github.com/repos/zcat-app/stargate/git/ref/tags/" + VERSION] = (
            {"ref": "refs/tags/" + VERSION, "object": {"type": "commit", "sha": C}}
            if tag_ref is None else tag_ref)
        if tag_object is not None:
            responses["https://api.github.com/repos/zcat-app/stargate/git/tags/" + "e" * 40] = tag_object
        responses["https://api.github.com/repos/zcat-app/stargate/releases/tags/" + VERSION] = (
            {"__status": 404 if failure != "reuse" else 200} if rest is None else rest)
        responses["https://api.github.com/graphql"] = (
            {"data": {"repository": {"nameWithOwner": "zcat-app/stargate", "release": None}}}
            if graphql is None else graphql)
        responses["https://api.github.com/repos/zcat-app/stargate"] = (
            {"id": 42, "full_name": "zcat-app/stargate", "default_branch": "main", "permissions": {"push": True}}
            if permissions is None else permissions)
        api = "https://api.github.com/repos/zcat-app/stargate"
        source_root, default_root = "1" * 40, "2" * 40
        source_github, default_github, workflows = "3" * 40, "4" * 40, "5" * 40
        responses[api + "/git/commits/" + C] = {"sha": C, "tree": {"sha": source_root}}
        responses[api + "/commits/main"] = {"sha": "d" * 40, "commit": {"tree": {"sha": default_root}}}
        for tree, child, name in ((source_root, source_github, ".github"),
                                  (default_root, default_github, ".github"),
                                  (source_github, workflows, "workflows"),
                                  (default_github, workflows, "workflows")):
            responses[api + "/git/trees/" + tree] = {"sha": tree, "truncated": False,
                "tree": [{"path": name, "type": "tree", "mode": "040000", "sha": child}]}
        responses["https://api.github.com/repos/zcat-app/stargate/releases?per_page=100&page=1"] = (
            [] if releases is None else releases)
        created = {"id": 99, "tag_name": VERSION, "draft": True, "prerelease": True} if create_response is None else create_response
        responses["https://api.github.com/repos/zcat-app/stargate/releases"] = (
            created if "__status" in created or "__value" in created else
            {"__value": created, "__http_status": 201})
        responses["https://api.github.com/repos/zcat-app/stargate/releases/99"] = (
            {"id": 99, "draft": False, "tag_name": VERSION, "prerelease": True} if publish_response is None else publish_response)
        if workflow_override:
            responses.update(workflow_override)
        self.transport["upload_failure"] = failure == "upload"
        self.config["push_failure"] = failure == "push"
        self.config["bad_signature"] = failure == "signature"
        self.env.update(GITHUB_RUN_ATTEMPT="1", GITHUB_SHA=C, GITHUB_WORKFLOW_SHA=C, GITHUB_REF="refs/tags/" + VERSION,
                        GITHUB_EVENT_NAME="workflow_dispatch", GITHUB_WORKFLOW_REF="zcat-app/stargate/.github/workflows/release.yml@refs/tags/" + VERSION,
                        ACTIONS_ID_TOKEN_REQUEST_TOKEN="fixture-oidc", ACTIONS_ID_TOKEN_REQUEST_URL="https://fixture.invalid")
        write_json(directory / "candidate.json", {"channel": "feature-preview", "images": self.images,
                                                   "source_files": manifest["source_files"], "artifacts": {}})
        write_json(self.root / "fixture.json", self.config)
        write_json(self.root / "transport.json", self.transport)
        extra = '''
m.candidate_pack=lambda args,where:(m.document(root/'pack.json'),root/'release',root/'release')
'''
        bootstrap = self.root / "publish-bootstrap.py"
        bootstrap.write_text(BOOTSTRAP.replace("try:m.main()", extra + "\ntry:m.main()"))
        return subprocess.run([sys.executable, "-B", str(bootstrap), "promote", "--source", C, "--version", VERSION,
                              "--evidence-commit", E, "--artifact-id", "42", "--prepare-run-id", "7", "--prepare-run-attempt", "1",
                              "--pack-sha256", sha((self.root / "pack.json").read_bytes())], cwd=self.root, env=self.env,
                              text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)

    def assert_reuse_gate_refused(self, result, after_signing):
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("release: refusing:", result.stderr)
        if after_signing:
            self.assertTrue(any(row[:2] == ["crane", "push"] for row in self.calls()))
            http = [json.loads(line) for line in (self.root / "http.jsonl").read_text().splitlines()]
            self.assertFalse(any(method == "POST" and url.endswith("/releases") for method, url in http))
        else:
            self.assertFalse(any(row[:2] in (["crane", "push"], ["cosign", "sign"],
                                            ["cosign", "sign-blob"]) for row in self.calls()))

    def test_final_publication_follows_verified_images_and_assets(self):
        result = self.publish()
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.calls()
        self.assertEqual(sum(c[:2] == ["crane", "push"] for c in calls), 4)
        self.assertFalse(any("build" in c or "--build" in c for c in calls))
        http = [json.loads(x) for x in (self.root / "http.jsonl").read_text().splitlines()]
        self.assertEqual(http[-1], ["PATCH", "https://api.github.com/repos/zcat-app/stargate/releases/99"])
        uploaded = [url for method, url in http if method == "POST" and "/assets?name=" in url]
        for name in ("stargate-extension.zip.inputs.json", "tor-packages.json", "build-logs.tar"):
            self.assertTrue(any(url.endswith("name=" + name) for url in uploaded), name)
        self.assertFalse(any(url.endswith("name=stargate-proxy-linux-arm64") for url in uploaded))
        self.assertEqual(json.loads((self.root / "uploaded-candidate.json").read_text())["channel"],"feature-preview")
        self.assertEqual(json.loads((self.root / "uploaded-release.json").read_text())["channel"],"feature-preview")
        bodies = [json.loads(line) for line in (self.root / "http-bodies.jsonl").read_text().splitlines()]
        create = json.loads(next(body for url, body in bodies if url.endswith("/releases")))
        self.assertTrue(create["prerelease"])
        self.assertTrue(create["draft"])

    def test_release_metadata_and_signed_manifest_bind_feature_preview(self):
        result=self.publish()
        self.assertEqual(result.returncode,0,result.stderr)
        bodies=[json.loads(line) for line in (self.root/"http-bodies.jsonl").read_text().splitlines()]
        create=json.loads(next(body for url,body in bodies if url.endswith("/releases")))
        self.assertTrue(create["prerelease"])
        self.assertEqual(json.loads((self.root/"uploaded-release.json").read_text())["channel"],"feature-preview")

    def test_signing_uses_exact_source_owned_service_config(self):
        result=self.publish()
        self.assertEqual(result.returncode,0,result.stderr)
        calls=[row for row in self.calls() if row[:2] in (["cosign","sign"],["cosign","sign-blob"])]
        self.assertEqual(len(calls),5)
        for row in calls:
            self.assertIn("--signing-config",row)
            self.assertIn("--trusted-root",row)
            self.assertIn("github-actions",row)
            self.assertNotIn("--use-signing-config=false",row)
            self.assertNotIn("--fulcio-url",row)
            self.assertNotIn("--rekor-url",row)
        self.assertEqual(json.loads((self.root/"observed-signing-config.json").read_text()),
                         self.pins["signing_config"])

    def test_push_signature_asset_failure_and_version_reuse_never_finalize(self):
        for failure in ("push", "signature", "upload", "reuse"):
            with self.subTest(failure=failure):
                (self.root / "http.jsonl").unlink(missing_ok=True)
                result = self.publish(failure)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("release: refusing:", result.stderr)
                http = [json.loads(x) for x in (self.root / "http.jsonl").read_text().splitlines()]
                self.assertFalse(any(method == "PATCH" for method, _ in http))

    def test_remote_tag_namespace_is_checked_before_each_promotion_phase(self):
        valid={"ref":"refs/tags/"+VERSION,"object":{"type":"commit","sha":C}}
        missing={"__status":404}
        for stage, response in (("pre-push", missing),
                                ("pre-draft", {"__sequence":[valid,missing]}),
                                ("pre-publish", {"__sequence":[valid,valid,missing]})):
            with self.subTest(stage=stage):
                (self.root/"calls.jsonl").unlink(missing_ok=True)
                (self.root/"http.jsonl").unlink(missing_ok=True)
                # The same-named branch still resolves to C through /commits/VERSION.
                result=self.publish(tag_ref=response)
                self.assertNotEqual(result.returncode,0)
                self.assertIn("release: refusing:",result.stderr)
                http=[json.loads(line) for line in (self.root/"http.jsonl").read_text().splitlines()]
                if stage=="pre-push":
                    self.assertFalse(any(row[:2]==["crane","push"] for row in self.calls()))
                elif stage=="pre-draft":
                    self.assertTrue(any(row[:2]==["crane","push"] for row in self.calls()))
                    self.assertFalse(any(method=="POST" and url.endswith("/releases") for method,url in http))
                else:
                    self.assertTrue(any(method=="POST" and url.endswith("/releases") for method,url in http))
                    self.assertFalse(any(method=="PATCH" for method,_ in http))

    def test_annotated_remote_tag_resolves_to_reviewed_commit(self):
        result=self.publish(tag_ref={"ref":"refs/tags/"+VERSION,
            "object":{"type":"tag","sha":"e"*40}},
            tag_object={"sha":"e"*40,"tag":VERSION,"object":{"type":"commit","sha":C}})
        self.assertEqual(result.returncode,0,result.stderr)
        http=[json.loads(line) for line in (self.root/"http.jsonl").read_text().splitlines()]
        self.assertEqual(sum(url.endswith("/git/ref/tags/"+VERSION) for _,url in http),3)
        self.assertEqual(sum(url.endswith("/git/tags/"+"e"*40) for _,url in http),3)

    def test_malformed_or_changed_remote_tag_refuses_before_push(self):
        tag_ref={"ref":"refs/tags/"+VERSION,"object":{"type":"tag","sha":"e"*40}}
        cases=(("wrong-ref",{"ref":"refs/heads/"+VERSION,"object":{"type":"commit","sha":C}},None),
               ("changed-commit",{"ref":"refs/tags/"+VERSION,
                                  "object":{"type":"commit","sha":"d"*40}},None),
               ("wrong-target-type",{"ref":"refs/tags/"+VERSION,
                                     "object":{"type":"blob","sha":C}},None),
               ("invalid-oid",{"ref":"refs/tags/"+VERSION,
                               "object":{"type":"commit","sha":"bad"}},None),
               ("wrong-annotation",tag_ref,{"sha":"e"*40,"tag":"v9.9.9",
                                            "object":{"type":"commit","sha":C}}),
               ("changed-annotation",tag_ref,{"sha":"e"*40,"tag":VERSION,
                                              "object":{"type":"commit","sha":"d"*40}}),
               ("tag-cycle",tag_ref,{"sha":"e"*40,"tag":VERSION,
                                     "object":{"type":"tag","sha":"e"*40}}))
        for label,ref,object_ in cases:
            with self.subTest(case=label):
                (self.root/"calls.jsonl").unlink(missing_ok=True)
                result=self.publish(tag_ref=ref,tag_object=object_)
                self.assert_reuse_gate_refused(result,after_signing=False)

    def test_offset_row_shift_cannot_hide_existing_draft_before_push(self):
        ordinary = [{"id": i + 1, "tag_name": f"v0.0.{i}", "draft": False}
                    for i in range(149)]
        draft = {"id": 200, "tag_name": VERSION, "draft": True}
        # Page 1 returns 100 ordinary rows. Deleting its first unrelated row
        # then moves the target draft from page 2 into the already-read page 1.
        self.transport["row_shift"] = [*ordinary[:100], draft, *ordinary[100:]]
        result = self.publish(graphql={"data": {"repository": {
            "nameWithOwner": "zcat-app/stargate",
            "release": {"tagName": VERSION, "isDraft": True}}}})
        self.assert_reuse_gate_refused(result, after_signing=False)

    def test_exact_tag_graphql_draft_and_uncertain_answers_refuse_at_both_guards(self):
        absent = {"data": {"repository": {"nameWithOwner": "zcat-app/stargate", "release": None}}}
        present = {"data": {"repository": {"nameWithOwner": "zcat-app/stargate",
                                           "release": {"tagName": VERSION, "isDraft": True}}}}
        cases = ("draft", present), (
            "published", {"data": {"repository": {"nameWithOwner": "zcat-app/stargate",
                                                  "release": {"tagName": VERSION, "isDraft": False}}}}), (
            "errors", {"data": absent["data"], "errors": [{"message": "partial"}]}), (
            "missing-data", {}), ("missing-repository", {"data": {}}), (
            "null-repository", {"data": {"repository": None}}), (
            "missing-release", {"data": {"repository": {"nameWithOwner": "zcat-app/stargate"}}}), (
            "wrong-repository", {"data": {"repository": {"nameWithOwner": "other/repo", "release": None}}}), (
            "wrong-tag", {"data": {"repository": {"nameWithOwner": "zcat-app/stargate",
                                                  "release": {"tagName": "v9.9.9", "isDraft": True}}}}), (
            "missing-draft-state", {"data": {"repository": {"nameWithOwner": "zcat-app/stargate",
                                                             "release": {"tagName": VERSION}}}}), (
            "transport", {"__status": 502}), ("partial-status", {"__value": absent, "__http_status": 206})
        for after_signing in (False, True):
            for label, response in cases:
                with self.subTest(after_signing=after_signing, case=label):
                    (self.root / "calls.jsonl").unlink(missing_ok=True)
                    (self.root / "http.jsonl").unlink(missing_ok=True)
                    graphql = {"__sequence": [absent, response]} if after_signing else response
                    result = self.publish(graphql=graphql)
                    self.assert_reuse_gate_refused(result, after_signing)

    def test_exact_tag_published_lookup_and_conflicts_refuse(self):
        absent = {"data": {"repository": {"nameWithOwner": "zcat-app/stargate", "release": None}}}
        for after_signing in (False, True):
            for label, response in (("published", {"id": 88, "tag_name": VERSION, "draft": False}),
                                    ("forbidden", {"__status": 403}),
                                    ("server-error", {"__status": 503}),
                                    ("partial-status", {"__value": {}, "__http_status": 206})):
                with self.subTest(after_signing=after_signing, case=label):
                    (self.root / "calls.jsonl").unlink(missing_ok=True)
                    (self.root / "http.jsonl").unlink(missing_ok=True)
                    rest = {"__sequence": [{"__status": 404}, response]} if after_signing else response
                    result = self.publish(graphql=absent, rest=rest)
                    self.assert_reuse_gate_refused(result, after_signing)

    def test_exact_tag_absence_is_queried_twice_with_target_variables(self):
        result = self.publish()
        self.assertEqual(result.returncode, 0, result.stderr)
        queries = [json.loads(line) for line in (self.root / "graphql.jsonl").read_text().splitlines() if line]
        self.assertEqual(len(queries), 2)
        for query in queries:
            self.assertEqual(query["variables"], {"owner": "zcat-app", "name": "stargate", "tag": VERSION})
            self.assertIn("release(tagName:", query["query"])
        http = [json.loads(line) for line in (self.root / "http.jsonl").read_text().splitlines()]
        created = next(i for i, (method, url) in enumerate(http) if
                       method == "POST" and url.endswith("/releases"))
        self.assertEqual(sum(url.endswith("/releases/tags/" + VERSION) for _, url in http), 2)
        self.assertLess([i for i, (_, url) in enumerate(http) if url.endswith("/graphql")][-1], created)

    def test_workflow_tree_identity_allows_different_default_commit(self):
        result = self.publish()
        self.assertEqual(result.returncode, 0, result.stderr)
        http = [json.loads(line) for line in (self.root / "http.jsonl").read_text().splitlines()]
        api = "https://api.github.com/repos/zcat-app/stargate"
        for path in ("/git/commits/" + C, "/commits/main", "/git/trees/" + "3" * 40,
                     "/git/trees/" + "4" * 40):
            self.assertEqual(sum(url == api + path for _, url in http), 2, path)

    def test_workflow_tree_mismatch_or_unknown_refuses_at_both_guards(self):
        api = "https://api.github.com/repos/zcat-app/stargate"
        default_github = "4" * 40
        valid_repo = {"id": 42, "full_name": "zcat-app/stargate", "default_branch": "main",
                      "permissions": {"push": True}}
        valid_tree = {"sha": default_github, "truncated": False,
                      "tree": [{"path": "workflows", "type": "tree", "mode": "040000", "sha": "5" * 40}]}
        cases = (("changed-workflows", api + "/git/trees/" + default_github,
                  {"sha": default_github, "truncated": False,
                   "tree": [{"path": "workflows", "type": "tree", "mode": "040000", "sha": "6" * 40}]}, valid_tree),
                 ("truncated-tree", api + "/git/trees/" + default_github,
                  {**valid_tree, "truncated": True}, valid_tree),
                 ("missing-tree", api + "/git/trees/" + default_github,
                  {**valid_tree, "tree": []}, valid_tree),
                 ("duplicate-tree", api + "/git/trees/" + default_github,
                  {**valid_tree, "tree": valid_tree["tree"] * 2}, valid_tree),
                 ("missing-default", api, {k: v for k, v in valid_repo.items() if k != "default_branch"},
                  valid_repo),
                 ("malformed-default-commit", api + "/commits/main",
                  {"sha": "bad", "commit": {"tree": {"sha": "2" * 40}}},
                  {"sha": "d" * 40, "commit": {"tree": {"sha": "2" * 40}}}),
                 ("wrong-source-commit", api + "/git/commits/" + C,
                  {"sha": "d" * 40, "tree": {"sha": "1" * 40}},
                  {"sha": C, "tree": {"sha": "1" * 40}}))
        for after_signing in (False, True):
            for label, url, broken, valid in cases:
                with self.subTest(after_signing=after_signing, case=label):
                    (self.root / "calls.jsonl").unlink(missing_ok=True)
                    (self.root / "http.jsonl").unlink(missing_ok=True)
                    override = {url: {"__sequence": [valid, broken]} if after_signing else broken}
                    result = self.publish(workflow_override=override)
                    self.assert_reuse_gate_refused(result, after_signing)

    def test_ambiguous_draft_creation_or_publication_requires_manual_reconciliation(self):
        cases = (("create-timeout", {"__status": 504}, None),
                 ("create-no-id", {"tag_name": VERSION, "draft": True}, None),
                 ("create-wrong-tag", {"id": 99, "tag_name": "v9.9.9", "draft": True}, None),
                 ("create-partial-status", {"__value": {"id": 99, "tag_name": VERSION, "draft": True},
                                            "__http_status": 200}, None),
                 ("publish-timeout", None, {"__status": 504}),
                 ("publish-partial-status", None, {"__value": {"id": 99, "tag_name": VERSION, "draft": False},
                                                   "__http_status": 206}),
                 ("publish-wrong-id", None, {"id": 100, "tag_name": VERSION, "draft": False}))
        for label, created, published in cases:
            with self.subTest(case=label):
                (self.root / "http.jsonl").unlink(missing_ok=True)
                result = self.publish(create_response=created, publish_response=published)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("release: refusing:", result.stderr)
                http = [json.loads(line) for line in (self.root / "http.jsonl").read_text().splitlines()]
                self.assertEqual(sum(method == "POST" and url.endswith("/releases") for method, url in http), 1)
                self.assertLessEqual(sum(method == "PATCH" and url.endswith("/releases/99") for method, url in http), 1)
                if label.startswith("create"):
                    self.assertFalse(any("/assets?name=" in url for _, url in http))


class WorkflowTests(unittest.TestCase):
    def test_preparation_read_grants_and_protected_promotion_are_separate(self):
        path = ROOT / ".github/workflows/release.yml"
        self.assertTrue(path.exists(), "release workflow absent")
        text = path.read_text()
        prepare = text.split("  prepare:\n", 1)[1].split("  pack:\n", 1)[0]
        pack = text.split("  pack:\n", 1)[1].split("  promote:\n", 1)[0]
        promote = text.split("  promote:\n", 1)[1]
        self.assertNotIn("write", prepare)
        self.assertNotIn("write", pack)
        self.assertIn("environment: stargate-release", promote)
        self.assertIn('>> "$GITHUB_OUTPUT"', pack)
        self.assertIn('pack_sha256=', pack)
        self.assertIn('PACK_SHA256: ${{ needs.pack.outputs.pack_sha256 }}', promote)
        for permission in ("contents: write", "packages: write", "id-token: write"):
            self.assertIn(permission, promote)
        for block in (prepare, pack, promote):
            self.assertIn("github.sha == inputs.source", block)
            self.assertIn("github.ref_name == inputs.version", block)
            self.assertIn("persist-credentials: false", block)
        self.assertIn("workflow_dispatch:", text)
        self.assertNotRegex(text, r"(?m)^  (push|pull_request|workflow_run):")
        self.assertNotIn("git tag", text)
        self.assertNotIn("git push", text)
        for line in text.splitlines():
            if "uses:" in line and not "uses: ./" in line:
                self.assertRegex(line, r"uses: [^@]+@[0-9a-f]{40}(?: |$)")


class ResourceBoundaryTests(unittest.TestCase):
    def module(self):
        spec = importlib.util.spec_from_file_location("release_resource_fixture", ROOT / "scripts/release.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_command_output_limit_refuses_without_returning_partial_success(self):
        module = self.module()
        module.MAX_COMMAND_OUTPUT = 1024
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "command.log"
            with self.assertRaises(module.Refusal):
                module.run([sys.executable, "-c", "import sys;sys.stdout.write('x'*100000);sys.stdout.flush()"], log=log)
            self.assertLessEqual(log.stat().st_size, 1024)
            self.assertGreater(log.stat().st_size, 0)

    def test_bounded_command_preserves_stdout_log_and_failure_status(self):
        module = self.module()
        module.MAX_COMMAND_OUTPUT = 1024
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "command.log"
            out = module.run([sys.executable, "-c", "import sys;print('answer');sys.stderr.write('diagnostic')"], log=log)
            self.assertEqual(out, b"answer\n")
            self.assertIn(b"diagnostic", log.read_bytes())
            with self.assertRaises(module.Refusal):
                module.run([sys.executable, "-c", "raise SystemExit(9)"])

    def test_aggregate_image_payload_bound_refuses_even_when_files_fit(self):
        module=self.module()
        module.MAX_PAYLOAD_BYTES=16
        with tempfile.TemporaryDirectory() as temporary:
            layout=Path(temporary)
            (layout/"blobs/sha256").mkdir(parents=True)
            archive=io.BytesIO()
            with tarfile.open(fileobj=archive,mode="w") as tf:
                for name in ("opt/stargate/app/a.jar","opt/stargate/lib/b.jar"):
                    info=tarfile.TarInfo(name);info.size=10;tf.addfile(info,io.BytesIO(b"x"*10))
            data=archive.getvalue()
            (layout/"blobs/sha256"/sha(data)).write_bytes(data)
            info={"layers":[{"digest":"sha256:"+sha(data),"mediaType":"application/vnd.oci.image.layer.v1.tar"}]}
            with self.assertRaises(module.Refusal):module.image_payload(layout,info,"stargate-control")


class ExtensionPackagingTests(Fixture):
    def setUp(self):
        super().setUp()
        shutil.copytree(ROOT / "extension", self.root / "extension", ignore=shutil.ignore_patterns("dist"))
        recipe = ROOT / "scripts/release/extension.Dockerfile"
        if recipe.exists(): shutil.copy2(recipe, self.root / "scripts/release/extension.Dockerfile")
        self.config["package_fixture"] = True
        self.copy = self.root / "copy"
        shutil.copytree(self.root / "extension", self.copy)

    def package(self):
        return self.invoke("package-extension", "--source-dir", self.copy, "--output", self.root / "extension.zip")

    def test_recipe_installs_only_hash_checked_local_debs_and_audits_dpkg(self):
        recipe=(ROOT/"scripts/release/extension.Dockerfile").read_text()
        install="dpkg -i ./libbz2-1.0_1.0.8-5+b1_amd64.deb ./zip_3.0-13_amd64.deb"
        self.assertIn(install,recipe)
        self.assertIn("&& dpkg --audit",recipe)
        self.assertNotIn("apt-get --no-download install",recipe)
        download=recipe.index("apt-get download zip=3.0-13 libbz2-1.0=1.0.8-5+b1")
        checked=recipe.index("sha256sum -c -",download)
        self.assertLess(checked,recipe.index(install))

    def test_pinned_packager_outputs_exact_source_zip_without_recipe(self):
        result = self.package()
        self.assertEqual(result.returncode, 0, result.stderr)
        with zipfile.ZipFile(self.root / "extension.zip") as z:
            self.assertNotIn("extension.Dockerfile", z.namelist())
            self.assertEqual(z.read("manifest.json"), (self.copy / "manifest.json").read_bytes())
            self.assertTrue(all(i.external_attr >> 16 == 0o100644 for i in z.infolist()))
        build = next(c for c in self.calls() if c[0] == "docker-buildx" and "build" in c)
        self.assertIn("--no-cache", build)
        self.assertIn("linux/amd64", build)
        calls = [c for c in self.calls() if c[:2] == ["docker", "run"]]
        self.assertTrue(all("none" in c and "--read-only" in c for c in calls))
        report = json.loads((self.root / "extension.zip.inputs.json").read_text())
        self.assertEqual(report["output_sha256"], sha((self.root / "extension.zip").read_bytes()))

    def test_missing_cleanup_tag_preserves_primary_build_failure(self):
        self.config.update(package_build_failure=True,missing_tag_on_cleanup=True)
        result=self.package()
        self.assertNotEqual(result.returncode,0)
        self.assertIn("fixture primary build failure",result.stderr)
        self.assertFalse((self.root/"extension.zip").exists())
        cleanup=[row for row in self.calls() if row[:3]==["docker","image","rm"]]
        self.assertEqual(len(cleanup),1)
        self.assertTrue(cleanup[0][3].startswith("stargate-release-zip:"))

    def test_cleanup_failure_after_success_is_not_ignored(self):
        self.config["missing_tag_on_cleanup"]=True
        result=self.package()
        self.assertNotEqual(result.returncode,0)
        self.assertIn("command failed: docker image",result.stderr)

    def test_changed_or_added_copy_source_refuses_before_build(self):
        for name in ("manifest.json", "injected.js"):
            with self.subTest(name=name):
                target = self.copy / name
                original = target.read_bytes() if target.exists() else None
                target.write_bytes(b"changed source")
                result = self.package()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("release: refusing:", result.stderr)
                self.assertEqual(self.calls(), [])
                if original is None: target.unlink()
                else: target.write_bytes(original)

    def test_existing_perturbed_copy_gate_selects_real_release_driver(self):
        target = self.root / "tests/reproducibility/extension_test.sh"
        target.parent.mkdir(parents=True)
        shutil.copy2(ROOT / "tests/reproducibility/extension_test.sh", target)
        write_json(self.root / "fixture.json", self.config)
        result = subprocess.run(["bash", str(target)], cwd=self.root,
                                env=self.env | {"STARGATE_EXTENSION_RUNNER": "release"}, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(sum(c[0] == "docker-buildx" and "build" in c for c in self.calls()), 2,
                         "release mode silently used host zip")


class ObserverReproTests(Fixture):
    def run_observer(self, difference=False):
        self.config["observer_fixture"] = True
        self.config["observer_difference"] = difference
        write_json(self.root / "fixture.json", self.config)
        dockerfile = self.root / "sidecars/tor-observer/Dockerfile"
        dockerfile.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / "sidecars/tor-observer/Dockerfile", dockerfile)
        path = self.root / "tests/reproducibility/tor_observer_test.sh"
        path.parent.mkdir(parents=True, exist_ok=True)
        if (ROOT / "tests/reproducibility/tor_observer_test.sh").exists():
            shutil.copy2(ROOT / "tests/reproducibility/tor_observer_test.sh", path)
        return subprocess.run(["bash", str(path)], cwd=self.root, env=self.env,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True, timeout=15)

    def test_two_actual_observer_builder_outputs_match(self):
        result = self.run_observer()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PASS", result.stdout)
        self.assertEqual(sum(c[:2] == ["docker", "build"] for c in self.calls()), 2)
        self.assertFalse(any("push" in c for c in self.calls()))

    def test_changed_second_observer_binary_refuses(self):
        result = self.run_observer(True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("FAIL", result.stderr)


if __name__ == "__main__":
    unittest.main()
