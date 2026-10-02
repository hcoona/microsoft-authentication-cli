"""Inert acquisition of current public compile inputs; no compiler or Windows execution."""
PREFLIGHT_ADMITTED = False
if not PREFLIGHT_ADMITTED:
    raise SystemExit('Independent source/input/runtime/call/accounting admission required.')
import hashlib,json,os,resource,signal,stat,sys,time
from pathlib import Path
R=None  # Exact dedicated retention root is a reviewed activation value.
REPORT=None  # Exact prior local-input report path is a reviewed activation value.
REPORT_PIN=None  # Exact accepted report descriptor is a reviewed activation value.
OUTPUT=None  # Exact fresh outcome path is a reviewed activation value.
COMMIT=None  # Exact accepted caller/protocol source commit is a reviewed activation value.
DONORS_SHA='ffd6b96b4216d07e1025980ea3556c6e230f6ed9fcc9e47ab745ebdeee17e1f0'
START=time.monotonic();WORK_END=START+50;END=START+55
owned=[];dirs={};rows=[];requested=0;written=0;reads=0;io_calls=0;cancelled=False;terminal_disposition=False
phase='startup';observation=None
def full9(s):return [s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_nlink]
def enc(v):return (json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode('ascii')
def sha(b):return hashlib.sha256(b).hexdigest()
def before(terminal=False):
    if time.monotonic()>=(END if terminal else WORK_END) or (cancelled and not terminal):raise TimeoutError()
def stop(*_):
    global cancelled
    cancelled=True
    # Late signals fail immediately only after all owned descriptors are closed.
    if terminal_disposition:raise SystemExit(1)
def opened(name,flags,pfd=None,terminal=False):
    before(terminal)
    assert len(owned)<80
    fd=os.open(name,flags|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=pfd);owned.append(fd);return fd
def closed(fd):
    os.close(fd);owned.remove(fd)
def directory(p,terminal=False):
    p=str(p)
    if p in dirs:return dirs[p][0]
    assert p.startswith('/') and len(dirs)<64
    if p=='/':fd=opened('/',os.O_RDONLY|os.O_DIRECTORY,terminal=terminal)
    else:
        parent,name=p.rsplit('/',1);pf=directory(parent or '/',terminal)
        ident=full9(os.stat(name,dir_fd=pf,follow_symlinks=False))[:5]
        fd=opened(name,os.O_RDONLY|os.O_DIRECTORY,pf,terminal)
        assert full9(os.fstat(fd))[:5]==ident
    dirs[p]=(fd,full9(os.fstat(fd))[:5]);return fd
def stable_dirs(terminal=False):
    for p,(fd,b) in dirs.items():
        before(terminal);assert full9(os.fstat(fd))[:5]==b
        if p!='/':
            parent,name=p.rsplit('/',1);assert full9(os.stat(name,dir_fd=dirs[parent or '/'][0],follow_symlinks=False))[:5]==b
def requested_read(fd,count,terminal=False):
    global requested,io_calls
    before(terminal)
    ceiling=268435456-written-(0 if terminal else 2097152)
    assert requested+count<=ceiling and io_calls+1<=8192
    requested+=count;io_calls+=1
    return os.read(fd,count)
def read(pin,cap,role,acquire_current=False,retain=False):
    global requested,reads,observation,phase
    before();phase=role+'-ancestry';p=Path(pin['path']);pf=directory(p.parent)
    phase=role+'-named';named=full9(os.stat(p.name,dir_fd=pf,follow_symlinks=False))
    observation=dict(role=role,expectedIdentity=pin['identity'],initialDescriptor=named,finalDescriptor=None,namedPath=None,
                     expectedBytes=pin['bytes'],returnedBytes=0,sha256=None,freshCurrentDonorAcquisition=acquire_current)
    assert stat.S_ISREG(named[2]) and named[8]==1 and 0<=named[5]<=cap and named[5]==pin['bytes']
    fd=opened(p.name,os.O_RDONLY|os.O_NONBLOCK,pf)
    try:
        initial=full9(os.fstat(fd));assert initial==named
        reads+=1;assert reads<=512
        phase=role+'-read';digest=hashlib.sha256();parts=[];left=pin['bytes'];returned=0
        while left:
            before();chunk=requested_read(fd,min(65536,left))
            # Count known payload returns before hashing/retention can fail; exclude the EOF probe.
            returned+=len(chunk);observation['returnedBytes']=returned
            assert chunk;digest.update(chunk);left-=len(chunk)
            if retain:parts.append(chunk)
        before();assert not requested_read(fd,1)
        after=full9(os.fstat(fd));current=full9(os.stat(p.name,dir_fd=pf,follow_symlinks=False))
        observation.update(initialDescriptor=initial,finalDescriptor=after,namedPath=current,returnedBytes=returned,sha256=digest.hexdigest())
        phase=role+'-correspondence'
        assert initial==after==current and returned==pin['bytes'] and digest.hexdigest()==pin['sha256']
        observation['historicalIdentityDifferences']=[i for i in range(9) if initial[i]!=pin['identity'][i]]
        # Fresh acquisition retains every historical difference. It never qualifies
        # the old read or claims continuity; independent acceptance supplies a new basis.
        if not acquire_current:assert initial==pin['identity']
        before();rows.append(observation);observation=None
        return b''.join(parts) if retain else None
    finally:closed(fd)
def create_result(value):
    global requested,written,reads
    before(True)
    # This immutable observation is provisional until complete transport and ordinary exit.
    cancellation_snapshot=cancelled
    value.update(provisional=True,cancellationObservedAtSnapshot=cancellation_snapshot,
                 passed=value['passed'] and not cancellation_snapshot)
    if cancellation_snapshot and value['failure'] is None:
        value['failure']=dict(phase='terminal-cancellation',type='InterruptedError',observation=None)
    raw=enc(value);assert len(raw)<=1048576
    pf=directory(R,True);fd=opened(OUTPUT.name,os.O_RDWR|os.O_CREAT|os.O_EXCL,pf,True)
    try:
        assert requested+2*len(raw)+1<=268435456
        written+=len(raw)
        assert os.write(fd,raw)==len(raw);os.fsync(fd);os.fchmod(fd,0o444);os.fsync(fd)
        ident=full9(os.fstat(fd));assert ident[2]==stat.S_IFREG|0o444 and ident[8]==1
        reads+=1;assert reads<=512 and requested+2*len(raw)+1<=268435456
        os.lseek(fd,0,os.SEEK_SET);before(True)
        assert requested_read(fd,len(raw),True)==raw and not requested_read(fd,1,True)
        assert ident==full9(os.fstat(fd))==full9(os.stat(OUTPUT.name,dir_fd=pf,follow_symlinks=False))
        os.fsync(pf);before(True)
        return dict(path=str(OUTPUT),bytes=len(raw),sha256=sha(raw),identity=ident)
    finally:closed(fd)
passed=False;result=None;close_failed=False;current_donors=[];original_inventory=None
try:
    assert sys.executable=='/usr/bin/python3.14' and sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode and len(sys.argv)==1
    resource.setrlimit(resource.RLIMIT_AS,(134217728,134217728));resource.setrlimit(resource.RLIMIT_CPU,(55,55))
    for sig in (signal.SIGTERM,signal.SIGINT):signal.signal(sig,stop)
    assert isinstance(R,Path) and isinstance(REPORT,Path) and isinstance(OUTPUT,Path)
    assert R.is_absolute() and OUTPUT.parent==R and REPORT.is_relative_to(R)
    assert isinstance(COMMIT,str) and len(COMMIT)==40 and set(COMMIT)<=set('0123456789abcdef')
    assert REPORT_PIN is not None and REPORT_PIN['path']==str(REPORT)
    phase='report';actual=json.loads(read(REPORT_PIN,1048576,'report',retain=True))
    assert actual['schema']=='private-compile-actual-local-inputs-v1' and actual['action']=='0190' and actual['sourceCommit']==COMMIT
    assert actual['originalExternalDescriptorsPreserved']==365 and actual['newLocalCompilerInputs']==48
    a=actual['admissionBase'];assert a['action']=='0190' and a['suite']=='compile' and a['sourceCommit']==COMMIT
    original_inventory=a['inventory']
    controls={}
    for role,cap in [('inventory',1048576),('sourceMap',65536),('checkpoint',65536),('caller',2097152),('controller',2097152),('catalog',1048576),('protocol',2097152)]:
        controls[role]=read(a[role],cap,'control-'+role,retain=role in ('inventory','sourceMap','checkpoint'))
    phase='fixed-selection';inventory=json.loads(controls['inventory']);files=inventory['files']
    assert inventory['schema']=='windows-controlled-harness-files-v1' and len(files)==413
    assert len({x['relativePath'] for x in files})==413 and sha(enc(files[:365]))==DONORS_SHA
    assert json.loads(controls['checkpoint'])['ceilings']==[100,400,60,1200]
    for role in ('python','systemdRun','launcher'):read(a[role],8388608,'infrastructure-'+role)
    for role in ('interop','runtimeDirectory'):
        before();phase='infrastructure-'+role;p=Path(a[role]['path']);pf=directory(p.parent)
        current=full9(os.stat(p.name,dir_fd=pf,follow_symlinks=False))
        observation=dict(role=role,expectedIdentity=a[role]['identity'],initialDescriptor=current)
        assert current==a[role]['identity'];rows.append(observation);observation=None
    for ordinal,item in enumerate(files):
        read(item['descriptor'],67108864,'input-'+str(ordinal),acquire_current=ordinal<365)
        if ordinal<365:
            pin=dict(item['descriptor']);pin['identity']=list(rows[-1]['initialDescriptor'])
            current_donors.append(dict(relativePath=item['relativePath'],descriptor=pin))
    assert len(current_donors)==365
    phase='final-ancestry';stable_dirs();before();passed=True
except Exception as error:
    failure=dict(phase=phase,type=type(error).__name__,observation=observation)
else:failure=None
try:
    stable_dirs(True)
    value=dict(schema='windows-controlled-compile-current-input-observation-v1',action='0190',sourceCommit=COMMIT,
               passed=passed,failure=failure,rows=rows,inputRowsPassed=sum(x.get('role','').startswith('input-') for x in rows),
               requestedReadBytesBeforeOutcome=requested,readPassesBeforeOutcome=reads,readCallsBeforeOutcome=io_calls,elapsedSeconds=time.monotonic()-START,
               historicalDonorDescriptorsPreserved=True,originalInventory=original_inventory,
               originalDonorsSha256=DONORS_SHA,currentDonors=current_donors,
               currentDonorsSha256=sha(enc(current_donors)),historicalSuccessClaimed=False,
               compilerSubmitted=False,windowsStarts=0,accountAccess=False)
    result=create_result(value);stable_dirs(True)
except Exception:passed=False;result=None
finally:
    while owned:
        fd=owned.pop()
        try:os.close(fd)
        except OSError:close_failed=True
# No terminal success bytes or prepared exit value can override a later handled signal.
terminal_disposition=True
if close_failed or result is None:raise SystemExit(1)
passed=passed and not cancelled
before(True)
raw=enc(dict(passed=passed,cancellationObserved=cancelled,sealedOutcomeProvisional=True,result=result,requestedReadBytes=requested,writtenBytes=written,readPasses=reads,readCalls=io_calls,ownedDescriptorsClosed=True,compilerSubmitted=False))
assert len(raw)<=2048 and os.write(1,raw)==len(raw);before(True)
raise SystemExit(0 if passed else 1)
