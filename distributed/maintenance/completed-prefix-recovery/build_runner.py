"""Generate a separately versioned driver from the retained C3 lifecycle driver."""
from pathlib import Path
import hashlib
HERE=Path(__file__).parent
SOURCE=HERE.parent/'workflow-recovery'
EXPECTED='893c72ca30c5a75209a3cd6409aadab5716627031167db9127968216c9c61ff5'
def build():
 s=(SOURCE/'continue.py').read_text()
 if hashlib.sha256(s.encode()).hexdigest()!=EXPECTED:raise ValueError('Retained driver source changed')
 def edit(old,new):
  nonlocal s
  if s.count(old)!=1:raise ValueError('Lifecycle source anchor changed: '+old[:90])
  s=s.replace(old,new)
 edit('Explicit workflows-only continuation after a verified, unused release prefix.','Versioned continuation of the remaining 17 cases after ten validated releases.')
 edit("manifest['profile']=='distributed-same-keyset-workflows-only-v1'","manifest['profile']=='distributed-completed-prefix-continuation-v1'")
 edit("tag in ('workflows-c1','workflows-c2','workflows-c3')","tag=='workflows-c4'")
 edit("from transforms import retention_overlay","from retention_transforms import retention_overlay")
 edit("self.base+'/'+host+'/workflow-continuation-compose/compose.json'","self.base+'/'+host+'/completed-prefix-compose/compose.json'")
 edit("    from cloud_results.owner_materials import collect as collect_public_owner_witnesses\n    from collect import collect as collect_original\n    def continued_collect(self):\n        collect_public_owner_witnesses(self);collect_original(self)\n        self.private_preservation=retention.preserve_hosts(self)","    from collect_segment import collect\n    def continued_collect(self):\n        collect(self)\n        self.private_preservation=retention.preserve_hosts(self)")
 start="    parent_state=read(Path(prepared['parentRun'])/'launch-state.json')"
 end="    for remote in worker.remotes.values():remote.read_deadline=deadline"
 begin=s.index(start);finish=s.index(end,begin)+len(end)
 s=s[:begin]+'''    envelope=read(continuation/'budget-runtime.json')
    from window import check
    check(envelope,now())
    window=envelope['continuationWindow']
    original_start=datetime.fromisoformat(envelope['startedAt'])
    window_start=datetime.fromisoformat(window['startedAt'])
    elapsed=(datetime.now(timezone.utc)-window_start).total_seconds()
    worker.started=time.monotonic()-elapsed
    worker.quote={**worker.quote,'planned_hours':window['hours']}
    deadline=worker.started+window['hours']*3600
    require(deadline-time.monotonic()>20*3600,'Preparation consumed too much renewed window')
    write(continuation/'cumulative-accounting.json',{'originalStartedAt':envelope['startedAt'],
        'continuationStartedAt':window['startedAt'],'elapsedBeforeWindowHours':window['pastElapsedHours'],
        'costAccountingReset':False,'protocolDeadlinesChanged':False},new=True)
    for remote in worker.remotes.values():remote.read_deadline=deadline
''' + s[finish:]
 edit("old_compose=worker.base+'/'+host['id']+'/compose.json'","old_compose=worker.base+'/'+host['id']+'/workflow-continuation-compose/compose.json'")
 edit("logs_dir=worker.base+'/'+host['id']+'/predecessor-container-logs'","logs_dir=worker.base+'/'+host['id']+'/predecessor-c3-container-logs'")
 edit("remote.run(['sudo','docker','compose','-f',worker.base+'/'+host['id']+'/workflow-continuation-compose/compose.json',", "remote.run(['sudo','docker','compose','-f',worker.base+'/'+host['id']+'/completed-prefix-compose/compose.json',")
 # C3 failure did not stop the sampler via its file. A separate new stop file
 # still prevents ambiguity even when prior sampling was terminated by VM stop.
 s=s.replace("sampler+'/stop-sampler'","sampler+'/stop-sampler-c4'")
 s=s.replace("worker.base+'/'+host+'/stop-sampler'","worker.base+'/'+host+'/stop-sampler-c4'")
 edit("tag in ('workflows-c2','workflows-c3')","tag=='workflows-c4'")
 edit("if tag!='workflows-c3':open_gate('recipient-1')","if tag!='workflows-c4':open_gate('recipient-1')")
 edit("if tag=='workflows-c3':","if tag=='workflows-c4':")
 edit("expected['manifest.json']=sha(continuation/'manifest.json')","expected['manifest.json']=sha(continuation/'manifest.json')\n        expected['prefix-validation.json']=sha(continuation/'prefix-validation.json')")
 edit("'originalDeadlineMaintained':True,'fullWorkflows':27","'renewedFiniteWindowHours':22,'completedPreserved':10,'pendingWorkflows':17")
 edit("'manifest.json','config.json','retention.py'","'manifest.json','config.json','retention.py','guard.mjs','prefix-validation.json'")
 # Never overwrite original sampler bytes. collect_segment preserves all source
 # segments and emits an explicit inventory, not an unlabelled concatenation.
 start=s.index('        # Preserve both sampling segments')
 end=s.index("        worker.stage('Collect and validate continued evidence',worker.collect)",start)
 s=s[:start]+"        for host,remote in worker.remotes.items():remote.run(['sudo','touch',worker.base+'/'+host+'/stop-sampler-c4'])\n        time.sleep(12)\n"+s[end:]
 start=s.index("        worker.state.update(status='completed',evaluationStatus='pending-publication')")
 end=s.index('    except BaseException as error:',start)
 s=s[:start]+'''        worker.state.update(status='segment-completed-preserved',evaluationStatus='pending-composite-validation',
            completedPrefixPreserved=10,completedNewWorkflows=17)
        write(segment/'launch-state.json',worker.state)
        receipt={'status':'segment-completed-preserved','completedPrefix':10,'completedNewWorkflows':17,
            'fullCampaignPublicationReady':False,'createdAt':now(),
            'rawPreservation':compact_hosts(worker.private_preservation),
            'sourceCheckpoint':source_receipt,'manifestSha256':sha(continuation/'manifest.json')}
        write(continuation/'segment-completed.json',receipt,new=True)
        stored=store.upload(continuation/'segment-completed.json','runs/'+job['jobId']+'/segment-completed.json')
        store.download(stored,continuation/'segment-completed.readback.json',maximum=2*1024**2)
        worker.stop()
        write(continuation/'segment-stop-confirmed.json',{'observedAt':now(),'protocolComputeStopped':True,
            'publicationPending':True},new=True)
''' + s[end:]
 s='# Generated by build_runner.py from the source-hash-checked retained C3 lifecycle.\n'+s
 (HERE/'runner.py').write_text(s)
 # These are off-path copies, original helpers are not edited.
 retention=(SOURCE/'transforms.py').read_text()
 retention += '''

_capacity_only_overlay = retention_overlay
def retention_overlay(source, gib=256, *, scratch=False):
    result = _capacity_only_overlay(source,gib,scratch=scratch)
    result = once(result, '    deployment.campaign_module().verify(campaign.run)',
        '    from collect_segment import verify_preservation_guard\\n    verify_preservation_guard(campaign.run)')
    return once(result,
        "    require(len(app['cases'])==27 and read(campaign.run/'state.json')['status']=='passed','Full source is incomplete')",
        "    require(len(app['cases'])==17 and app['status']=='passed','Pending segment is incomplete')")
'''
 (HERE/'retention_transforms.py').write_text(retention)
 storage=(SOURCE/'continuation_storage.py').read_text()
 old="    expected='/var/tmp/vcfhe-private-archive-'+digest({'run':str(campaign.run),'config':digest(campaign.config)})[:32]"
 new="    from cloud_results.common import read\n    parent=read(campaign.run/'distributed/workflow-continuation/manifest.json')['parentRun']\n    require(Path(parent).name==parent,'Unsafe predecessor identity')\n    expected='/var/tmp/vcfhe-private-archive-'+digest({'run':str(campaign.run.with_name(parent)),'config':digest(campaign.config)})[:32]"
 assert storage.count(old)==1
 (HERE/'continuation_storage.py').write_text(storage.replace(old,new))
 return s
if __name__=='__main__':build()
