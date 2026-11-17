"""Selected evaluation plots, with case-wise CPU/gas sums and source reconciliation."""
import csv
import hashlib
import json
import statistics
import math
from pathlib import Path
from verify_composite import require

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

GROUPS = [f'{w}-{n}' for w in ['regulatory_qoe_compliance', 'regional_qoe_compliance'] for n in [16,32,50]]
LABELS = ['16 sessions', '32 sessions', '50 sessions'] * 2
Y = np.array([0,1,2,4,5,6])
BLUE, ORANGE, GREEN, GRAY, YELLOW = '#0072B2', '#D55E00', '#009E73', '#999999', '#E69F00'
plt.rcParams.update({'font.family':'DejaVu Serif', 'font.size':8.5, 'axes.titlesize':9,
                     'axes.labelsize':8.5, 'legend.fontsize':7.6, 'xtick.labelsize':8,
                     'ytick.labelsize':8, 'pdf.fonttype':42, 'ps.fonttype':42,
                     'axes.spines.top':False, 'axes.spines.right':False,
                     'axes.spines.left':False, 'svg.hashsalt':'vc-fhe-workflow-figures-v1', 'svg.fonttype':'none', 'savefig.dpi':300})

SELECTED = {'linear':['linear-cost'], 'nonlinear':['nonlinear-work','workflow-gas']}
LINEAR_CAPTION = (r'Linear verification. (a) Off-chain admission and aggregate verification using commitments and '
    r'signatures versus BLS signatures and reaggregation. (b) Proposed admissions and result submission '
    r'(output digest and commitment). Means with sample SD from 100 pairs in (a) and five full cases in (b).')
WORK_CAPTION = (r'QoE tasks count all inputs, including sessions outside the selected area. '
    r'(a) One full audit versus two full baseline recomputations, excluding signing, chain waits and decryption. '
    r'(b) After auditing and bisection, two certifiers per method: one disputed instruction (upper) or the full program (lower). '
    r'CPU separates FHE processes from task checks/signing, including overhead but excluding context certification, operator work and full auditing. '
    r'Means with sample SD from 30 pairs in (a) and five cases in (b).')




def gas_caption(data):
    costs=[]
    for steps,label in [(['shared_deployment','collateral_setup'],'Shared setup'),
                        (['baseline_deployment'],'Baseline deployment'),
                        (['step2_baseline_certificate'],'Baseline acceptance')]:
        rows=[data.measure('workflow-gas',g,'full-honest',[(s,'gasUsed') for s in steps],
                           'Excluded: '+label,1e6)[0] for g in GROUPS]
        for row in rows:
            row['display']='caption'
        values=sorted({f"{r['mean']:.3f}" for r in rows},key=float)
        costs.append('$'+values[0]+('$' if len(values)==1 else '$--$'+values[-1]+'$'))
    return (r'Gas by workflow stage. Setup: registration, consent, context and auditor selection. '
            r'Release approval: record registration, decryption approval and request reservation. '
            r'Audit opening: commitment and reveal. Settlement: evidence admission, certificate verification and withdrawals. '
            r'Means and total sample SD from five cases. Horizontal scales differ. '
            'Excluded (million gas): shared setup '+costs[0]+', baseline deployment '+costs[1]+
            ' and baseline acceptance '+costs[2]+'. Percentages: release approval (a), '
            'challenge/disclosure (b), relative to plotted totals.')



class Dataset:
    def __init__(self, report, observations):
        from distributed_profile import is_distributed
        self.distributed=is_distributed(report)
        self.full_count=3 if self.distributed else 5
        self.metrics = report["metrics"]
        self.observations = observations
        self.points = []

    def measure(self, figure, group, cohort, components, name, divisor=1, count=None):
        """Sum disjoint measured components within each case, then calculate sample SD."""
        count=self.full_count if count is None else count
        cases = {}
        for r in self.observations:
            key = (r['step'], r['metric'])
            if r['group'] == group and r['cohort'] == cohort and key in components:
                bucket = cases.setdefault(r['case'], {})
                require(key not in bucket, 'duplicate figure observation')
                bucket[key] = float(r['value'])
                require(math.isfinite(bucket[key]) and bucket[key]>=0, 'invalid figure observation')
        require(len(cases) == count, 'incomplete figure cases: '+group+' '+name)
        require(all(set(c) == set(components) for c in cases.values()), 'missing figure component')
        values = [sum(c.values()) / divisor for c in cases.values()]
        result = {'figure':figure, 'group':group, 'cohort':cohort, 'series':name,
                  'mean':statistics.mean(values), 'sample_sd':statistics.stdev(values),
                  'n':count, 'divisor':divisor, 'components':json.dumps(components), 'display':'plot'}
        # Independently reconcile each underlying metric with the published summary.
        for step, metric in components:
            rows = [r for r in self.metrics if (r['group'],r['cohort'],r['step'],r['metric']) ==
                    (group,cohort,step,metric)]
            require(len(rows) == 1, 'ambiguous figure metric')
            vals = [c[(step,metric)] for c in cases.values()]
            require(abs(statistics.mean(vals)-rows[0]['mean']) < 1e-6, 'figure mean mismatch')
            require(abs(statistics.stdev(vals)-rows[0]['sampleSd']) < 1e-6, 'figure SD mismatch')
            require(rows[0]['observations'] == count, 'figure observation count mismatch')
        self.points.append(result)
        return result, cases
    

def save(fig, name, data, output, caption):
    if data.distributed:caption=caption.replace('five cases','three cases').replace('five full','three full')
    metadata = {'Title':name, 'Subject':caption, 'Creator':'VC-FHE workflow_figures.py',
                'CreationDate':None, 'ModDate':None}
    fig.savefig(output / (name+'.pdf'), bbox_inches='tight', pad_inches=.035, metadata=metadata)
    fig.savefig(output / (name+'.png'), bbox_inches='tight', pad_inches=.035)
    fig.savefig(output / (name+'.svg'), bbox_inches='tight', pad_inches=.035,
                metadata={'Date':None, 'Description':caption})
    plt.close(fig)
    rows = [r for r in data.points if r['figure']==name]
    with (output/(name+'.csv')).open('x', newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    (output/(name+'.json')).write_text(json.dumps({'caption':caption,'rows':rows},indent=2)+'\n')
    return {'name':name,'caption':caption,'series':sorted({r['series'] for r in rows}),
            'formats':['pdf','png','svg','csv','json']}


def workload_labels(ax, offset=.60):
    ax.set_yticks(Y,LABELS)
    ax.set_ylim(6.5,-1.15)
    for y,label in [(-.85,'All sessions'),(3.15,'Selected area')]:
        ax.text(-offset,y,label,transform=ax.get_yaxis_transform(),ha='left',va='center',
                fontsize=8,fontweight='bold',clip_on=False)


def verification_bars(ax, data, evidence):
    """Merge the existing certification components with context and audit CPU."""
    from verification_budget import summary
    specs = [(-.26, 'Proposed, correct', ['context_honest_s', 'audit_honest_s']),
             (0, 'Baseline, correct', ['context_honest_s', 'full_checks_s', 'full_fhe_s']),
             (.26, 'Proposed, faulty', ['context_faulty_s', 'audit_faulty_s', 'leaf_checks_s', 'leaf_fhe_s'])]
    colors = [('context', 'Context', GRAY, ''), ('audit', 'Full audit', GREEN, '...'),
              ('checks', 'Result checks/signing', BLUE, ''), ('fhe', 'Result FHE', ORANGE, '///')]
    labelled, maximum = set(), 0
    for offset, name, keys in specs:
        left = np.zeros(len(GROUPS))
        for key in keys:
            kind, label, color, hatch = next(x for x in colors if x[0] in key)
            means = []
            for group in GROUPS:
                mean, sd, n = summary(evidence, group, [key])
                means.append(mean)
                data.points.append(dict(figure='nonlinear-work',group=group,cohort='full-verification',
                    series=name+': '+label,mean=mean,sample_sd=sd,n=n,divisor=1,
                    components=json.dumps([['recorded_worker_cpu_s',key]]),display='component'))
            ax.barh(Y+offset,means,left=left,height=.22,color=color,hatch=hatch,
                    label=label if kind not in labelled else None,edgecolor='black',linewidth=.2)
            labelled.add(kind)
            left += np.array(means)
        totals = [summary(evidence, group, keys) for group in GROUPS]
        require(all(abs(total[0]-value)<1e-8 for total,value in zip(totals,left)), 'verification stack mismatch')
        ax.errorbar(left,Y+offset,xerr=[s for _,s,_ in totals],fmt='none',ecolor='black',capsize=2,lw=.7,zorder=3)
        for group,(mean,sd,n) in zip(GROUPS,totals):
            data.points.append(dict(figure='nonlinear-work',group=group,cohort='full-verification',
                series=name,mean=mean,sample_sd=sd,n=n,divisor=1,
                components=json.dumps([['recorded_worker_cpu_s',k] for k in keys]),display='plot'))
            maximum=max(maximum,mean+sd)
    return maximum*1.08


def comparison(data, output, timing=None, verification=None):
    require(verification is None or (timing and data.distributed), 'verification budget requires geographic evidence')
    fig, axes = plt.subplots(1,3 if timing else 2,
        figsize=(6.5,2.45 if verification else (2.2 if timing else 2.3)), sharey=True)
    fig.subplots_adjust(left=.18 if timing else .21, right=.985, bottom=.17 if verification else .20,
        top=.75 if verification else (.76 if timing else .78), wspace=.32 if timing else .28)
    specs = [
        ('paired', [('step2','proposed_verification')], [('step2','baseline_verification')], 30,
         '(a) Full recomputation', 'Elapsed time (s)',
         'Proposed: 1 auditor', 'Baseline: 2 certifiers'),
        ('full', [('comparison','adjudicator_leaf_complete_cpu_ms'),
                  ('comparison','remote_fhe_challenged_leaf_complete_cpu_ms')],
                 [('comparison','adjudicator_full_complete_cpu_ms'),
                  ('comparison','remote_fhe_honest_baseline_complete_cpu_ms')], data.full_count,
         '(b) Result certification', 'CPU time (s)',
         'Proposed: 1 instruction', 'Baseline: full program')]
    for ax, (cohort, pkeys, bkeys, n, title, xlabel, pname, bname) in zip(axes,specs):
        proposed, baseline = [], []
        for group in GROUPS:
            proposed.append(data.measure('nonlinear-work',group,cohort,pkeys,pname,1000,n)[0])
            baseline.append(data.measure('nonlinear-work',group,cohort,bkeys,bname,1000,n)[0])
        if cohort == 'full':
            for series,keys,offset,short in [(proposed,pkeys,-.17,'Leaf'),(baseline,bkeys,.17,'Full')]:
                controller, native = [], []
                for group in GROUPS:
                    for destination,component,part in [(controller,keys[0],'Certification processes'),
                                                       (native,keys[1],'FHE processes')]:
                        row=data.measure('nonlinear-work',group,cohort,[component],short+': '+part,1000,n)[0]
                        row['display']='component'
                        destination.append(row['mean'])
                require(all(abs(c+f-total['mean'])<1e-8 for c,f,total in zip(controller,native,series)),
                        'certification components do not reproduce totals')
                if verification:
                    for row in series:
                        row['display']='component'
                    continue
                ax.barh(Y+offset,controller,height=.29,color=BLUE,
                        label='Task checks and signing' if short=='Leaf' else None)
                ax.barh(Y+offset,native,left=controller,height=.29,color=ORANGE,hatch='///',
                        label='FHE processes' if short=='Leaf' else None,edgecolor='black',linewidth=.25)
                ax.errorbar([r['mean'] for r in series],Y+offset,xerr=[r['sample_sd'] for r in series],
                            fmt='none',ecolor='black',capsize=2,lw=.7,zorder=3)
            if timing is None:
                ax.text(0,-.80,'Upper: instruction / lower: full program',va='center',fontsize=7.2)
            if verification:
                cpu_max=verification_bars(ax,data,verification)
                title='(b) Verification CPU'
        else:
            for y,p,b in zip(Y,proposed,baseline):
                ax.plot([p['mean'],b['mean']],[y,y],color='#AAAAAA',lw=1.4,zorder=1)
            for series, color, marker, label in [(proposed,BLUE,'o',pname),(baseline,ORANGE,'s',bname)]:
                ax.errorbar([r['mean'] for r in series],Y,xerr=[r['sample_sd'] for r in series],
                            fmt=marker,color=color,ms=4,capsize=2,lw=.8,label=label,zorder=2)
        ax.set_title(title,pad=56 if verification else (42 if timing else 31),loc='left',fontweight='bold')
        ax.legend(loc='lower left',bbox_to_anchor=(-.025,1.015),frameon=False,handletextpad=.5,borderpad=0)
        ax.set_xlabel(xlabel)
        ax.set_xlim(0,max(19 if cohort=='paired' else 28,
                         max(r['mean']+r['sample_sd'] for r in proposed+baseline)*1.12))
        if verification and cohort=='full':
            ax.set_xlim(0,cpu_max)
        if not data.distributed:
            ax.set_xticks([0,5,10,15] if cohort=='paired' else [0,10,20])
        else:
            from matplotlib.ticker import MaxNLocator
            ax.xaxis.set_major_locator(MaxNLocator(nbins=4))
        ax.grid(axis='x',color='#DDDDDD',lw=.5)
        ax.set_axisbelow(True)
        ax.axhline(2.65,color='#CCCCCC',lw=.6)
        ax.tick_params(axis='y',length=0)
    workload_labels(axes[0], .80 if timing else .60)
    if timing:
        from decision_timing import summary
        ax = axes[2]
        left = np.zeros(len(GROUPS))
        for metric, label, color in [('before_challenge_blocks','Before challenge',GRAY),
                                    ('challenge_decision_blocks','Challenge to decision',ORANGE),
                                    ('after_decision_blocks','After decision',GREEN)]:
            values = []
            for group in GROUPS:
                mean, sd, n = summary(timing,group,metric)
                values.append(mean)
                data.points.append(dict(figure='nonlinear-work',group=group,cohort='full-challenged',
                    series=label,mean=mean,sample_sd=sd,n=n,divisor=1,
                    components=json.dumps([['receipt_blocks',metric]]),display='plot'))
            ax.barh(Y,values,left=left,height=.54,color=color,
                    label={'Before challenge':'Before challenge','Challenge to decision':'Challenge to rejection',
                           'After decision':'Bond release / payout'}[label])
            left += np.array(values)
        # All observed decision endpoints, not an artificial seconds conversion.
        for i,group in enumerate(GROUPS):
            points=[r['before_challenge_blocks']+r['challenge_decision_blocks'] for r in timing if r['group']==group]
            ax.plot(points,[Y[i]]*len(points),'|',color='black',ms=7,mew=.7)
        ax.set_title('(c) Dispute decision',pad=56 if verification else 42,loc='left',fontweight='bold')
        ax.legend(loc='lower left',bbox_to_anchor=(-.025,1.015),frameon=False,handletextpad=.5,borderpad=0)
        ax.set_xlabel('Blocks since request')
        ax.set_xlim(0,255)
        ax.set_xticks([0,100,200])
        ax.grid(axis='x',color='#DDDDDD',lw=.5)
        ax.set_axisbelow(True)
        ax.axhline(2.65,color='#CCCCCC',lw=.6)
        ax.tick_params(axis='y',length=0)
    caption=WORK_CAPTION
    if data.distributed:
        caption += ' Remote times in (a) include public-data transfers. Baseline certifiers run concurrently on separate hosts.'
    if timing:
        bounds = lambda key: (min(r[key] for r in timing), max(r[key] for r in timing))
        before, decision, after = [bounds(k) for k in ['before_challenge_blocks','challenge_decision_blocks','after_decision_blocks']]
        total = bounds('request_decision_blocks')
        require(after[0] == after[1], 'withdrawal interval no longer invariant')
        caption = (r'QoE task sizes include inputs outside the selected area. '
            r'(a) One audit versus two concurrent baseline recomputations on separate hosts, including public transfers but '
            r'excluding signing, chain waits and decryption. (b) Two certifiers per method: instruction (upper), full program (lower). '
            r'CPU includes process overhead, excluding context certification, operator work and full auditing. '
            r'Means from 30 pairs (a) and three cases (b,c). Error bars show sample SD. '
            r'In (c), ticks mark on-chain rejection. Ranges: '
            f'{before[0]}--{before[1]} blocks from disclosure request to challenge, {decision[0]}--{decision[1]} to rejection '
            f'({total[0]}--{total[1]} from request), then {after[0]} for unused bond releases and reward withdrawal. Blocks include phase waits.')
        if verification:
            caption=caption.removeprefix('QoE task sizes include inputs outside the selected area. ')
            caption=caption.replace(
                r'(b) Two certifiers per method: instruction (upper), full program (lower). '
                r'CPU includes process overhead, excluding context certification, operator work and full auditing. ',
                r'(b) Top to bottom: proposed/correct, baseline/correct, proposed/faulty. '
                r'Context and result certificates each use two workers. Context is counted once per alternative. '
                r'Result checks/signing and FHE certify the full program (baseline) or disputed instruction (faulty task). '
                r'CPU excludes operator, owners, chain, KMS and orchestration outside measured processes. ')

    return save(fig,'nonlinear-work',data,output,caption)


def gas(data, output):
    fig, axes = plt.subplots(1,2,figsize=(6.5,2.8),sharey=True)
    fig.subplots_adjust(left=.21,right=.99,bottom=.31,top=.88,wspace=.28)
    setup = ['step1_owner_admission','step1_task_context','step2_sampling']
    specs = [
        ('full-honest','(a) Accepted task',
         [('Task setup',setup,GRAY,''),
          ('Finalization',['step2_finality'],BLUE,'///'),
          ('Release approval',['release_setup','release_authorization'],YELLOW,'...')],27,[0,10,20]),
        ('full-challenged','(b) Rejected task',
         [('Task setup',setup,GRAY,''),
          ('Audit opening',['step2_dispute_audit'],BLUE,'///'),
          ('Challenge/disclosure',['step3_challenge_disclosure'],ORANGE,''),
          ('Bisection',['step3_bisection'],YELLOW,'...'),
          ('Admission/settlement',['step4_admission_settlement'],GREEN,'xxx')],175,[0,50,100,150])]
    for ax,(cohort,title,stages,xmax,ticks) in zip(axes,specs):
        left=np.zeros(6)
        highlighted=None
        for label, steps, color, hatch in stages:
            rows=[data.measure('workflow-gas',g,cohort,[(s,'gasUsed') for s in steps],label,1e6)[0] for g in GROUPS]
            means=np.array([r['mean'] for r in rows])
            ax.barh(Y,means,left=left,height=.60,color=color,label=label,hatch=hatch,
                    edgecolor='white',linewidth=.25)
            if label in ('Release approval','Challenge/disclosure'):
                highlighted=(left.copy(),means.copy())
            left += means
        totals=[data.measure('workflow-gas',g,cohort,[(s,'gasUsed') for _,ss,_,_ in stages for s in ss],
                        'Plotted task total',1e6)[0] for g in GROUPS]
        ax.errorbar(left,Y,xerr=[r['sample_sd'] for r in totals],fmt='none',ecolor='black',capsize=2,lw=.7)
        start,width=highlighted
        for x,w,total,y in zip(start,width,left,Y):
            ax.text(x+w*(.5 if cohort=='full-challenged' else .32),y,f'{100*w/total:.0f}%',
                    ha='center',va='center',fontsize=7.2,zorder=4,
                    color='white' if cohort=='full-challenged' else 'black',fontweight='bold',
                    bbox=dict(facecolor=ORANGE if cohort=='full-challenged' else YELLOW,edgecolor='none',pad=.05))
        for x,y,total in zip(left,Y,totals):
            ax.text(x+total['sample_sd']+xmax*.025,y,f'{x:.1f}',va='center',fontsize=7.2)
        ax.set_title(title,pad=8,loc='left',fontweight='bold')
        ax.set_xlabel('Gas (millions)')
        ax.set_xlim(0,max(xmax,max(r['mean']+r['sample_sd'] for r in totals)*1.16))
        ax.set_xticks(ticks)
        ax.grid(axis='x',color='#DDDDDD',lw=.5)
        ax.set_axisbelow(True)
        ax.axhline(2.65,color='#CCCCCC',lw=.6)
        ax.tick_params(axis='y',length=0)
        ax.legend(loc='upper left',bbox_to_anchor=(-.025,-.23),frameon=False,handlelength=1.3,
                  labelspacing=.38,borderpad=0)
    workload_labels(axes[0])
    return save(fig,'workflow-gas',data,output,gas_caption(data))


def linear(data, output):
    fig,axes=plt.subplots(1,2,figsize=(6.5,2.1))
    fig.subplots_adjust(left=.09,right=.985,bottom=.21,top=.75,wspace=.35)
    ns=[10,16,27]
    for variant,color,marker,label in [('proposed',BLUE,'o','Proposed'),
                                      ('baseline',ORANGE,'s','BLS baseline')]:
        rows=[data.measure('linear-cost',f'linear-acr-{n}','paired',[('step2',variant+'_verification')],label,1000,100)[0] for n in ns]
        axes[0].errorbar(ns,[r['mean'] for r in rows],yerr=[r['sample_sd'] for r in rows],color=color,
                         marker=marker,ms=4,capsize=2,lw=1,label=label)
    axes[0].set_title('(a) Verification time',loc='left',pad=34,fontweight='bold')
    axes[0].legend(loc='lower left',bbox_to_anchor=(-.03,1.01),frameon=False,borderpad=0)
    axes[0].set_ylabel('Elapsed time (s)')
    axes[0].set_ylim(bottom=0)
    for step,color,marker,label in [('step1_owner_admission',BLUE,'o','Record admissions'),
                                   ('step2_result',ORANGE,'s','Result submission')]:
        rows=[data.measure('linear-cost',f'linear-acr-{n}','full-honest',[(step,'gasUsed')],label,1e6,data.full_count)[0] for n in ns]
        axes[1].errorbar(ns,[r['mean'] for r in rows],yerr=[r['sample_sd'] for r in rows],color=color,
                         marker=marker,ms=4,capsize=2,lw=1,label=label)
    axes[1].set_title('(b) Contract gas',loc='left',pad=34,fontweight='bold')
    axes[1].legend(loc='lower left',bbox_to_anchor=(-.03,1.01),frameon=False,borderpad=0)
    axes[1].set_ylabel('Gas (millions)')
    axes[1].set_ylim(bottom=0)
    for ax in axes:
        ax.set_xlabel('Encrypted user ratings')
        ax.set_xticks(ns)
        ax.grid(axis='y',color='#DDDDDD',lw=.5)
        ax.set_axisbelow(True)
    return save(fig,'linear-cost',data,output,LINEAR_CAPTION)


def generate_selected(report, observations, output, half, timing=None, verification=None):
    """Render the experiment's three figures only when their complete evidence is present."""
    require(half in ('linear','nonlinear','both'), 'invalid selected figure scope')
    data = Dataset(report, observations)
    figures = []
    if half != 'nonlinear':
        figures.append(linear(data, output))
    if half != 'linear':
        # The comparison caption describes two actual recomputing workers per arm.
        for group in GROUPS:
            for metric in ['adjudicator_leaf_cpu_measured_workers', 'adjudicator_full_cpu_measured_workers',
                           'remote_fhe_challenged_leaf_cpu_measured_commands',
                           'remote_fhe_honest_baseline_cpu_measured_commands']:
                rows = [r for r in observations if (r['group'],r['cohort'],r['step'],r['metric']) ==
                        (group,'full','comparison',metric)]
                require(len(rows)==data.full_count and len({r['case'] for r in rows})==data.full_count
                        and all(float(r['value'])==2 for r in rows), 'two-certifier evidence missing: '+metric)
        figures.extend([comparison(data, output, timing, verification),gas(data, output)])
    return figures


