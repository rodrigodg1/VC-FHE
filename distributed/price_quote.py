"""Current catalog rates plus explicit, unmeasured planning quantities."""
from datetime import datetime,timezone
from decimal import Decimal, ROUND_CEILING
import json
import subprocess
import urllib.parse
import urllib.request
import budget
from cloud_tools import ensure
import topology

CATALOG='https://cloudbilling.googleapis.com/v1/'
NETWORK_SOURCE='https://cloud.google.com/vpc/network-pricing'
BUILD_SOURCE='https://cloud.google.com/build/pricing?hl=en'

def price(sku):
    expression=sku['pricingInfo'][-1]['pricingExpression']
    values=[Decimal(r['unitPrice'].get('units','0'))+Decimal(r['unitPrice'].get('nanos',0))/10**9 for r in expression['tieredRates']]
    return max(values),expression

def catalog(project,service):
    token=subprocess.check_output(['gcloud','auth','print-access-token'],text=True).strip()
    values=[];page=''
    for _ in range(40):
        params={'currencyCode':'USD','pageSize':5000}
        if page:params['pageToken']=page
        request=urllib.request.Request(CATALOG+service+'/skus?'+urllib.parse.urlencode(params),
            headers={'Authorization':'Bearer '+token,'X-Goog-User-Project':project})
        response=json.load(urllib.request.urlopen(request,timeout=60));values.extend(response.get('skus',[]))
        page=response.get('nextPageToken')
        if not page:return values
    raise ValueError('catalog pagination exceeded its bound')

def compute_rates(config,skus):
    details=[];compute=Decimal(0);disks=Decimal(0)
    def choose(region,condition):
        found=[s for s in skus if region in s.get('serviceRegions',[]) and s.get('category',{}).get('usageType')=='OnDemand' and condition(s)]
        if len(found)!=1:raise ValueError('ambiguous or missing current SKU in '+region)
        return found[0]
    for host in topology.hosts(config):
        region=host['region'];cpus=int(host['machine_type'].rsplit('-',1)[1])
        family='N2D AMD' if host['machine_type'].startswith('n2d-') else 'N2'
        core=choose(region,lambda s:s['description'].startswith(family+' Instance Core running in '))
        ram=choose(region,lambda s:s['description'].startswith(family+' Instance Ram running in '))
        disk=choose(region,lambda s:s['description'].startswith('Balanced PD Capacity'))
        c,ce=price(core);r,re=price(ram);d,de=price(disk)
        if ce['usageUnit']!='h' or re['usageUnit']!='GiBy.h' or de['usageUnit']!='GiBy.mo':
            raise ValueError('SKU unit changed. Refusing an implicit conversion.')
        monthly_hours=Decimal(str(de['baseUnitConversionFactor']))/(Decimal(2)**30*3600)
        hourly=c*cpus+r*cpus*4
        storage=d*(config['boot_disk_gib']+config['state_disk_gib'])/monthly_hours
        compute+=hourly;disks+=storage
        details.append({'host':host['id'],'region':region,'computeHourlyUsd':str(hourly),
            'diskHourlyUsd':str(storage),'machineType':host['machine_type'],
            'vcpus':cpus,'memoryGiB':cpus*4,'skuIds':[core['skuId'],ram['skuId'],disk['skuId']]})
    return compute,disks,details

def builder_rate(config,skus):
    """Price the Intel builder independently of the evaluation host family."""
    region=topology.builder_location(config)['name'];selected=[]
    for prefix,unit in [('N2 Instance Core running in ','h'),('N2 Instance Ram running in ','GiBy.h'),
                        ('Balanced PD Capacity','GiBy.mo')]:
        found=[s for s in skus if region in s.get('serviceRegions',[])
               and s.get('category',{}).get('usageType')=='OnDemand' and s['description'].startswith(prefix)]
        if len(found)!=1:raise ValueError('ambiguous or missing independent N2 builder SKU in '+region)
        rate,expression=price(found[0])
        if expression['usageUnit']!=unit:raise ValueError('builder SKU unit changed')
        selected.append((found[0],rate,expression))
    core,ram,disk=selected
    monthly_hours=Decimal(str(disk[2]['baseUnitConversionFactor']))/(Decimal(2)**30*3600)
    cpus=int(topology.builder_machine_type(config).rsplit('-',1)[1])
    return {'region':region,'machineType':topology.builder_machine_type(config),
        'cpuPlatform':topology.builder_cpu_platform(config),'vcpus':cpus,'memoryGiB':32,
        'computeHourlyUsd':str(core[1]*cpus+ram[1]*32),
        'ceilingMachineType':'n2-standard-8','computeCeilingHourlyUsd':str(core[1]*8+ram[1]*32),
        'diskGiB':100,'diskHourlyUsd':str(disk[1]*100/monthly_hours),
        'skuIds':[item[0]['skuId'] for item in selected]}

def make(config,hours=14,transfer_gib=48,retention_hours=24):
    ensure()
    skus=catalog(config['project_id'],'services/6F81-5844-456A')
    compute,disk,details=compute_rates(config,skus)
    # Public network/build rates last reviewed on this date. Current compute
    # rates are read above. Refuse to silently redate these fixed price bounds.
    reviewed=datetime(2026,10,27,tzinfo=timezone.utc)
    if not 0<=(datetime.now(timezone.utc)-reviewed).total_seconds()<=7*86400:
        raise ValueError('Review current NAT, network and Cloud Build rates before refreshing this quote.')
    host_count=Decimal(len(topology.hosts(config)))
    nat=host_count*Decimal('0.0014');ipv4=host_count*Decimal('0.005')
    # Planning allowance: inter-region data at an upper USD 0.24/GiB and
    # ten additional GiB of public downloads at USD 0.045/GiB through NAT.
    transfer=budget.amount(transfer_gib)*Decimal('0.24')+Decimal(10)*Decimal('0.045')
    retained=(disk+nat+ipv4)*budget.amount(retention_hours)
    result={'currency':'USD','campaign':config['campaign'],'layout':config['layout'],
        'quoted_at':datetime.now(timezone.utc).isoformat(),
        'hourly':{'compute':str(compute),'nat':str(nat),'disks':str(disk),'ipv4':str(ipv4)},
        'planned_hours':str(budget.amount(hours)),'case_allowance_hours':2,
        'build_registry':'8.00','retained_resources':str(retained),
        'transfer_storage_upper_bound':str(transfer),'source_urls':[CATALOG,NETWORK_SOURCE,BUILD_SOURCE],
        'rateEvidence':details,'builderRateEvidence':builder_rate(config,skus),
        'networkAndBuildRatesReviewedAt':reviewed.isoformat(),
        'planningQuantities':{'interRegionGiB':transfer_gib,'externalNatGiB':10,'retentionHours':retention_hours,
            'cloudBuildMaximumMinutes':120,'gceBuilderMaximumHours':4,
            'assumedCompletion':False,'measuredTraffic':False},
        'warning':'Estimate-based admission. Completion, transfer volume and final billing remain unmeasured.'}
    from cloud_archive import settings as archive_settings
    archive_plan=archive_settings(config)
    if archive_plan is not None:
        storage_skus=catalog(config['project_id'],'services/95FF-2EF5-5EA1')
        matches=[s for s in storage_skus if archive_plan['location'] in s.get('serviceRegions',[])
                 and s['description'].startswith('Standard Storage ')
                 and 'Dual-region' not in s['description']]
        if len(matches)!=1:raise ValueError('ambiguous or missing regional Standard Storage SKU')
        storage_rate,expression=price(matches[0])
        if expression['usageUnit']!='GiBy.mo':raise ValueError('archive storage SKU unit changed')
        # Budget 30-day-equivalent months, seven additional soft-delete days,
        # and USD 0.25 for the bounded small number of object/IAM operations.
        storage=storage_rate*archive_plan['maximum_gib']*Decimal(archive_plan['planning_days']+7)/30
        allowance=((storage+Decimal('0.25'))*4).to_integral_value(rounding=ROUND_CEILING)/4
        result['retained_resources']=str(budget.amount(result['retained_resources'])+allowance)
        result['cloud_archive']={'plan':archive_plan,'storage_and_operations_usd':str(allowance),
            'regionalStorageSku':matches[0]['skuId'],'regionalStorageMonthlyUsdPerGiB':str(storage_rate),
            'softDeletePlanningDays':7,'operationsAllowanceUsd':'0.25',
            'network_in_existing_envelope':True,
            'source_urls':['https://cloud.google.com/storage/pricing',CATALOG],
            'automaticDeletion':False,'warning':'Retention is a planning period, not an automatic expiry. Upload/readback use the separately quoted network envelope.'}
        result['source_urls'].append('https://cloud.google.com/storage/pricing')
    result['admission']=budget.assess(config,result)
    return result
