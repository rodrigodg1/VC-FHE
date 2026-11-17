"""Read-only full-campaign pricing, including off-path controller and preservation."""
from decimal import Decimal,ROUND_CEILING
import copy
from cloud_results.common import VERSION,check_full,require
import price_quote
import budget
from cloud_results.completion_budget import assess as assess_completion_budget


def make(config, *, hours=14, transfer_gib=48, retention_hours=24, prior_usd=None):
    check_full(config)
    require(config['maximum_vm_runtime_seconds']==hours*3600,'Quote must cover the full configured VM duration')
    require(prior_usd is not None,'Explicit cumulative prior-experiment cost evidence is required')
    result=price_quote.make(config,hours,transfer_gib,retention_hours)
    skus=price_quote.catalog(config['project_id'],'services/6F81-5844-456A')
    region=config['regions'][0]['name'];selected=[]
    for prefix,unit in [('E2 Instance Core running in ','h'),('E2 Instance Ram running in ','GiBy.h'),
                        ('Balanced PD Capacity','GiBy.mo')]:
        rows=[s for s in skus if region in s.get('serviceRegions',[])
              and s.get('category',{}).get('usageType')=='OnDemand' and s['description'].startswith(prefix)]
        require(len(rows)==1,'Missing or ambiguous controller SKU: '+prefix)
        rate,expression=price_quote.price(rows[0]);require(expression['usageUnit']==unit,'Controller SKU unit changed')
        selected.append((rows[0],rate,expression))
    cpu,ram,disk=selected
    month_hours=Decimal(str(disk[2]['baseUnitConversionFactor']))/(Decimal(2)**30*3600)
    controller={'compute':cpu[1]*2+ram[1]*8,'disks':disk[1]*200/month_hours,'ipv4':Decimal('0.005')}
    # Keep original protocol-host hours. Add two controller-only hours for
    # preparation/export without changing a single protocol deadline or quorum.
    for key,rate in controller.items():result['hourly'][key]=str(budget.amount(result['hourly'][key])+rate)
    extra_controller=sum(controller.values())*2
    storage_skus=price_quote.catalog(config['project_id'],'services/95FF-2EF5-5EA1')
    rows=[s for s in storage_skus if region in s.get('serviceRegions',[])
          and s['description'].startswith('Standard Storage ') and 'Dual-region' not in s['description']]
    require(len(rows)==1,'Missing or ambiguous complete-evidence storage SKU')
    rate,expression=price_quote.price(rows[0]);require(expression['usageUnit']=='GiBy.mo','Storage SKU unit changed')
    archive_cost=rate*100*Decimal(37)/30+Decimal('0.25')
    archive_allowance=(archive_cost*4).to_integral_value(rounding=ROUND_CEILING)/4
    result['retained_resources']=str(budget.amount(result['retained_resources'])+extra_controller+archive_allowance
                                   +controller['disks']*budget.amount(retention_hours))
    result['build_registry']='1.00'  # Already published images only. This route cannot compile.
    result['prior_experiment_upper_bound_usd']=str(budget.amount(prior_usd))
    result['cloud_controller']={'version':VERSION,'machineType':'e2-standard-2','vcpus':2,'memoryGiB':8,
        'diskGiB':200,'region':region,'extraControllerOnlyHours':2,'rateEvidence':{
            'hourly':{k:str(v) for k,v in controller.items()},'skuIds':[v[0]['skuId'] for v in selected]},
        'privateEvidenceGiB':100,'retentionPlanningDays':30,'softDeletePlanningDays':7,
        'archiveAndOperationsAllowanceUsd':str(archive_allowance),'storageSku':rows[0]['skuId'],
        'nativeImageBuildAllowed':False,'localEvaluationPackageMaximumMiB':256,
        'networkIncludedInSeparateEnvelope':True,'billingHardCap':False}
    result['source_urls']+=['https://cloud.google.com/storage/pricing','https://cloud.google.com/artifact-registry/pricing']
    result['admission']=assess_completion_budget(config,result)
    return result
