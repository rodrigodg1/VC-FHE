"""Synthetic catalogue regressions. No cloud calls or resource creation."""
from decimal import Decimal
import json
from pathlib import Path
import sys
import unittest

HERE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(HERE))
import gce_image
import price_quote

class ProfilePriceTests(unittest.TestCase):
    def setUp(self):
        self.config=json.loads((HERE/'config.example.json').read_text())
        self.skus=[]
        for region in self.config['regions']:
            for prefix,rate,unit in [('N2 Instance Core running in ','.03','h'),
                    ('N2 Instance Ram running in ','.004','GiBy.h'),
                    ('N2D AMD Instance Core running in ','.02','h'),
                    ('N2D AMD Instance Ram running in ','.003','GiBy.h'),
                    ('Balanced PD Capacity ','.1','GiBy.mo')]:
                self.skus.append({'skuId':prefix+region['name'],'description':prefix+region['name'],
                    'serviceRegions':[region['name']],'category':{'usageType':'OnDemand'},
                    'pricingInfo':[{'pricingExpression':{'usageUnit':unit,
                        'baseUnitConversionFactor':str(2**30*730*3600),
                        'tieredRates':[{'unitPrice':{'units':'0','nanos':int(Decimal(rate)*10**9)}}]}}]})
    def test_n2_and_n2d_hosts_use_their_own_core_and_ram_skus(self):
        n2,_,n2_rows=price_quote.compute_rates(self.config,self.skus)
        self.config.update(host_machine_type='n2d-standard-4',min_cpu_platform='AMD Milan')
        n2d,_,rows=price_quote.compute_rates(self.config,self.skus)
        self.assertEqual(n2,Decimal('.736'));self.assertEqual(n2d,Decimal('.512'))
        self.assertTrue(all(row['machineType']=='n2d-standard-4' and row['memoryGiB']==16 for row in rows))
        self.assertTrue(all(row['skuIds'][0].startswith('N2D AMD Instance Core') for row in rows))
        self.assertTrue(all(row['skuIds'][0].startswith('N2 Instance Core') for row in n2_rows))
    def test_builder_prices_remain_n2_and_follow_the_selected_region(self):
        self.config.update(host_machine_type='n2d-standard-4',min_cpu_platform='AMD Milan',
                           builder_machine_type='n2-highmem-4',builder_zone=self.config['regions'][1]['zone'])
        evidence=price_quote.builder_rate(self.config,self.skus)
        self.assertEqual(evidence['region'],self.config['regions'][1]['name'])
        self.assertEqual(evidence['cpuPlatform'],'Intel Ice Lake')
        self.assertEqual(Decimal(evidence['computeHourlyUsd']),Decimal('.248'))
        self.assertEqual(Decimal(evidence['computeCeilingHourlyUsd']),Decimal('.368'))
        self.assertEqual(evidence['diskGiB'],100)
        self.assertTrue(evidence['skuIds'][0].startswith('N2 Instance Core'))
        upper=gce_image.builder_price_ceiling(self.config,{'builderRateEvidence':evidence})
        self.assertEqual(upper,(Decimal('.368')+Decimal('.1')*100/730+Decimal('.005'))*4)
    def test_n2d_host_rates_cannot_substitute_for_builder_evidence(self):
        self.config.update(host_machine_type='n2d-standard-4',min_cpu_platform='AMD Milan')
        _,_,rows=price_quote.compute_rates(self.config,self.skus)
        with self.assertRaisesRegex(ValueError,'independent N2 builder price evidence'):
            gce_image.builder_price_ceiling(self.config,{'rateEvidence':rows})
        evidence=price_quote.builder_rate(self.config,self.skus)
        for field,value in [('region',self.config['regions'][1]['name']),('machineType','n2d-standard-4'),
                            ('cpuPlatform','AMD Milan'),('ceilingMachineType','n2d-standard-8')]:
            changed={**evidence,field:value}
            with self.subTest(field=field),self.assertRaises(ValueError):
                gce_image.builder_price_ceiling(self.config,{'builderRateEvidence':changed})
    def test_missing_or_ambiguous_builder_catalogue_is_rejected(self):
        with self.assertRaises(ValueError):price_quote.builder_rate(self.config,[])
        with self.assertRaises(ValueError):price_quote.builder_rate(self.config,self.skus+[self.skus[0]])

if __name__=='__main__':unittest.main()
