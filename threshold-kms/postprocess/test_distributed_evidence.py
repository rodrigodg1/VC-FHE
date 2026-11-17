import copy
import unittest
from distributed_evidence import validate_byte_probe

class ByteEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.records={('operator-1','execute'):{'task':'canonical-execute'}}
        self.probe={'status':'passed','plaintextOpenings':0,'includedInMeasurements':False,
                    'operatorEventId':'execute','audits':[]}
        for i in range(1,4):
            node=f'auditor-{i}'
            self.records[node,'audit']={'task':'canonical-audit'}
            self.probe['audits'].append({'node':node,'eventId':'audit','evidence':{
                'index':None,'plaintextOpenings':0,'operatorRoot':'root','replayRoot':'root'}})
    def test_all_three_actual_auditor_tasks_are_required(self):
        validate_byte_probe(self.probe,self.records)
        del self.records['auditor-3','audit']
        with self.assertRaises(ValueError):validate_byte_probe(self.probe,self.records)
    def test_boolean_pass_cannot_hide_divergence_or_different_traces(self):
        for change in [{'index':0},{'replayRoot':'different'},
                       {'operatorRoot':'different','replayRoot':'different'}]:
            probe=copy.deepcopy(self.probe)
            probe['audits'][0]['evidence'].update(change)
            with self.assertRaises(ValueError):validate_byte_probe(probe,self.records)

if __name__=='__main__':unittest.main()
