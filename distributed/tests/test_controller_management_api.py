from pathlib import Path
import sys,unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from cloud_results import controller_api

class ControllerApiTests(unittest.TestCase):
    def rows(self,names):return [{'config':{'name':n}} for n in names]
    def test_ready_project_never_reenables_apis(self):
        with patch.object(controller_api,'gcloud',return_value=self.rows(controller_api.REQUIRED)),patch.object(controller_api,'run') as mutate:
            x=controller_api.ensure({'project_id':'example-project'});self.assertEqual(x['newlyEnabled'],[]);mutate.assert_not_called()
    def test_read_only_call_refuses_missing_apis(self):
        with patch.object(controller_api,'gcloud',return_value=[]),patch.object(controller_api,'run') as mutate:
            with self.assertRaises(ValueError):controller_api.ensure({'project_id':'example-project'})
            mutate.assert_not_called()
    def test_explicit_start_enables_only_missing_controller_services(self):
        present={'serviceusage.googleapis.com'}
        with patch.object(controller_api,'gcloud',side_effect=[self.rows(present),self.rows(controller_api.REQUIRED)]),patch.object(controller_api,'run') as mutate:
            x=controller_api.ensure({'project_id':'example-project'},execute=True)
            self.assertEqual(x['newlyEnabled'],['cloudresourcemanager.googleapis.com'])
            self.assertEqual(mutate.call_count,1);self.assertNotIn('compute.googleapis.com',mutate.call_args.args[0])
    def test_incomplete_activation_is_not_a_pass(self):
        with patch.object(controller_api,'gcloud',return_value=[]),patch.object(controller_api,'run'):
            with self.assertRaises(ValueError):controller_api.ensure({'project_id':'example-project'},execute=True)

if __name__=='__main__':unittest.main()
