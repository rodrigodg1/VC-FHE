import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
import cli
import gcp
import metrics
import topology

class PreparationTests(unittest.TestCase):
    def setUp(self):
        self.config = json.loads((HERE/"config.example.json").read_text())

    def test_four_hosts_all_twenty_one_roles(self):
        result = topology.plan(self.config)
        self.assertEqual(len(result["nodes"]), 21)
        self.assertEqual(len(result["hosts"]), 4)
        self.assertEqual(result["capacity_request"]["vcpus"], 16)
        self.assertTrue(result["campaign_execution_available"])
        self.assertIn('execution-validation',result['protocol_adapter_gaps'])

    def test_threshold_roles_distributed_operator_separate_from_auditors(self):
        nodes = topology.inventory(self.config)
        for role, count in (("kms",4), ("validator",4), ("adjudicator",3), ("auditor",3)):
            self.assertEqual(len({n["host"] for n in nodes if n["role"] == role}), count)
        op = next(n["host"] for n in nodes if n["role"] == "operator")
        self.assertNotIn(op, {n["host"] for n in nodes if n["role"] == "auditor"})

    def test_dedicated_layout_changes_actual_vm_count(self):
        self.config["layout"] = "dedicated"
        self.assertEqual(len(topology.hosts(self.config)),21)
        self.assertEqual(len(gcp.terraform(self.config)["resource"]["google_compute_instance"]),21)

    def test_no_port_collision_on_shared_hosts(self):
        used = set()
        for node in topology.inventory(self.config):
            for port in node["ports"]:
                item = (node["host"],port)
                self.assertNotIn(item,used)
                used.add(item)

    def test_iam_and_firewall_limits_for_dedicated_layout(self):
        self.config["layout"] = "dedicated"
        self.config["campaign"] = "a"*21
        resources = gcp.terraform(self.config)["resource"]
        for account in resources["google_service_account"].values():
            self.assertLessEqual(len(account["account_id"]),30)
        for firewall in resources["google_compute_firewall"].values():
            self.assertLessEqual(len(firewall.get("source_service_accounts",[])),10)
            self.assertLessEqual(len(firewall["target_service_accounts"]),10)

    def test_no_public_ips_or_public_rpc(self):
        resources = gcp.terraform(self.config)["resource"]
        for instance in resources["google_compute_instance"].values():
            self.assertNotIn("access_config",instance["network_interface"][0])
            self.assertTrue(instance["deletion_protection"])
        for rule in resources["google_compute_firewall"].values():
            self.assertNotIn("0.0.0.0/0",rule.get("source_ranges",[]))
            if "source_ranges" in rule:
                self.assertEqual(rule["source_ranges"],["35.235.240.0/20"])
                self.assertEqual(rule["allow"][0]["ports"],["22"])

    def test_one_kms_peer_and_validator_in_every_region(self):
        nodes = topology.inventory(self.config)
        for region in self.config["regions"]:
            for role in ("kms","validator"):
                self.assertEqual(sum(n["region"]==region["name"] and n["role"]==role for n in nodes),1)

    def test_reject_protocol_changes(self):
        for field, value in (("adjudicator_threshold",1),("kms_response_threshold",2),
                             ("validator_query_threshold",2),("window_seconds",30),
                             ("fhe_threads",2),("fhe_parameters","Default")):
            config = copy.deepcopy(self.config)
            config[field] = value
            with self.assertRaises(ValueError): topology.plan(config)

    def test_reject_overlapping_subnets(self):
        self.config["regions"][1]["cidr"] = self.config["regions"][0]["cidr"]
        with self.assertRaises(ValueError): topology.plan(self.config)

    def test_reject_changed_evaluation_grid(self):
        self.config["measurement_grid"]["paired_measurements"] = 4
        with self.assertRaises(ValueError): topology.plan(self.config)

    def test_budget_never_guarantees_hard_cap(self):
        self.assertEqual(cli.budget(self.config)["status"],"unpriced")
        self.config["cost_estimate"] = {"hourly_total":1,"planned_hours":24,"transfer_and_storage":4}
        result = cli.budget(self.config)
        self.assertEqual(result["estimated_usd"],"28")
        self.assertFalse(result["hard_billing_cap"])
        self.config["cost_estimate"]["planned_hours"] = 50
        self.assertEqual(cli.budget(self.config)["status"],"over-budget")

    def test_prepare_is_local_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)/"prepared"
            result = cli.prepare(self.config,target)
            self.assertEqual(result["hosts"],4)
            self.assertTrue((target/"terraform/main.tf.json").is_file())
            self.assertEqual(json.loads((target/"commands.json").read_text())["cloud_actions_executed"],[])
            with self.assertRaises(ValueError): cli.prepare(self.config,target)

class MetricTests(unittest.TestCase):
    def setUp(self):
        self.plan = topology.plan(json.loads((HERE/"config.example.json").read_text()))
        self.phase = {"kind":"phase","host":"host-2","role":"auditor-1","event_id":"1",
            "case_id":"synthetic-test-only","phase":"auditor_recomputation","status":"passed",
            "elapsed_seconds":2,"cpu_seconds":1,"peak_rss_bytes":100,"payload_bytes_sent":10,
            "payload_bytes_received":20,"contract_deadline_timestamp":100,"receipt_block_timestamp":101}

    def summarize(self,rows):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp)/"events.jsonl"
            file.write_text("".join(json.dumps(row)+"\n" for row in rows))
            result = metrics.summarize([file],self.plan,Path(tmp)/"out")
            self.assertTrue((Path(tmp)/"out/phase-summary.csv").is_file())
            return result

    def test_late_receipt_retained_and_not_publishable(self):
        result = self.summarize([self.phase])
        self.assertEqual(result["phase_summary"][0]["late_receipts"],1)
        self.assertFalse(result["evaluation_publishable"])

    def test_wrong_host_rejected(self):
        self.phase["host"] = "host-1"
        with self.assertRaises(ValueError): self.summarize([self.phase])

    def test_duplicate_event_rejected(self):
        with self.assertRaises(ValueError): self.summarize([self.phase,self.phase])

    def test_failed_phases_not_counted_as_success(self):
        self.phase["status"] = "failed"
        result = self.summarize([self.phase])
        row = result["phase_summary"][0]
        self.assertEqual(row["failed_or_incomplete"],1)
        self.assertIsNone(row["mean_success_seconds"])

    def test_nonfinite_and_negative_metrics_rejected(self):
        for value in (float("nan"),float("inf"),-1,True):
            self.phase["elapsed_seconds"] = value
            with self.assertRaises(ValueError): self.summarize([self.phase])

    def test_empty_observations_do_not_become_campaign(self):
        self.assertFalse(self.summarize([])["evaluation_publishable"])

if __name__ == "__main__": unittest.main()
