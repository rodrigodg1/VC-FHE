import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from progress import ProgressMonitor, format_event, stage_message


class ProgressTests(unittest.TestCase):
    def test_counts_distinguish_measured_pairs_warmups_and_full_cases(self):
        for group,total,label in [('paired',480,'measured pairs'),('warmup',18,'warm-ups'),('full',45,'full cases')]:
            phase='full-case' if group=='full' else 'paired-comparison'
            message=format_event(dict(version=1,phase=phase,state='done',group=group,current=total,total=total))
            self.assertIn(f'{label} {total}/{total}, 100% complete',message)
        partial=format_event(dict(version=1,phase='recipient-recovery',state='done',group='full',current=45,total=45))
        self.assertNotIn('100%',partial)
        self.assertIn('blockchain',stage_message('besu'))
        self.assertIn('authorization contract',stage_message('release-policy'))

    def test_unknown_private_fields_and_terminal_escapes_are_ignored(self):
        valid=dict(version=1,phase='operator-execution',state='start')
        for changed in [dict(secret='value'),dict(phase='untrusted'),dict(caseName='x\nsecret'),
                        dict(current=True,total=10),dict(current=2,total=1),dict(group='private')]:
            self.assertIsNone(format_event(valid|changed))

    def test_partial_lines_are_delivered_once_and_malformed_rows_do_not_block_progress(self):
        with tempfile.TemporaryDirectory() as folder:
            reports=Path(folder)/'reports';reports.mkdir();path=reports/'progress-owner.jsonl'
            rows=[];monitor=ProgressMonitor(folder,emit=rows.append)
            event=json.dumps(dict(version=1,phase='owner-encrypt',state='start',caseName='linear-10'))
            path.write_text(event[:12]);monitor.poll();self.assertEqual(rows,[])
            with path.open('a') as file:file.write(event[12:]+'\nnot json\n')
            monitor.poll();monitor.poll();self.assertEqual(len(rows),1)
            self.assertIn('Data owners encrypt',rows[0])

    def test_slow_child_progress_is_visible_before_completion_without_docker(self):
        with tempfile.TemporaryDirectory() as folder:
            reports=Path(folder)/'reports';reports.mkdir();path=reports/'progress-evaluation.jsonl'
            child="""import json,sys,time
path=sys.argv[1]
for current in (1,2):
 with open(path,'a') as f:
  f.write(json.dumps(dict(version=1,phase='full-case',state='done',group='full',current=current,total=2))+'\\n')
 time.sleep(0.3)
"""
            rows=[];monitor=ProgressMonitor(folder,emit=rows.append)
            proc=subprocess.Popen([sys.executable,'-u','-c',child,str(path)])
            observed_while_running=False;deadline=time.monotonic()+5
            try:
                while proc.poll() is None:
                    monitor.poll()
                    if rows:observed_while_running=True
                    self.assertLess(time.monotonic(),deadline)
                    time.sleep(0.03)
                monitor.poll()
                self.assertEqual(proc.returncode,0)
            finally:
                if proc.poll() is None:proc.kill()
                proc.wait()
            self.assertTrue(observed_while_running)
            self.assertEqual(len(rows),2)
            self.assertIn('1/2, 50% complete',rows[0]);self.assertIn('2/2, 100% complete',rows[1])

    def test_missing_logs_are_nonfatal(self):
        with tempfile.TemporaryDirectory() as folder:
            ProgressMonitor(folder,emit=lambda _:self.fail('unexpected progress')).poll()


if __name__=='__main__':unittest.main()
