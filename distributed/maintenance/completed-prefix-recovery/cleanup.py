"""Stop owned compute after the finite service. Preserve all disks and outputs."""
from pathlib import Path
import argparse,sys,os,subprocess
p=argparse.ArgumentParser();p.add_argument('--input',required=True);p.add_argument('--output',required=True);p.add_argument('--bootstrap',action='store_true');a=p.parse_args()
if a.bootstrap:
    state=subprocess.run(['systemctl','is-active','vcfhe-workflows-c4'],capture_output=True,text=True)
    if state.stdout.strip() in ('active','activating'):raise SystemExit(0)
root=Path(a.input).resolve();sys.path.insert(0,str(root/'repository/VC-FHE/distributed'))
os.environ['CLOUDSDK_PYTHON']=sys.executable;os.environ['CLOUDSDK_PYTHON_SITEPACKAGES']='1'
from cloud_tools import ensure
ensure()
from cloud_results.common import read
from cloud_results.cli import stop_compute_local
stop_compute_local(read(root/'job/config.local.json'),Path(a.output))
