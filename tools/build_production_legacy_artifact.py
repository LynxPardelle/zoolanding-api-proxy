"""Exact reviewed root-source inventory for general production API v1 only."""
from pathlib import Path
import shutil
import subprocess
import sys
ROOT=Path(__file__).resolve().parents[1]
FILES=('auth_service.py', 'lambda_function.py', 'service_binding_registry_consumer_v2.py', 'thn_auth_runtime_v2.py', 'thn_current_user_provisioning_v2.py', 'thn_environment_profile.py', 'zoolanding_lambda_common.py')
def build(destination):
    destination=Path(destination);destination.mkdir(parents=True,exist_ok=True)
    if any(destination.iterdir()):raise ValueError('production_artifact_destination_not_empty')
    for name in FILES:shutil.copy2(ROOT/name,destination/name)
    subprocess.run([sys.executable,'-m','pip','install','--disable-pip-version-check','--no-compile','--only-binary=:all:','--platform','manylinux_2_34_x86_64','--platform','manylinux2014_x86_64','--implementation','cp','--python-version','313','--abi','cp313','-r',str(ROOT/'requirements.txt'),'--target',str(destination)],check=True)
if __name__=='__main__':build(sys.argv[1])
