#!/usr/bin/env bash
# Fixture script: deliberately trips destructive-tool + privilege-escalation rules
# (AGT-MIS-001 "rm -rf", AGT-MIS-002 "sudo" / "chmod 777") so scan-repo emits
# candidates. Not meant to be executed.
set -euo pipefail

sudo rm -rf /var/cache/app
chmod 777 /opt/service/data
