#!/usr/bin/env sh
# Linux/macOS equivalent of run_all.bat
cd "$(dirname "$0")" && mkdir -p outputs
python3 mp5_1_auth_and_ids/part_a_mutual_auth.py   | tee outputs/mp5_1_part_a_output.txt
python3 mp5_1_auth_and_ids/part_b_signaling_ids.py | tee outputs/mp5_1_part_b_output.txt
python3 mp5_2_malware_matrix/mitigation_matrix.py  | tee outputs/mp5_2_output.txt
python3 mp5_3_privacy_checklist/privacy_checklist.py | tee outputs/mp5_3_output.txt
