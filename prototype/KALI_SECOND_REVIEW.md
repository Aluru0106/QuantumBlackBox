# Second Review - Kali commands (run inside ~/qbb)

One-time:   pip install pymavlink dilithium-py cryptography --break-system-packages
Unzip the new files over ~/qbb (keep your env.sh and tpm_start.sh).

## Terminal A (logger)
source env.sh
./tpm_start.sh                 # starts swtpm
python3 logger.py init         # fresh log + TPM anchor
python3 logger.py run 40       # listens for 40 messages  (start Terminal B right after)

## Terminal B (real data replay) - start right after 'run'
cd ~/qbb && python3 replay_real.py 2     # real PX4 flight log as MAVLink, 2 Hz

## Terminal A, after run finishes
python3 logger.py verify                 # -> VALID
python3 pqc_sign.py sign                 # ML-DSA-65 signature of the chain head
python3 pqc_sign.py verify               # -> signature OK

## Attacks (each one then verify)
python3 attacker.py tamper 10 ; python3 logger.py verify     # edit caught
python3 attacker.py restore
python3 attacker.py truncate 5 ; python3 logger.py verify    # PCR23 mismatch
python3 attacker.py restore
python3 attacker.py forge 10 ; python3 logger.py verify      # MAC invalid
python3 attacker.py restore
python3 pqc_sign.py verify                                   # fails if log changed

## Full evaluation (8 attacks x 4 schemes)
python3 evaluate.py 200        # writes results.json
