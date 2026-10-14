# QuantumBlackBox - Kali Linux runbook (First Review, 50% implementation)

Everything runs on a Kali VM. TPM = **swtpm (software TPM 2.0 emulator)**; telemetry = **live MAVLink**
(ArduPilot SITL if you manage to build it, otherwise the bundled MAVLink simulator). Say this out loud in the review.

## Step 0 - Machine
Kali VM (VirtualBox/VMware), 4 GB RAM, 30 GB disk, internet. Take a snapshot first.

## Step 1 - Install tools (rubric: "setting up the environment, installing software tools")
**Kali apt problems seen on 10 Oct (403 Forbidden from kali.download / http.kali.org, only ~640 MB free disk):**

    df -h /                                   # need at least ~1.5 GB free; if less, free space or enlarge the VM disk
    sudo apt autoremove -y && sudo apt clean  # frees several hundred MB
    sudo sed -i 's|http://http.kali.org/kali|http://mirrors.esto.network/kali|g; s|http://kali.download/kali|http://mirrors.esto.network/kali|g' /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null
    grep -rn "esto" /etc/apt/sources.list /etc/apt/sources.list.d/    # must print a line; if empty, run: cat /etc/apt/sources.list /etc/apt/sources.list.d/*
    sudo apt update

Install ONLY the TPM tools (do NOT add python3-venv/python3-pip/libssl-dev/cmake: they triggered a 193-package upgrade last time).
Run it WITHOUT -y and read the summary first:

    sudo apt install --no-install-recommends swtpm swtpm-tools tpm2-tools

If it says "Upgrading" a handful of packages and the download is a few hundred MB or less, answer Y.
If it still wants to upgrade ~190 packages (libc6, python3...), answer n and skip the TPM steps for now.
If the 403s continue, switch network (phone hotspot) and retry.

    swtpm --version && tpm2_pcrread -v        # screenshot #1

## Step 2 - Get the code, make a venv
    unzip qbb_repo.zip && cd qbb_repo      # or: git clone <your repo>
    python3 -m venv venv && . venv/bin/activate
    pip install cmake ninja pymavlink pytest ruff bandit     # cmake/ninja from pip: no apt needed

## Step 3 - Software TPM (swtpm) as the root of trust
    mkdir -p ~/swtpm-state
    swtpm_setup --tpm2 --tpmstate ~/swtpm-state --createek --overwrite
    swtpm socket --tpm2 --tpmstate dir=$HOME/swtpm-state \
         --server type=tcp,port=2321 --ctrl type=tcp,port=2322 \
         --flags not-need-init,startup-clear --daemon
    export TPM2TOOLS_TCTI="swtpm:host=127.0.0.1,port=2321"
    tpm2_getrandom --hex 16                       # TPM answers
    tpm2_pcrread sha256:16                        # PCR 16 starts as all zeros
    tpm2_createprimary -C o -G ecc -c primary.ctx
    tpm2_create -C primary.ctx -G ecc256:ecdsa-sha256 -u sign.pub -r sign.priv
    tpm2_load -C primary.ctx -u sign.pub -r sign.priv -c sign.ctx
    echo "flight-log-head" > msg.txt
    tpm2_sign -c sign.ctx -g sha256 -o msg.sig msg.txt
    tpm2_verifysignature -c sign.ctx -g sha256 -s msg.sig -m msg.txt && echo SIGNATURE-OK   # screenshot #2
(If a flag differs on your tpm2-tools version, run the command with `--help`. Screenshot what works.)

## Step 4 - Post-quantum signing (ML-DSA-65, FIPS 204) via liboqs
Build only what we need (about 15 seconds on my test machine; no OpenSSL headers needed):
(run this inside the activated venv so the pip cmake/ninja are used)
    cd ~ && git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git
    cd liboqs && mkdir build && cd build
    cmake -GNinja -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON \
          -DCMAKE_INSTALL_PREFIX=$HOME/_oqs -DOQS_USE_OPENSSL=OFF \
          -DOQS_MINIMAL_BUILD="SIG_ml_dsa_65;KEM_ml_kem_768" ..
    ninja && ninja install
    cd ~/qbb_repo && . venv/bin/activate && pip install liboqs-python
    python -c "import oqs; print(oqs.oqs_version(), [m for m in oqs.get_enabled_sig_mechanisms()])"   # screenshot #3

## Step 5 - Core demo (the 50%): tamper-evident log
    python -m pytest -q                       # 5 tests pass            # screenshot #4
    python demo_tamper.py --tpm               # edit/delete/truncate all DETECTED   # screenshot #5 (most important)

## Step 6 - Live MAVLink recording
    python record_flight.py --source sim --tpm      # or --source sitl if SITL is running   # screenshot #6
    tpm2_pcrread sha256:16                          # PCR 16 changed -> head hash anchored in the TPM # screenshot #7

## Step 7 - OPTIONAL: real ArduPilot SITL (time-box 45 min; skip if it fights you)
    git clone --recurse-submodules https://github.com/ArduPilot/ardupilot.git ~/ardupilot
    cd ~/ardupilot && Tools/environment_install/install-prereqs-ubuntu.sh -y && . ~/.profile
    cd ArduCopter && ../Tools/autotest/sim_vehicle.py -v ArduCopter --console --out=127.0.0.1:14550
    # (MAVProxy forwards the stream to udp 14550.) In a second terminal in the repo:
    #   python record_flight.py --source sitl      # screenshot the SITL console + the recorder output together

## Step 8 - GitHub + CI (rubric: secure coding / DevOps / crypto)
    git init && git add . && git commit -m "QuantumBlackBox: forward-secure PQC-signed flight log"
    # create an EMPTY repo on github.com, then:
    git remote add origin https://github.com/<you>/quantumblackbox.git && git branch -M main && git push -u origin main
Open the repo -> Actions tab -> wait for the green tick. Screenshot the green run and the workflow steps (lint, bandit, secret scan, tests).

## Step 9 - Jira evidence (rubric: Agile)
Board -> Reports: Burndown, Velocity, Sprint report; Backlog view showing epics + story points. One screenshot each.

## Step 10 - Send me
The 7+ screenshots, the terminal text of demo_tamper.py, your GitHub link, and which steps you could NOT finish.
