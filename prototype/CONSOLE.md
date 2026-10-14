# One-page console (everything in the browser)

    cd ~/qbb
    source env.sh
    pip install pymavlink dilithium-py cryptography --break-system-packages   # once
    python3 qbb_console.py
    # open  http://127.0.0.1:8080   in Firefox on Kali

Click in order: 1 Start TPM -> 2 Initialise -> 3 Record real flight -> 4 Verify (LOG OK)
-> 5 Sign -> 6 Verify signature -> Attack: Edit / Truncate / Forge -> Verify (TAMPERED + reason)
-> Restore -> 7 Evaluate -> Results tab.
The bottom box runs any shell command. Only listens on 127.0.0.1.
