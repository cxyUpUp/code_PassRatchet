# ShareKey_Negotiation

This directory contains the extended PCKA implementation: before entering the PCKA secure messaging phase, it runs a ShareKey negotiation process, designed for experiments under asymmetric-password settings.

## 1. Files and Structure

- `ShareKey_server.py`: Server for the extended scheme. Handles registration, authentication, bulletin-board state, proof verification, and then transitions to the PCKA phase.
- `ShareKey_Alice.py`: Alice side. Performs registration, authentication, ShareKey derivation, then enters `PCKA_4_SM.Alice.run(...)`.
- `ShareKey_Bob.py`: Bob side. Performs registration, authentication, ShareKey derivation, then enters `PCKA_4_SM.Bob.run(...)`.
- `CONFIG.py`: Shared protocol configuration (curve, KDF, point encoding, encryption/decryption, etc.).

## 2. Requirements

- Python 3.9+ (recommended)
- `cryptography`
- `ecdsa`
- `pandas`

Install dependencies:

```bash
pip install cryptography ecdsa pandas
```

## 3. Default Network Configuration

- ShareKey server bind address: `0.0.0.0:8000` (`ShareKey_server.py`)
- Alice default target: `127.0.0.1:8000` (`ShareKey_Alice.py`)
- Bob default target: `127.0.0.1:8000` (`ShareKey_Bob.py`)

For cross-machine deployment, change the address in client `connect_to_server(...)` calls to the actual server IP.


## 4. How to Run

Open 3 terminals in the `ShareKey_Negotiation` directory:

### Terminal 1: Start Server

```bash
python ShareKey_server.py
```

### Terminal 2: Start Bob

```bash
python ShareKey_Bob.py
```

### Terminal 3: Start Alice

```bash
python ShareKey_Alice.py
```

Recommended order (same as original note): start `Server` first, then `Alice` and `Bob`.  
After both complete registration, they enter authentication. During authentication, entering Bob's password first and Alice's password second helps keep Alice-side timing more stable.

## 5. Protocol Flow (Implementation View)

1. **Registration stage**
   - Both parties send blinded value `a` to the server.
   - The server returns `b`.
   - Both parties unblind, compute `env`, and post it to the server bulletin board.
2. **Authentication stage**
   - Both parties send `a2` and `y`.
   - The server synchronously returns `auth_bundle` (including `b2`, `cm`, and peer `env/y`).
   - Both parties submit `auth_proof`; if verification passes, the protocol continues.
3. **ShareKey derivation**
   - Both parties compute and obtain the same `ShareKey`.
4. **Enter PCKA messaging stage**
   - Clients call the corresponding `run(...)` in `PCKA_4_SM` for subsequent secure messaging.

## 6. Default Test Settings (Adjust as Needed)

The current code includes defaults for batch testing:

- `ShareKey_Alice.py`: loop count defaults to `for _ in range(10)`, password defaults to `"alice_password"`.
- `ShareKey_Bob.py`: loop count defaults to `for _ in range(10)`, password defaults to `"bob_password"`.

For more interactive experiments, you can change to:

- Loop count set to `1`
- Use `input(...)` to enter passwords manually

## 7. Output

Runtime logs usually include:

- Authentication success/failure messages
- ShareKey derivation completion messages
- Messaging and latency statistics after entering PCKA




