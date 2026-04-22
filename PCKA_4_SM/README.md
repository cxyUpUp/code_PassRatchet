# PCKA_4_SM

This directory contains the implementation of the PCKA scheme used in the paper.  
The system has three parties: `Alice`, `Bob`, and `Server`. Alice and Bob first complete password-based initialization, then perform secure message exchange. Decrypted messages can be further used for symmetric-ratchet-style key evolution.

## 1. Directory and File Overview

- `Server.py`: Server-side logic for client registration, initialization coordination, message forwarding, and server key rotation.
- `Alice.py`: Alice client that initiates the session and performs send/receive operations.
- `Bob.py`: Bob client that responds to Alice and performs send/receive operations.
- `CONFIG.py`: Shared protocol configuration (curve, security level, KDF/encryption/network utilities, etc.).
- `Passwords.py`: Generates `passwords.txt` with passwords of different lengths.
- `passwords.txt`: Default password source file read by Alice/Bob.
- `requirements.txt`: Dependency list.

## 2. Environment Requirements

- Python 3.9+ (recommended)
- pip

Install dependencies:

```bash
pip install -r requirements.txt
```

## 3. IP and Port

- `Server.py` default bind: `0.0.0.0:9000`
- `Alice.py` default target: `127.0.0.1:9000`
- `Bob.py` default target: `127.0.0.1:9000`

For cross-machine deployment, update the host in `connect_to_server(...)` in both `Alice.py` and `Bob.py` to the actual server IP.

## 4. Password File

By default, `Alice.py` and `Bob.py` read:

```python
pw = get_pw(8).encode()
```

This means they use the length-8 password entry in `passwords.txt`.  
If the file is missing or you want to regenerate it, run:

```bash
python Passwords.py
```

## 5. Run Steps (Local Reproduction)

Open three terminals in the `PCKA_4_SM` directory.

### Terminal 1: Start Server

```bash
python Server.py
```

### Terminal 2: Start Alice

```bash
python Alice.py
```

### Terminal 3: Start Bob

```bash
python Bob.py
```

Recommended order: `Server` -> `Alice` -> `Bob`.  
After all connections are established, the program automatically enters initialization and secure messaging.

## 6. Protocol Workflow

1. **Identity registration**: Alice/Bob send `identity` to the server.
2. **Session initialization**: Alice generates `sid`, and the server forwards it to Bob.
3. **PCKA Init (password-related)**:
   - Alice/Bob generate blinded values from password + `sid` and send them to the server.
   - The server computes responses; both parties unblind locally and obtain initial state.
4. **Secure Messaging loop (10 rounds by default)**:
   - Alice -> Bob: send `c_10` and `alpha_A1`.
   - Server executes server-side step and rotates `sk`.
   - Bob decrypts and sends back `c_11` and `alpha_B1`.
   - Alice decrypts and updates local state.
5. Per-round latency and summary tables are printed.

## 7. Experiment Output

After execution, the terminals print:

- Per-round communication time for A->B and B->A (ms)
- `PCKA Messaging Time Summary`
- `PCKA Snd Time Summary` (Alice send stage)
- `PCKA Rcv Time Summary` (Alice receive stage)


## 8. AWS Deployment

First sign in to your AWS account at https://aws.amazon.com/ and create security credentials for programmatic AWS EC2 access.

If you use a different cloud provider, minor client-side changes may be needed to adapt to that provider's API. The current prototype uses EC2. For real-network testing, one example setup is: server in Osaka, Bob in London, and Alice local. You can choose other region combinations as needed.

Before deployment, prepare:

- AWS access key for programmatic EC2 access  
  See (https://docs.aws.amazon.com/general/latest/gr/aws-sec-cred-types.html).

After deploying both server and clients, you can run tests across different regions.
