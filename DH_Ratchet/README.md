# DH_Ratchet

This directory provides an DH Ratchet baseline implementation for comparison with the PCKA scheme in terms of workflow and latency.

## 1. File Overview

- `Server_dh.py`: Relay server for client registration and public-key forwarding.
- `Alice_dh.py`: Alice-side script that runs DH Ratchet loops and measures timing.
- `Bob_dh.py`: Bob-side script that runs DH Ratchet loops and measures timing.

## 2. Requirements

- Python 3.9+ (recommended)
- `ecdsa`
- `pandas`

Install dependencies:

```bash
pip install ecdsa pandas
```

## 3. Default Network Configuration

- Server bind address: `0.0.0.0:8000` (`Server_dh.py`)
- Alice target address: `127.0.0.1:8000` (`Alice_dh.py`)
- Bob target address: `127.0.0.1:8000` (`Bob_dh.py`)

For cross-machine runs, change `HOST` in the client scripts to the actual server IP.


## 4. How to Run

Open 3 terminals in the `DH_Ratchet` directory:

### Terminal 1: Start Server

```bash
python Server_dh.py
```

### Terminal 2: Start Bob

```bash
python Bob_dh.py
```

### Terminal 3: Start Alice

```bash
python Alice_dh.py
```

Note: The server waits until both clients register. Then Alice and Bob exchange compressed public keys through the server and enter the ratchet loop.

## 5. Protocol Flow (Implementation View)

1. Alice and Bob each send `register` to the server.
2. Both send `public_key`, and the server forwards each key to the peer.
3. In each ratchet round:
   - Perform ECDH with local private key and peer public key.
   - Hash the shared value to derive a DH output.
   - Generate a new ephemeral keypair and send the new public key for the next round.
4. The default run is 10 rounds, followed by timing summaries.

## 6. Output

During execution, the scripts print:

- DH output per round (truncated display)
- Per-round communication latency (ms)
- Summary statistics (including `pandas` table output)


## 7. Scope

This implementation is intended for paper experiments and baseline comparison. It focuses on ratchet behavior and latency observation, not production-grade secure messaging.
