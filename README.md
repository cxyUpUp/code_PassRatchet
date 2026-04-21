The repository contains the main scheme from the paper, an extension for asymmetric password scenarios, and a DH Ratchet baseline for performance and workflow comparison.

Repository Structure

PCKA_4_SM/
Main paper code: Implements the PCKA functionality described in the paper.

ShareKey_Negotiation/
Extension scheme: For scenarios where the two parties have inconsistent (asymmetric) passwords. A ShareKey negotiation is run before entering the PCKA phase to obtain a shared key, which is then used in the PCKA stage.

DH_Ratchet/
Baseline for comparison: A Diffie-Hellman-based Ratchet implementation, used for computational performance comparison against the PCKA scheme.

For detailed information, please refer to the README.md in each subdirectory.
