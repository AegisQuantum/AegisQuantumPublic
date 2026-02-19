"""
AegisQuantum crypto-core
Package de cryptographie post-quantique pour AegisQuantum.

Modules :
  pq/          — ML-KEM (Kyber-1024) + ML-DSA (Dilithium3)
  identity/    — Génération d'identité et signature de prekeys
  hybrid/      — Échange de clés X25519 + ML-KEM + HKDF
  symmetric/   — AES-256-GCM + ChaCha20-Poly1305
  ratchet/     — Double Ratchet (chain, algorithm, session)
"""