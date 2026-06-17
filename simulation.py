"""
WP4 – Simulazione completa e misurazione delle prestazioni
Algoritmi e Protocolli per la Sicurezza - A.A. 2025/2026
GRUPPO 20: Silano Omar - Vitale Antonio
"""

import os
import time
import random
import hashlib

from voting_protocol import (
    phase1_setup,
    phase2_issue_token,
    phase3_encrypt_vote, phase3_compose_message, phase3_receive_vote,
    phase4_tally_and_publish,
    verify_universal, verify_individual,
    get_merkle_proof, verify_merkle_proof, sha256
)

SEP = "=" * 60


def run_simulation(n_voters: int = 10, yes_ratio: float = 0.6):

    print(SEP)
    print(f"  SIMULAZIONE REFERENDUM  —  {n_voters} elettori")
    print(SEP)

    question  = "ti piace il gelato?"
    now       = int(time.time())
    open_ts   = now
    close_ts  = now + 3600
    voter_ids = [f"studente_{i:04d}" for i in range(n_voters)]

    # ----------------------------------------------------------------
    # FASE 1
    # ----------------------------------------------------------------
    t0 = time.perf_counter()
    state = phase1_setup(question, open_ts, close_ts, voter_ids)
    t_setup = (time.perf_counter() - t0) * 1000
    print(f"  Setup completato in {t_setup:.1f} ms")
    print(f"  Integrità quesito verificata da terzo: ", end="")
    from voting_protocol import rsa_verify
    ok = rsa_verify(state["pk_admin"], state["H_Q"], state["sig_H_Q"])
    print("OK" if ok else "FAIL")

    # ----------------------------------------------------------------
    # FASE 2
    # ----------------------------------------------------------------
    print(f"\n[FASE 2] Autenticazione e Rilascio Token")
    print("-" * 50)

    tokens = []
    token_times = []
    for vid in voter_ids:
        t0 = time.perf_counter()
        tok = phase2_issue_token(state, vid)
        token_times.append((time.perf_counter() - t0) * 1000)
        tokens.append(tok)

    avg_token = sum(token_times) / len(token_times)
    print(f"  Token emessi: {len(tokens)}")
    print(f"  Tempo medio emissione token: {avg_token:.3f} ms")
    print(f"  Dimensione token packet: {len(tokens[0])} byte")

    # ----------------------------------------------------------------
    # FASE 3
    # ----------------------------------------------------------------
    print(f"\n[FASE 3] Espressione e Raccolta del Voto")
    print("-" * 50)

    n_yes = int(n_voters * yes_ratio)
    votes = [1] * n_yes + [0] * (n_voters - n_yes)
    random.shuffle(votes)

    ciphertexts = []
    receipts    = []
    enc_times   = []
    recv_times  = []

    for i, (vid, tok, vote) in enumerate(zip(voter_ids, tokens, votes)):
        # Lato client: cifratura
        t0 = time.perf_counter()
        C_i = phase3_encrypt_vote(vote, state["pk_ae"])
        M_i = phase3_compose_message(C_i, tok)
        enc_times.append((time.perf_counter() - t0) * 1000)

        # Lato AE: ricezione e burning
        t0 = time.perf_counter()
        R_i = phase3_receive_vote(state, M_i)
        recv_times.append((time.perf_counter() - t0) * 1000)

        ciphertexts.append(C_i)
        receipts.append(R_i)

    avg_enc  = sum(enc_times)  / len(enc_times)
    avg_recv = sum(recv_times) / len(recv_times)
    print(f"  Voti ricevuti nell'urna: {len(state['ae_urn'])}")
    print(f"  Tempo medio cifratura RSA-OAEP (client): {avg_enc:.3f} ms")
    print(f"  Tempo medio processing AE per voto:      {avg_recv:.3f} ms")
    print(f"  Dimensione M_i (C_i + token):            {len(M_i)} byte")
    print(f"  Dimensione C_i (RSA-2048 ciphertext):    {len(C_i)} byte")

    # Test double-voting
    print("\n  --- Sicurezza: Double-Voting ---")
    try:
        phase3_receive_vote(state, M_i)   # riusa l'ultimo messaggio
        print("  [FAIL] Double-voting non rilevato!")
    except ValueError as e:
        print(f"  [OK]   Bloccato: {e}")

    # Test token contraffatto
    print("\n  --- Sicurezza: Token contraffatto ---")
    try:
        fake_nonce = os.urandom(32)
        fake_ts    = int(time.time()).to_bytes(8, "big")
        fake_sig   = os.urandom(256)
        fake_tok   = fake_nonce + fake_ts + fake_sig  # lunghezze fisse
        fake_C     = phase3_encrypt_vote(1, state["pk_ae"])
        fake_M     = phase3_compose_message(fake_C, fake_tok)
        phase3_receive_vote(state, fake_M)
        print("  [FAIL] Token contraffatto accettato!")
    except ValueError as e:
        print(f"  [OK]   Rigettato: {e}")

# ----------------------------------------------------------------
    # FASE 4
    # ----------------------------------------------------------------
    state["close_ts"] = int(time.time()) - 1    # salto temporale
    
    t0 = time.perf_counter()
    phase4_tally_and_publish(state)
    t_tally = (time.perf_counter() - t0) * 1000
    
    print(f"  Scrutinio completato in {t_tally:.1f} ms")
    print(f"  Dimensione Merkle Root firmata: "
          f"{len(state['merkle_root']) + len(state['merkle_root_sig'])} byte")
    print(f"  Livelli Merkle Tree: {len(state['merkle_tree'])} "
          f"(foglie: {len(state['merkle_tree'][0])})")

    # ----------------------------------------------------------------
    # Verifica Universale
    # ----------------------------------------------------------------
    print(f"\n[VERIFICA UNIVERSALE]")
    print("-" * 50)
    t0 = time.perf_counter()
    u_checks = verify_universal(state)
    t_univ = (time.perf_counter() - t0) * 1000
    for k, v in u_checks.items():
        print(f"  [{'OK' if v else 'FAIL'}] {k}")
    print(f"  Tempo verifica universale: {t_univ:.3f} ms")

    # ----------------------------------------------------------------
    # Verifica Individuale
    # ----------------------------------------------------------------
    print(f"\n[VERIFICA INDIVIDUALE]")
    print("-" * 50)
    indiv_times = []
    for i in range(min(3, n_voters)):
        t0 = time.perf_counter()
        i_checks = verify_individual(state, ciphertexts[i], receipts[i])
        indiv_times.append((time.perf_counter() - t0) * 1000)
        print(f"  Elettore {i:02d}:")
        for k, v in i_checks.items():
            print(f"    [{'OK' if v else 'FAIL'}] {k}")

    proof_sample = get_merkle_proof(state["merkle_tree"], 0)
    proof_size   = len(proof_sample) * 33  # 32 hash + 1 direzione
    avg_indiv    = sum(indiv_times) / len(indiv_times)
    print(f"\n  Dimensione Merkle Proof O(log N): {proof_size} byte "
          f"({len(proof_sample)} nodi)")
    print(f"  Tempo medio verifica individuale: {avg_indiv:.3f} ms")

    # ----------------------------------------------------------------
    # Riepilogo
    # ----------------------------------------------------------------
    print(f"\n{SEP}")
    print("  RIEPILOGO PRESTAZIONI")
    print(SEP)
    rows = [
        ("Setup (keygen + whitelist)",          f"{t_setup:.1f} ms"),
        ("Emissione token (media)",              f"{avg_token:.3f} ms"),
        ("Cifratura RSA-OAEP client (media)",   f"{avg_enc:.3f} ms"),
        ("Processing AE per voto (media)",      f"{avg_recv:.3f} ms"),
        ("Scrutinio totale",                    f"{t_tally:.1f} ms"),
        ("Verifica universale",                 f"{t_univ:.3f} ms"),
        ("Verifica individuale (media)",        f"{avg_indiv:.3f} ms"),
        ("Dimensione M_i",                      f"{len(M_i)} byte"),
        ("Dimensione C_i (RSA-2048)",           f"{len(C_i)} byte"),
        ("Dimensione Merkle Proof",             f"{proof_size} byte"),
    ]
    for label, val in rows:
        print(f"  {label:<42} {val}")

    return state


def scalability_benchmark():
    print(f"\n{SEP}")
    print("  BENCHMARK SCALABILITÀ")
    print(SEP)
    print(f"  {'N':>5}  {'Setup(ms)':>10}  {'Voto(ms)':>10}  "
          f"{'Scrutinio(ms)':>14}  {'Proof(ms)':>10}")
    print("  " + "-" * 58)

    for n in [5, 10, 50, 100]:
        vids = [f"v_{i}" for i in range(n)]

        t0 = time.perf_counter()
        st = phase1_setup("Q", int(time.time()), int(time.time()) + 3600, vids)
        t_setup = (time.perf_counter() - t0) * 1000

        vote_times = []
        for vid in vids:
            tok = phase2_issue_token(st, vid)
            v   = random.choice([0, 1])
            t0  = time.perf_counter()
            C_i = phase3_encrypt_vote(v, st["pk_ae"])
            M_i = phase3_compose_message(C_i, tok)
            phase3_receive_vote(st, M_i)
            vote_times.append((time.perf_counter() - t0) * 1000)

        # SALTO TEMPORALE QUI
        st["close_ts"] = int(time.time()) - 1 

        t0 = time.perf_counter()
        phase4_tally_and_publish(st)
        t_tally = (time.perf_counter() - t0) * 1000

        proof  = get_merkle_proof(st["merkle_tree"], 0)
        t0     = time.perf_counter()
        verify_merkle_proof(sha256(st["published_urn"][0][0] + st["published_urn"][0][1]), proof)
        t_proof = (time.perf_counter() - t0) * 1000

        avg_vote = sum(vote_times) / len(vote_times)
        print(f"  {n:>5}  {t_setup:>10.1f}  {avg_vote:>10.2f}  "
              f"{t_tally:>14.1f}  {t_proof:>10.4f}")


if __name__ == "__main__":
    run_simulation(n_voters=10, yes_ratio=0.6)
    scalability_benchmark()