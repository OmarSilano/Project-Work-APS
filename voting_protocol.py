"""
WP4 - Protocollo di Voto Elettronico
Struttura a 4 fasi come da WP2.
Algoritmi e Protocolli per la Sicurezza - A.A. 2025/2026
GRUPPO 20: Silano Omar - Vitale Antonio
"""

import os
import time
import random
import hashlib

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

# Lunghezze fisse per RSA-2048 (256 byte) e SHA-256 (32 byte)
RSA_LEN    = 256   # lunghezza ciphertext / firma RSA-2048
NONCE_LEN  = 32    # nonce CSPRNG
TS_LEN     = 8     # timestamp big-endian
HASH_LEN   = 32    # SHA-256


# ---------------------------------------------------------------------------
# Utilità RSA (stesse API e pattern dei lab)
# ---------------------------------------------------------------------------

def generate_rsa_keypair():
    """Genera coppia RSA-2048 con esponente 65537"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    return private_key, private_key.public_key()


def rsa_encrypt(public_key, plaintext: bytes) -> bytes:
    """Cifratura RSA-OAEP"""
    return public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def rsa_decrypt(private_key, ciphertext: bytes) -> bytes:
    """Decifratura RSA-OAEP"""
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def rsa_sign(private_key, message: bytes) -> bytes:
    """Firma RSA-PSS"""
    return private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


def rsa_verify(public_key, message: bytes, signature: bytes) -> bool:
    """Verifica firma RSA-PSS"""
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


# ---------------------------------------------------------------------------
# Merkle Tree 
# ---------------------------------------------------------------------------

def build_merkle_tree(leaves: list) -> list:
    """
    Costruisce il Merkle Tree bottom-up.
    Restituisce lista di livelli: tree[0] = foglie, tree[-1] = [root].
    Se il numero di foglie è dispari, duplica l'ultima.
    """
    if not leaves:
        return []
    level = list(leaves)
    tree  = [level]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level = level + [level[-1]]
        next_level = [sha256(level[i] + level[i + 1])
                      for i in range(0, len(level), 2)]
        tree.append(next_level)
        level = next_level
    return tree


def get_merkle_proof(tree: list, idx: int) -> list:
    """
    Percorso di autenticazione O(log N) per la foglia all'indice idx.
    Ogni elemento: (hash_fratello: bytes, direzione: 'L'|'R').
    """
    proof = []
    for level in tree[:-1]:
        if len(level) % 2 == 1:
            level = level + [level[-1]]
        if idx % 2 == 0:
            proof.append((level[idx + 1], "R"))
        else:
            proof.append((level[idx - 1], "L"))
        idx //= 2
    return proof


def verify_merkle_proof(leaf_hash: bytes, proof: list) -> bytes:
    """Ricalcola la Merkle Root a partire dalla foglia e dal percorso."""
    current = leaf_hash
    for sibling, direction in proof:
        if direction == "R":
            current = sha256(current + sibling)
        else:
            current = sha256(sibling + current)
    return current


# ---------------------------------------------------------------------------
# FASE 1 – Setup
# ---------------------------------------------------------------------------

def phase1_setup(question: str, open_ts: int, close_ts: int, voter_ids: list) -> dict:
    """
    Genera le coppie di chiavi di tutte le entità e configura il referendum.
    Restituisce lo 'state', che simula bacheca pubblica + stato interno.
    """
    print("\n[FASE 1] Setup")
    print("-" * 50)

    sk_admin, pk_admin = generate_rsa_keypair()
    print("  Chiavi Amministratore generate (RSA-2048)")

    sk_sa, pk_sa = generate_rsa_keypair()
    print("  Chiavi SA generate (RSA-2048)")

    sk_ae, pk_ae = generate_rsa_keypair()
    print("  Chiavi AE generate (RSA-2048)")

    # H_Q = SHA-256(Q || ts_apertura || ts_chiusura)
    h_q_raw = (question.encode()
                + open_ts.to_bytes(TS_LEN, "big")
                + close_ts.to_bytes(TS_LEN, "big"))
    H_Q     = sha256(h_q_raw)
    sig_H_Q = rsa_sign(sk_admin, H_Q)
    print(f"  Quesito firmato: H_Q = {H_Q.hex()[:16]}...")

    # Whitelist W (privata) e H(W) (pubblica)
    whitelist = set(voter_ids)
    H_W = sha256(b"||".join(v.encode() for v in sorted(voter_ids)))
    print(f"  Whitelist: {len(whitelist)} elettori, H(W) = {H_W.hex()[:16]}...")

    return {
        # chiavi private
        "sk_admin": sk_admin, "sk_sa": sk_sa, "sk_ae": sk_ae,
        # chiavi pubbliche (bacheca)
        "pk_admin": pk_admin, "pk_sa": pk_sa, "pk_ae": pk_ae,
        # parametri referendum (bacheca)
        "question": question,
        "open_ts": open_ts, "close_ts": close_ts,
        "H_Q": H_Q, "sig_H_Q": sig_H_Q,
        "H_W": H_W, "whitelist_size": len(whitelist),
        # stato interno SA
        "whitelist": whitelist,
        "sa_issued": {},        # voter_id -> nonce_i
        # stato interno AE
        "ae_urn": [],           # lista di (C_i: bytes, ts_insert: bytes)
        "ae_spent": set(),      # insieme H(T_i) già bruciati
        # risultati (fase 4)
        "merkle_root": None, "merkle_root_sig": None,
        "merkle_tree": None, "published_urn": None,
        "published_tokens": None, "published_votes": None,
        "result": None,
    }


# ---------------------------------------------------------------------------
# FASE 2 – Autenticazione e Rilascio Token
# ---------------------------------------------------------------------------

def phase2_issue_token(state: dict, voter_id: str) -> bytes:
    """
    SA verifica identità, controlla whitelist, rilascia token anonimo.

    Payload firmato: nonce_i (32 B) || timestamp (8 B)
    T_i = Sign_RSA-PSS(sk_SA, SHA-256(nonce_i || ts))

    Pacchetto token (lunghezze fisse, come Lab 2 iv||ct||sig):
        nonce_i (32 B) || ts (8 B) || T_i (256 B)
    """
    if voter_id not in state["whitelist"]:
        raise ValueError(f"Elettore '{voter_id}' non in whitelist.")
    if voter_id in state["sa_issued"]:
        raise ValueError(f"Elettore '{voter_id}' ha già ottenuto un token.")

    nonce_i = os.urandom(NONCE_LEN)   # CSPRNG (os.urandom come nei lab)
    ts      = int(time.time()).to_bytes(TS_LEN, "big")
    T_i     = rsa_sign(state["sk_sa"], sha256(nonce_i + ts))

    state["sa_issued"][voter_id] = nonce_i   # (id_i, nonce_i) — mai all'AE

    # nonce_i || ts || T_i  — lunghezze fisse, no separatore
    return nonce_i + ts + T_i


def _unpack_token(token_packet: bytes) -> tuple:
    """Spacchetta il pacchetto token in (nonce_i, ts, T_i) per lunghezze fisse."""
    nonce_i = token_packet[:NONCE_LEN]
    ts      = token_packet[NONCE_LEN: NONCE_LEN + TS_LEN]
    T_i     = token_packet[NONCE_LEN + TS_LEN:]
    return nonce_i, ts, T_i


# ---------------------------------------------------------------------------
# FASE 3 – Espressione e Raccolta del Voto
# ---------------------------------------------------------------------------

def phase3_encrypt_vote(vote: int, pk_ae) -> bytes:
    """
    Lato client: C_i = Enc_RSA-OAEP(pk_AE, v_i),  v_i assume valori {0, 1, 2}.
    """
    if vote not in (0, 1, 2):
        raise ValueError("Il voto deve essere 0 (No), 1 (Sì) o 2 (Nullo).")
    return rsa_encrypt(pk_ae, vote.to_bytes(1, "big"))


def phase3_compose_message(C_i: bytes, token_packet: bytes) -> bytes:
    """
    Lato client: M_i = C_i (256 B) || token_packet (296 B).
    Lunghezze fisse — nessun separatore necessario (come Lab 2 iv||ct||sig).
    """
    return C_i + token_packet


def phase3_receive_vote(state: dict, message: bytes) -> bytes:
    """
    Lato AE: spacchetta M_i, valida token, burning, archivia C_i.
    Restituisce la ricevuta R_i.

    Formato M_i (lunghezze fisse):
        C_i (256 B) || nonce_i (32 B) || ts (8 B) || T_i (256 B)

    Formato ricevuta (lunghezze fisse):
        ballot_hash (32 B) || ts_insert (8 B) || R_i (256 B)
    """
    # Spacchetta per lunghezze fisse
    C_i     = message[:RSA_LEN]
    nonce_i = message[RSA_LEN: RSA_LEN + NONCE_LEN]
    ts      = message[RSA_LEN + NONCE_LEN: RSA_LEN + NONCE_LEN + TS_LEN]
    T_i     = message[RSA_LEN + NONCE_LEN + TS_LEN:]

    # 1. Verifica autenticità: SHA-256(nonce_i || ts) firmato da sk_SA
    if not rsa_verify(state["pk_sa"], sha256(nonce_i + ts), T_i):
        raise ValueError("Firma del token non valida.")

    # 2. Anti-double-voting: H(T_i) nel registro spesi
    h_token = sha256(T_i)
    if h_token in state["ae_spent"]:
        raise ValueError("Token già speso: double-voting impedito.")

    # Burning
    state["ae_spent"].add(h_token)

    # 3. Deposito nell'urna
    ts_insert = int(time.time()).to_bytes(TS_LEN, "big")
    state["ae_urn"].append((C_i, ts_insert))

    # 4. Ricevuta: R_i = Sign(sk_AE, SHA-256(C_i || ts_insert))
    ballot_hash = sha256(C_i + ts_insert)
    R_i         = rsa_sign(state["sk_ae"], ballot_hash)

    # ballot_hash (32 B) || ts_insert (8 B) || R_i (256 B)
    return ballot_hash + ts_insert + R_i


def _unpack_receipt(receipt: bytes) -> tuple:
    """Spacchetta la ricevuta in (ballot_hash, ts_insert, R_i)."""
    ballot_hash = receipt[:HASH_LEN]
    ts_insert   = receipt[HASH_LEN: HASH_LEN + TS_LEN]
    R_i         = receipt[HASH_LEN + TS_LEN:]
    return ballot_hash, ts_insert, R_i


# ---------------------------------------------------------------------------
# FASE 4 – Scrutinio e Pubblicazione
# ---------------------------------------------------------------------------

def phase4_tally_and_publish(state: dict) -> dict:
    """
    AE: chiude l'urna, mescola, decifra, costruisce Merkle Tree, pubblica.
    """
    print("\n[FASE 4] Scrutinio e Pubblicazione")
    print("-" * 50)

    #blocco dello scrutinio anticipato
    if int(time.time()) < state["close_ts"]:
        raise ValueError("Scrutinio bloccato: il tempo del referendum non è ancora scaduto.")

    urn_copy = list(state["ae_urn"])
    random.shuffle(urn_copy)   # distrugge correlazione temporale

    yes_count  = 0
    no_count   = 0
    null_count = 0
    plaintext_votes = []

    for C_i, ts_insert in urn_copy:
        try:
            plaintext = rsa_decrypt(state["sk_ae"], C_i)
            v = int.from_bytes(plaintext, "big")
            if v == 1:
                yes_count += 1
                plaintext_votes.append(1) #inserisco il Sì
            elif v == 0:
                no_count += 1
                plaintext_votes.append(0) #inserisco il No
            else:
                null_count += 1
                plaintext_votes.append(2) #inserisco il voto nullo
        except Exception:
            null_count += 1
            plaintext_votes.append(2) #nullo se la decifratura fallisce

    print(f"  Sì: {yes_count}  |  No: {no_count}  |  Nulli: {null_count}")

    # Merkle Tree sui ciphertext e timestamp mescolati 
    leaves = [sha256(C_i + ts_insert) for C_i, ts_insert in urn_copy]
    merkle_tree = build_merkle_tree(leaves)
    merkle_root = merkle_tree[-1][0] if merkle_tree else b""
    merkle_root_sig = rsa_sign(state["sk_ae"], merkle_root)
    print(f"  Merkle Root: {merkle_root.hex()[:16]}...")

    state["merkle_root"]      = merkle_root
    state["merkle_root_sig"]  = merkle_root_sig
    state["merkle_tree"]      = merkle_tree
    state["published_urn"]    = urn_copy
    state["published_tokens"] = list(state["ae_spent"])
    state["published_votes"]  = plaintext_votes
    state["result"] = {
        "yes": yes_count, "no": no_count, "null": null_count,
        "total_valid":   yes_count + no_count,
        "total_ballots": len(urn_copy),
    }
    return state["result"]


# ---------------------------------------------------------------------------
# Verifica Universale
# ---------------------------------------------------------------------------

def verify_universal(state: dict) -> dict:
    """Controlli eseguibili da chiunque con i soli dati della bacheca pubblica."""
    checks = {}

    checks["ballot_count_le_whitelist"] = (
        state["result"]["total_ballots"] <= state["whitelist_size"]
    )
    checks["merkle_root_signature_valid"] = rsa_verify(
        state["pk_ae"], state["merkle_root"], state["merkle_root_sig"]
    )
    checks["no_double_voting"] = (
        len(state["published_tokens"]) == len(set(state["published_tokens"]))
    )
    
    #conteggio
    recount_yes  = state["published_votes"].count(1)
    recount_no   = state["published_votes"].count(0)
    recount_null = state["published_votes"].count(2)
    
    checks["tally_coherent"] = (
        recount_yes  == state["result"]["yes"] and
        recount_no   == state["result"]["no"] and
        recount_null == state["result"]["null"]
    )
    
    #Costruzione Merkle Tree
    leaves = [sha256(C_i + ts_insert) for C_i, ts_insert in state["published_urn"]]
    
    merkle_tree = build_merkle_tree(leaves)
    #evita il crash se l'urna è vuota (0 votanti)
    rebuilt_root = merkle_tree[-1][0] if merkle_tree else b""
    
    checks["merkle_root_matches"] = (rebuilt_root == state["merkle_root"])

    return checks


# ---------------------------------------------------------------------------
# Verifica Individuale (Merkle Proof)
# ---------------------------------------------------------------------------

def verify_individual(state: dict, C_i: bytes, receipt: bytes) -> dict:
    """
    L'elettore verifica che il proprio voto sia incluso nell'urna.
    1. Controlla la firma sulla ricevuta R_i con pk_AE.
    2. Trova C_i nell'urna pubblicata.
    3. Ricalcola la Merkle Root tramite percorso O(log N).
    """
    checks = {}

    ballot_hash, ts_insert, R_i = _unpack_receipt(receipt)

    # 1. Verifica firma ricevuta
    checks["receipt_signature_valid"] = rsa_verify(
        state["pk_ae"], sha256(C_i + ts_insert), R_i
    )

    # 2. Trova C_i nell'urna pubblicata
    idx = None
    for i, (ciphertext, _) in enumerate(state["published_urn"]):
        if ciphertext == C_i:
            idx = i
            break

    if idx is None:
        checks["ballot_in_urn"]       = False
        checks["merkle_proof_valid"]  = False
        return checks

    checks["ballot_in_urn"] = True

    # 3. Merkle Proof O(log N)
    proof = get_merkle_proof(state["merkle_tree"], idx)
    leaf_hash = sha256(C_i + ts_insert)
    computed_root = verify_merkle_proof(leaf_hash, proof)
    checks["merkle_proof_valid"] = (computed_root == state["merkle_root"])

    return checks
