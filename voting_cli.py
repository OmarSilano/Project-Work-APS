"""
voting_cli.py — Interfaccia interattiva da terminale per il protocollo di voto
Algoritmi e Protocolli per la Sicurezza - A.A. 2025/2026
GRUPPO 20: Silano Omar - Vitale Antonio
"""

import os
import sys
import time

# ---------------------------------------------------------------------------
# Importa il protocollo (voting_protocol.py deve essere nella stessa cartella)
# ---------------------------------------------------------------------------
try:
    from voting_protocol import (
        phase1_setup,
        phase2_issue_token,
        phase3_encrypt_vote, phase3_compose_message, phase3_receive_vote,
        phase4_tally_and_publish,
        verify_universal, verify_individual,
        get_merkle_proof, verify_merkle_proof, sha256,
        rsa_verify, rsa_decrypt
    )
except ImportError:
    print("[ERRORE] voting_protocol.py non trovato nella stessa cartella.")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Helpers UI
# ---------------------------------------------------------------------------

SEP  = "=" * 60
SEP2 = "-" * 60

def banner(title: str):
    print(f"\n{SEP}")
    print(f"  {title}")
    print(SEP)

def section(title: str):
    print(f"\n{SEP2}")
    print(f"  {title}")
    print(SEP2)

def ok(msg):  print(f"  [✓] {msg}")
def fail(msg): print(f"  [✗] {msg}")
def info(msg): print(f"  {msg}")

def ask(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    try:
        val = input(f"  >>> {prompt}{suffix}: ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\n[Uscita]")
        sys.exit(0)
    return val if val else default

def ask_int(prompt: str, default: int) -> int:
    while True:
        raw = ask(prompt, str(default))
        try:
            return int(raw)
        except ValueError:
            print("  [!] Inserisci un numero intero.")

def ask_choice(prompt: str, choices: list) -> str:
    opts = " / ".join(f"[{c}]" for c in choices)
    while True:
        val = ask(f"{prompt} {opts}").lower()
        if val in [c.lower() for c in choices]:
            return val
        print(f"  [!] Scelta non valida. Opzioni: {', '.join(choices)}")

def pause():
    input("\n  Premi INVIO per continuare...")


# ---------------------------------------------------------------------------
# Stato globale della sessione
# ---------------------------------------------------------------------------

class Session:
    def __init__(self):
        self.state      = None   # dict restituito da phase1_setup
        self.voter_ids  = []
        self.tokens     = {}     # voter_id -> bytes
        self.ciphertexts = {}    # voter_id -> bytes
        self.receipts   = {}     # voter_id -> bytes
        self.tallied    = False

    def phase_done(self, n: int) -> bool:
        if n == 1: return self.state is not None
        if n == 2: return len(self.tokens) > 0
        if n == 3: return len(self.receipts) > 0
        if n == 4: return self.tallied
        return False


# ---------------------------------------------------------------------------
# Menù principale
# ---------------------------------------------------------------------------

MENU = """
  ┌─────────────────────────────────────────────┐
  │         PROTOCOLLO DI VOTO ELETTRONICO      │
  ├─────────────────────────────────────────────┤
  │  1  Fase 1 – Setup referendum               │
  │  2  Fase 2 – Rilascio token (singolo)       │
  │  2b Fase 2 – Rilascio token (tutti)         │
  │  3  Fase 3 – Vota (singolo elettore)        │
  │  3b Fase 3 – Vota (tutti gli elettori)      │
  │  4  Fase 4 – Scrutinio e pubblicazione      │
  │  5  Verifica universale                     │
  │  6  Verifica individuale (Merkle Proof)     │
  ├─────────────────────────────────────────────┤
  │          SIMULAZIONE ATTACCHI WP3           │
  │  7  Attacchi – CPA (Chosen-Plaintext)       │
  │  8  Attacchi – CCA (Chosen-Ciphertext)      │
  │  9  Attacchi – Replay Attack (Riproduzione) │
  │ 10  Attacchi – LEA (Length Extension)       │
  │ 11  Attacchi – Double-Voting (Riuso token)  │
  │ 12  Attacchi – Token Contraffatto           │
  ├─────────────────────────────────────────────┤
  │ 13  Stato sessione                          │
  │  0  Esci                                    │
  └─────────────────────────────────────────────┘"""

def main():
    sess = Session()

    print(SEP)
    print("  Benvenuto nel simulatore interattivo del protocollo di voto")
    print("  Segui il menu in ordine (1 → 2 → 3 → 4 → 5/6/7/8)")
    print(SEP)

    while True:
        print(MENU)
        scelta = ask("Scelta").lower()

        if scelta == "0":
            print("\n  Arrivederci!")
            break
        elif scelta == "1":
            do_setup(sess)
        elif scelta == "2":
            do_issue_token_single(sess)
        elif scelta == "2b":
            do_issue_token_all(sess)
        elif scelta == "3":
            do_vote_single(sess)
        elif scelta == "3b":
            do_vote_all(sess)
        elif scelta == "4":
            do_tally(sess)
        elif scelta == "5":
            do_verify_universal(sess)
        elif scelta == "6":
            do_verify_individual(sess)
        elif scelta == "7":
            do_attack_cpa(sess)
        elif scelta == "8":
            do_attack_cca(sess)
        elif scelta == "9":
            do_attack_replay(sess)
        elif scelta == "10":
            do_attack_lea(sess)
        elif scelta == "11":
            do_attack_double_voting(sess)
        elif scelta == "12":
            do_attack_fake_token(sess)
        elif scelta == "13":
            do_status(sess)
        else:
            print("  [!] Scelta non riconosciuta.")

        


# ---------------------------------------------------------------------------
# FASE 1 – Setup
# ---------------------------------------------------------------------------

def do_setup(sess: Session):
    banner("FASE 1 – Setup del Referendum")

    info("Definisci i parametri del referendum.")
    question = ask("Quesito referendario", "Sei favorevole alla proposta X?")
    n_voters = ask_int("Numero di elettori da registrare", 5)
    duration = ask_int("Durata del referendum in secondi (da ora)", 3600)

    now      = int(time.time())
    open_ts  = now
    close_ts = now + duration

    # Genera ID elettori
    voter_ids = [f"elettore_{i:03d}" for i in range(n_voters)]
    info(f"\n  Elettori registrati: {', '.join(voter_ids)}")

    confirm = ask_choice("Avviare il setup?", ["s", "n"])
    if confirm != "s":
        info("Setup annullato.")
        return

    print()
    sess.state     = phase1_setup(question, open_ts, close_ts, voter_ids)
    sess.voter_ids = voter_ids
    sess.tokens.clear()
    sess.ciphertexts.clear()
    sess.receipts.clear()
    sess.tallied = False

    print()
    ok(f"Quesito: '{question}'")
    ok(f"Whitelist: {n_voters} elettori")
    ok(f"H_Q = {sess.state['H_Q'].hex()[:32]}...")

    # Verifica firma Admin sul quesito
    valid = rsa_verify(sess.state["pk_admin"], sess.state["H_Q"], sess.state["sig_H_Q"])
    if valid:
        ok("Firma Admin su H_Q verificata correttamente")
    else:
        fail("Firma Admin non valida!")

    pause()


# ---------------------------------------------------------------------------
# FASE 2 – Rilascio Token
# ---------------------------------------------------------------------------

def do_issue_token_single(sess: Session):
    banner("FASE 2 – Rilascio Token (singolo)")

    if not sess.phase_done(1):
        print("  [!] Esegui prima la Fase 1.")
        return

    not_issued = [v for v in sess.voter_ids if v not in sess.tokens]
    if not not_issued:
        info("Tutti gli elettori hanno già ricevuto un token.")
        return

    info(f"Elettori ancora senza token: {', '.join(not_issued)}")
    voter_id = ask("ID elettore", not_issued[0])

    if voter_id not in sess.voter_ids:
        print(f"  [!] '{voter_id}' non è nella whitelist.")
        return

    if voter_id in sess.tokens:
        info(f"'{voter_id}' ha già un token.")
        return

    try:
        tok = phase2_issue_token(sess.state, voter_id)
        sess.tokens[voter_id] = tok
        ok(f"Token emesso per '{voter_id}'")
        info(f"  Dimensione pacchetto: {len(tok)} byte")
        info(f"  nonce_i = {tok[:8].hex()}...  |  T_i = {tok[-8:].hex()}...")
    except ValueError as e:
        fail(str(e))

    pause()


def do_issue_token_all(sess: Session):
    banner("FASE 2 – Rilascio Token (tutti gli elettori)")

    if not sess.phase_done(1):
        print("  [!] Esegui prima la Fase 1.")
        return

    emitted = 0
    for vid in sess.voter_ids:
        if vid not in sess.tokens:
            tok = phase2_issue_token(sess.state, vid)
            sess.tokens[vid] = tok
            ok(f"Token emesso per '{vid}'")
            emitted += 1
        else:
            info(f"'{vid}' ha già un token — saltato")

    info(f"\n  Token emessi in questa sessione: {emitted}")
    info(f"  Token totali: {len(sess.tokens)} / {len(sess.voter_ids)}")
    pause()


# ---------------------------------------------------------------------------
# FASE 3 – Voto
# ---------------------------------------------------------------------------

def do_vote_single(sess: Session):
    banner("FASE 3 – Espressione del Voto (singolo)")

    if not sess.phase_done(2):
        print("  [!] Esegui prima la Fase 2 per almeno un elettore.")
        return

    eligible = [v for v in sess.tokens if v not in sess.receipts]
    if not eligible:
        info("Tutti gli elettori che hanno un token hanno già votato.")
        return

    info(f"Elettori che possono votare: {', '.join(eligible)}")
    voter_id = ask("ID elettore", eligible[0])

    if voter_id not in sess.tokens:
        print(f"  [!] '{voter_id}' non ha un token.")
        return
    if voter_id in sess.receipts:
        print(f"  [!] '{voter_id}' ha già votato.")
        return

    # Modifica qui: permette invio vuoto = Nullo
    voto_str = ask("Voto (s = Sì, n = No, INVIO = Nullo)", "").lower()
    if voto_str == "s":
        voto = 1
    elif voto_str == "n":
        voto = 0
    else:
        voto = 2
        info("  → Voto nullo/scheda bianca registrato.")

    try:
        C_i = phase3_encrypt_vote(voto, sess.state["pk_ae"])
        M_i = phase3_compose_message(C_i, sess.tokens[voter_id])
        R_i = phase3_receive_vote(sess.state, M_i)

        sess.ciphertexts[voter_id] = C_i
        sess.receipts[voter_id]    = R_i

        ok(f"Voto di '{voter_id}' registrato nell'urna")
        info(f"  C_i (ciphertext RSA-OAEP): {C_i[:8].hex()}...")
        info(f"  Ricevuta (ballot_hash):     {R_i[:8].hex()}...")
        info(f"  Dimensione M_i:             {len(M_i)} byte")
    except ValueError as e:
        fail(str(e))

    pause()


def do_vote_all(sess: Session):
    banner("FASE 3 – Espressione del Voto (tutti)")

    if not sess.phase_done(2):
        print("  [!] Esegui prima la Fase 2 per tutti gli elettori.")
        return

    info("Definisci il voto per ciascun elettore (s/n), oppure lascia vuoto per voto casuale.")
    print()

    import random
    for vid in sess.voter_ids:
        if vid not in sess.tokens:
            info(f"'{vid}' non ha token — saltato")
            continue
        if vid in sess.receipts:
            info(f"'{vid}' ha già votato — saltato")
            continue

        scelta = ask(f"Voto per '{vid}' [s/n/invio=nullo]", "")
        if scelta.lower() == "s":
            voto = 1
        elif scelta.lower() == "n":
            voto = 0
        else:
            voto = 2
            info(f"  → Voto nullo registrato")

        try:
            C_i = phase3_encrypt_vote(voto, sess.state["pk_ae"])
            M_i = phase3_compose_message(C_i, sess.tokens[vid])
            R_i = phase3_receive_vote(sess.state, M_i)
            sess.ciphertexts[vid] = C_i
            sess.receipts[vid]    = R_i
            ok(f"Voto di '{vid}' registrato")
        except ValueError as e:
            fail(f"'{vid}': {e}")

    info(f"\n  Voti nell'urna: {len(sess.state['ae_urn'])}")
    pause()


# ---------------------------------------------------------------------------
# FASE 4 – Scrutinio
# ---------------------------------------------------------------------------

def do_tally(sess: Session):
    banner("FASE 4 – Scrutinio e Pubblicazione")

    if not sess.phase_done(3):
        print("  [!] Esegui prima la Fase 3 (almeno un voto).")
        return
    if sess.tallied:
        info("Lo scrutinio è già stato eseguito. Risultato:")
        _print_result(sess, sess.state["result"])
        pause()
        return

    # per non aspettare tutto il tempo, simulazione del passaggio del tempo
    if int(time.time()) < sess.state["close_ts"]:
        info("ATTENZIONE: Il tempo del referendum non è ancora scaduto.")
        forza = ask_choice("Vuoi forzare la scadenza del tempo ora (simulazione salto temporale)?", ["s", "n"])
        if forza == "s":
            sess.state["close_ts"] = int(time.time()) - 1
            ok("Salto temporale effettuato. Il referendum è ora ufficialmente concluso.")
        else:
            info("Operazione annullata. Attendi la fine del referendum.")
            pause()
            return

    confirm = ask_choice("Chiudere l'urna ed eseguire lo scrutinio?", ["s", "n"])
    if confirm != "s":
        return

    print()
    try:
        result = phase4_tally_and_publish(sess.state)
        sess.tallied = True

        print()
        _print_result(sess, result)
        info(f"\n  Merkle Root: {sess.state['merkle_root'].hex()[:32]}...")
        info(f"  Livelli Merkle Tree: {len(sess.state['merkle_tree'])}")
    except ValueError as e:
        fail(str(e))
    
    pause()


def _print_result(sess: Session, result: dict):
    ok(f"Sì:           {result['yes']}")
    ok(f"No:           {result['no']}")
    ok(f"Nulli/Bianche:{result['null']}")
    
    # Calcolo reale degli astenuti
    astenuti = len(sess.voter_ids) - result['total_ballots']
    info(f"  Non Votanti:  {astenuti}")
    
    ok(f"Totale Schede:{result['total_ballots']}")


# ---------------------------------------------------------------------------
# VERIFICA UNIVERSALE
# ---------------------------------------------------------------------------

def do_verify_universal(sess: Session):
    banner("VERIFICA UNIVERSALE")

    if not sess.phase_done(4):
        print("  [!] Esegui prima la Fase 4.")
        return

    checks = verify_universal(sess.state)
    for k, v in checks.items():
        if v: ok(k)
        else: fail(k)

    all_ok = all(checks.values())
    print()
    if all_ok:
        ok("TUTTI I CONTROLLI SUPERATI — referendum integro")
    else:
        fail("ALCUNI CONTROLLI FALLITI")

    pause()


# ---------------------------------------------------------------------------
# VERIFICA INDIVIDUALE
# ---------------------------------------------------------------------------

def do_verify_individual(sess: Session):
    banner("VERIFICA INDIVIDUALE (Merkle Proof)")

    if not sess.phase_done(4):
        print("  [!] Esegui prima la Fase 4.")
        return

    voted = list(sess.receipts.keys())
    if not voted:
        info("Nessun elettore ha votato in questa sessione.")
        return

    info(f"Elettori con ricevuta: {', '.join(voted)}")
    voter_id = ask("ID elettore da verificare", voted[0])

    if voter_id not in sess.receipts:
        print(f"  [!] Nessuna ricevuta trovata per '{voter_id}'.")
        return

    C_i = sess.ciphertexts[voter_id]
    R_i = sess.receipts[voter_id]

    checks = verify_individual(sess.state, C_i, R_i)
    for k, v in checks.items():
        if v: ok(k)
        else: fail(k)

    if all(checks.values()):
        ok(f"\n  Il voto di '{voter_id}' è incluso e verificato nel Merkle Tree")
    else:
        fail(f"\n  Verifica fallita per '{voter_id}'")

    pause()

# ---------------------------------------------------------------------------
# ATTACCHI WP3 – Proprietà crittografiche (CPA, CCA, Replay, LEA)
# ---------------------------------------------------------------------------

def do_attack_cpa(sess: Session):
    banner("ATTACCO – Chosen-Plaintext Attack (CPA)")

    if not sess.phase_done(1):
        print("  [!] Esegui prima la Fase 1 per generare le chiavi.")
        return

    info("Teoria: L'attaccante cifra tutti i voti possibili per creare un dizionario.")
    info("Se il sistema è deterministico i ciphertext corrisponderanno a quelli nell'urna.")
    print()

    pk = sess.state["pk_ae"]
    info("Cifro il voto '1' (Sì) per due volte consecutive con la stessa chiave pubblica...")

    c1 = phase3_encrypt_vote(1, pk)
    c2 = phase3_encrypt_vote(1, pk)

    info(f"  C_1 = {c1[:16].hex()}...")
    info(f"  C_2 = {c2[:16].hex()}...")

    if c1 != c2:
        ok("I ciphertext sono completamente diversi!")
        ok("Difesa riuscita: il padding probabilistico RSA-OAEP garantisce sicurezza CPA.")
        ok("L'attaccante non può risalire ai voti confrontando i ciphertext.")
    else:
        fail("I ciphertext sono identici! (VULNERABILITÀ CPA RILEVATA)")

    pause()


def do_attack_cca(sess: Session):
    banner("ATTACCO – Chosen-Ciphertext Attack (CCA) e Malleabilità")

    if not sess.phase_done(3):
        print("  [!] Esegui prima la Fase 3 (almeno un voto registrato).")
        return

    voted  = list(sess.receipts.keys())
    victim = voted[-1]
    valid_c = sess.ciphertexts[victim]

    info(f"Teoria: L'attaccante intercetta il ciphertext C_i di '{victim}'.")
    info("Prova ad alterare un byte del ciphertext sperando di ribaltare il voto in chiaro.")
    print()

    # Flip XOR sull'ultimo byte del ciphertext
    malicious_c = bytearray(valid_c)
    malicious_c[-1] ^= 0xFF
    malicious_c = bytes(malicious_c)

    info(f"  C_originale (ultimi 16 B) = {valid_c[-16:].hex()}")
    info(f"  C_alterato  (ultimi 16 B) = {malicious_c[-16:].hex()}")
    info("\nL'attaccante invia il pacchetto malevolo; l'AE tenta la decifratura...")

    try:
        rsa_decrypt(sess.state["sk_ae"], malicious_c)
        fail("Decifratura riuscita! Il sistema è malleabile (VULNERABILITÀ CCA RILEVATA).")
    except Exception as e:
        ok(f"Errore catturato durante la decifratura: {type(e).__name__}")
        ok("Difesa riuscita: il controllo di integrità interno di RSA-OAEP")
        ok("ha rilevato la corruzione strutturale, garantendo la non-malleabilità.")

    pause()


def do_attack_replay(sess: Session):
    banner("ATTACCO – Replay Attack (Riproduzione pacchetto)")

    if not sess.phase_done(3):
        print("  [!] Esegui prima la Fase 3 (almeno un voto registrato).")
        return

    voted  = list(sess.receipts.keys())
    victim = voted[-1]

    info(f"Teoria: L'avversario ha registrato il traffico di rete legittimo di '{victim}'.")
    info("Senza alterare nulla, ritrasmette il medesimo pacchetto M_i")
    info("per far valere il voto una seconda volta.")
    print()

    # Ricostruisce il pacchetto M_i originale (già speso)
    C_i        = sess.ciphertexts[victim]
    tok        = sess.tokens[victim]
    M_i_replay = phase3_compose_message(C_i, tok)

    info("Tentativo di reinvio del pacchetto M_i all'Autorità Elettorale...")

    try:
        phase3_receive_vote(sess.state, M_i_replay)
        fail("Pacchetto accettato una seconda volta (VULNERABILITÀ REPLAY RILEVATA)!")
    except ValueError as e:
        ok(f"Bloccato correttamente: {e}")
        ok("Difesa riuscita: il set dei token spesi (token burning) funge da nonce univoco,")
        ok("rigettando immediatamente pacchetti validi ma replicati.")

    pause()


def do_attack_lea(sess: Session):
    banner("ATTACCO – Length Extension Attack (LEA)")

    if not sess.phase_done(1):
        print("  [!] Esegui prima la Fase 1 per generare i dati di base.")
        return

    info("Teoria: nelle costruzioni deboli MAC = H(k || m) un attaccante può prolungare")
    info("l'hashing aggiungendo un suffisso senza conoscere k.")
    print()

    info("Simulazione: l'attaccante estende H_Q (quesito firmato dall'Admin)")
    info("e tenta di spacciare il nuovo hash usando la firma originale.")
    print()

    H_Q_orig    = sess.state["H_Q"]
    sig_H_Q_orig = sess.state["sig_H_Q"]

    info(f"  H_Q legittimo : {H_Q_orig.hex()[:32]}...")

    # L'attaccante concatena dati arbitrari e ricalcola l'hash
    H_Q_fake = sha256(H_Q_orig + b"||OPZIONE_FITTIZIA")
    info(f"  H_Q alterato  : {H_Q_fake.hex()[:32]}...")
    info("\nL'attaccante usa la firma originale sul nuovo hash (non possiede sk_admin)...")

    valid = rsa_verify(sess.state["pk_admin"], H_Q_fake, sig_H_Q_orig)

    if not valid:
        ok("La verifica crittografica ha rigettato il pacchetto (firma non valida).")
        ok("Difesa riuscita: l'autenticazione è basata su RSA-PSS, non su MAC naïf.")
        ok("Il LEA è strutturalmente inapplicabile al protocollo.")
    else:
        fail("Firma risultata valida sull'hash alterato (VULNERABILITÀ LEA RILEVATA)!")

    pause()

# ---------------------------------------------------------------------------
# ATTACCHI – Proprietà di protocollo (Double-Voting, Token contraffatto)
# ---------------------------------------------------------------------------

def do_attack_double_voting(sess: Session):
    banner("ATTACCO – Double-Voting")

    if not sess.phase_done(3):
        print("  [!] Esegui prima la Fase 3 (almeno un voto).")
        return

    # Prende l'ultimo M_i disponibile
    voted = list(sess.receipts.keys())
    if not voted:
        info("Nessun voto disponibile per il test.")
        return

    victim = voted[-1]
    info(f"Tentativo di riusare il token di '{victim}' (già speso)...")

    # Ricostruisce M_i usando C_i e token già usato
    C_i = sess.ciphertexts[victim]
    tok = sess.tokens[victim]
    M_i = phase3_compose_message(C_i, tok)

    try:
        phase3_receive_vote(sess.state, M_i)
        fail("Double-voting NON rilevato — VULNERABILITÀ!")
    except ValueError as e:
        ok(f"Bloccato correttamente: {e}")

    pause()


def do_attack_fake_token(sess: Session):
    banner("ATTACCO – Token Contraffatto")

    if not sess.phase_done(1):
        print("  [!] Esegui prima la Fase 1.")
        return

    info("Genera un token con firma RSA casuale (non valida)...")

    fake_nonce = os.urandom(32)
    fake_ts    = int(time.time()).to_bytes(8, "big")
    fake_sig   = os.urandom(256)
    fake_tok   = fake_nonce + fake_ts + fake_sig

    fake_C = phase3_encrypt_vote(1, sess.state["pk_ae"])
    fake_M = phase3_compose_message(fake_C, fake_tok)

    info(f"  fake_nonce = {fake_nonce[:8].hex()}...")
    info(f"  fake_sig   = {fake_sig[:8].hex()}...")

    try:
        phase3_receive_vote(sess.state, fake_M)
        fail("Token contraffatto ACCETTATO — VULNERABILITÀ!")
    except ValueError as e:
        ok(f"Rigettato correttamente: {e}")

    pause()


# ---------------------------------------------------------------------------
# STATO SESSIONE
# ---------------------------------------------------------------------------

def do_status(sess: Session):
    banner("STATO SESSIONE")

    if sess.state is None:
        info("Nessuna sessione attiva. Esegui la Fase 1.")
        pause()
        return

    info(f"Quesito:           {sess.state['question']}")
    info(f"Elettori totali:   {len(sess.voter_ids)}")
    info(f"Token emessi:      {len(sess.tokens)} / {len(sess.voter_ids)}")
    info(f"Voti registrati:   {len(sess.receipts)} / {len(sess.voter_ids)}")
    info(f"Scrutinio eseguito: {'Sì' if sess.tallied else 'No'}")

    if sess.tallied:
        r = sess.state["result"]
        astenuti = len(sess.voter_ids) - r['total_ballots']
        info(f"Risultato:         Sì={r['yes']}  No={r['no']}  Nulli={r['null']}  Astenuti={astenuti}")
        
    fasi = []
    for i in range(1, 5):
        fasi.append(f"Fase {i}: {'✓' if sess.phase_done(i) else '✗'}")
    info("  " + "  |  ".join(fasi))

    pause()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    main()
