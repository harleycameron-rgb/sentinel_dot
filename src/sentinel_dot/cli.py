"""sentinel_dot CLI: keygen | verify | head | migrate | show | anchor"""
import os
import argparse, base64, json, secrets, sys
from . import log as L


def _key(args):
    if getattr(args, "key_env", None):
        from .agent import load_key
        return load_key(args.key_env)
    return None


def _signer(path):
    if not path:
        return None
    from .signing import load_signer
    pw = os.environ.get("SENTINEL_DOT_SIGNING_PASSWORD")
    return load_signer(path, pw.encode() if pw else None)


def _verifier(path):
    if not path:
        return None
    from .signing import load_verifier
    return load_verifier(path)


def main(argv=None):
    from . import __version__
    p = argparse.ArgumentParser(prog="sentinel_dot", description=__doc__)
    p.add_argument("--version", action="version", version=f"sentinel_dot {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)
    kg = sub.add_parser("keygen", help="HMAC: print base64 key. --ed25519: write keypair files")
    kg.add_argument("--ed25519", metavar="PREFIX",
                    help="shorthand for --signing PREFIX --alg ed25519")
    kg.add_argument("--signing", metavar="PREFIX",
                    help="write PREFIX.key (private, 0600) and PREFIX.pub (give to auditors)")
    kg.add_argument("--alg", default="ed25519",
                    choices=["ed25519", "ml-dsa-44", "ml-dsa-65", "ml-dsa-87", "hybrid"],
                    help="signature algorithm for --signing (default ed25519; "
                         "ml-dsa-* are post-quantum; hybrid = Ed25519 + ML-DSA-65)")
    for name in ("verify", "head", "show"):
        s = sub.add_parser(name); s.add_argument("path")
        s.add_argument("--key-env", help="env var holding base64 key")
    sub.choices["verify"].add_argument("--expect-seq", type=int)
    sub.choices["verify"].add_argument("--expect-hash")
    sub.choices["verify"].add_argument("--pubkey", help="public key PEM: Ed25519, ML-DSA or hybrid (auditor mode)")
    sub.choices["show"].add_argument("-n", type=int, default=20, help="last N entries")
    m = sub.add_parser("migrate"); m.add_argument("src"); m.add_argument("dst")
    m.add_argument("--key-env"); m.add_argument("--legacy-head")
    m.add_argument("--no-convert-floats", action="store_true")
    m.add_argument("--signing-key", help="private key PEM: Ed25519, ML-DSA or hybrid (sign migrated log)")
    an = sub.add_parser("anchor", help="Bitcoin anchoring via OpenTimestamps")
    asub = an.add_subparsers(dest="acmd", required=True)
    for n in ("create", "upgrade", "status", "audit"):
        x = asub.add_parser(n); x.add_argument("path", help="log file")
        x.add_argument("--dir", help="anchor directory (default: <log>.anchors)")
    asub.choices["audit"].add_argument("--pubkey"); asub.choices["audit"].add_argument("--key-env")
    asub.choices["audit"].add_argument("--require-confirmed", action="store_true")
    pv = asub.add_parser("verify-proof", help="verify any file + .ots without a Bitcoin node")
    pv.add_argument("file"); pv.add_argument("--ots")
    a = p.parse_args(argv)

    try:
        if a.cmd == "keygen" and (a.ed25519 or a.signing):
            from .signing import generate
            if a.ed25519 and a.signing:
                p.error("use --ed25519 or --signing, not both")
            prefix, alg = (a.ed25519, "ed25519") if a.ed25519 else (a.signing, a.alg)
            priv, pub = prefix + ".key", prefix + ".pub"
            if os.path.exists(priv):
                raise L.LogError(f"{priv} exists; refusing to overwrite")
            sg = generate(alg)
            pw = os.environ.get("SENTINEL_DOT_SIGNING_PASSWORD")
            fd = os.open(priv, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(sg.private_pem(pw.encode() if pw else None))
            with open(pub, "wb") as f:
                f.write(sg.public_pem())
            print(json.dumps({"private": priv, "public": pub, "alg": sg.alg,
                              "key_id": sg.key_id, "encrypted": bool(pw)}))
            return 0
        if a.cmd == "keygen":
            print(base64.b64encode(secrets.token_bytes(32)).decode()); return 0
        if a.cmd == "verify":
            head = None
            if a.expect_seq is not None or a.expect_hash:
                if a.expect_seq is None or not a.expect_hash:
                    p.error("--expect-seq and --expect-hash go together")
                head = (a.expect_seq, a.expect_hash)
            ok, issues = L.verify_log(a.path, key=_key(a), expected_head=head,
                                      verify_key=_verifier(a.pubkey))
            for i in issues: print(json.dumps(i))
            print("OK" if ok else f"FAIL: {len(issues)} issue(s)")
            return 0 if ok else 1
        if a.cmd == "head":
            seq, h = L.AppendOnlyLog(a.path).head()
            print(json.dumps({"next_seq": seq, "hash": h})); return 0
        if a.cmd == "show":
            for e in L.AppendOnlyLog(a.path).read_all()[-a.n:]:
                print(f'{e["seq"]:>6} r{e["round"]:<3} {e["msg_type"]:<15} '
                      f'{e["sender"]:<12} {e["action_type"]:<24} {json.dumps(e["parameters"])[:80]}')
            return 0
        if a.cmd == "anchor":
            from . import anchor as A
            if a.acmd == "verify-proof":
                r = A.verify_proof(a.file, a.ots); print(json.dumps(r, indent=2))
                return 0 if r["ok"] else 1
            d = a.dir or A.default_anchor_dir(a.path)
            if a.acmd == "create":
                print(json.dumps(A.create_anchor(a.path, d), indent=2)); return 0
            if a.acmd == "upgrade":
                print(json.dumps(A.upgrade_anchors(d), indent=2)); return 0
            if a.acmd == "status":
                import glob
                print(json.dumps({os.path.basename(f): A.proof_status(f) for f in
                                  sorted(glob.glob(os.path.join(d, "*.ots")))}, indent=2))
                return 0
            if a.acmd == "audit":
                r = A.check_log_against_anchors(a.path, d, key=_key(a),
                                                verify_key=_verifier(a.pubkey),
                                                require_confirmed=a.require_confirmed)
                print(json.dumps(r, indent=2)); return 0 if r["ok"] else 1
        if a.cmd == "migrate":
            r = L.migrate_legacy_log(a.src, a.dst, key=_key(a), expected_legacy_head=a.legacy_head,
                                     convert_floats=not a.no_convert_floats,
                                     signer=_signer(a.signing_key))
            print(json.dumps(r, indent=2)); return 0
    except (L.LogError, ValueError, OSError, ImportError) as e:
        print(f"error: {e}", file=sys.stderr); return 2


if __name__ == "__main__":
    sys.exit(main())
