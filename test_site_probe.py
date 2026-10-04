import os, socket, ssl, sys, tempfile, threading
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import certgen

TMP = tempfile.mkdtemp()
CA = certgen.make_ca(TMP)
os.environ["SSL_CERT_FILE"] = os.path.join(TMP, "ca.pem")     # trust our test CA only

from modules import site_probe

def serve(certfile, keyfile):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile, keyfile)
    srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(5)
    port = srv.getsockname()[1]
    def loop():
        while True:
            try:
                c, _ = srv.accept()
                try:
                    with ctx.wrap_socket(c, server_side=True) as s:
                        s.recv(10)
                except Exception:
                    pass
            except Exception:
                return
    threading.Thread(target=loop, daemon=True).start()
    return port

def run():
    good = serve(*certgen.make_leaf(TMP, "good", CA, ["localhost", "127.0.0.1"], -30, 90))
    expired = serve(*certgen.make_leaf(TMP, "exp", CA, ["localhost"], -200, -5))
    selfs = serve(*certgen.make_leaf(TMP, "self", CA, ["localhost"], -10, 300, self_signed=True))
    wrong = serve(*certgen.make_leaf(TMP, "wrong", CA, ["other.example"], -10, 300))
    soon = serve(*certgen.make_leaf(TMP, "soon", CA, ["localhost"], -80, 5))

    # SSRF guard: loopback must be refused unless the test flag is set
    r = site_probe.check_certificate("localhost", good)
    assert r["blocked"] and r["cert"] is None, r

    r = site_probe.check_certificate("localhost", good, allow_private=True)
    assert r["reachable"] and r["trusted"] is True, r
    assert r["cert"]["hostname_match"] and 80 <= r["cert"]["days_left"] <= 90, r["cert"]
    assert r["cert"]["issuer_org"] == "TestCA" and r["cert"]["key_bits"] == 2048
    assert r["tls_version"] in ("TLSv1.2", "TLSv1.3")

    r = site_probe.check_certificate("localhost", expired, allow_private=True)
    assert r["trusted"] is False and r["reason"] == "expired", r
    assert r["cert"]["expired"] and r["cert"]["days_left"] < 0

    r = site_probe.check_certificate("localhost", selfs, allow_private=True)
    assert r["trusted"] is False and r["reason"] in ("self_signed", "self_signed_chain"), r
    assert r["cert"]["self_signed"]

    r = site_probe.check_certificate("localhost", wrong, allow_private=True)
    assert r["trusted"] is False and r["reason"] == "hostname_mismatch", r
    assert r["cert"]["hostname_match"] is False

    r = site_probe.check_certificate("localhost", soon, allow_private=True)
    assert r["trusted"] is True and r["cert"]["days_left"] <= 5, r

    # nothing listening
    dead = socket.socket(); dead.bind(("127.0.0.1", 0)); p = dead.getsockname()[1]; dead.close()
    r = site_probe.check_certificate("localhost", p, timeout=2, allow_private=True)
    assert r["reachable"] is False and r["cert"] is None

    # unresolvable name
    r = site_probe.check_certificate("this-domain-does-not-exist.invalid")
    assert r["dns_ok"] is False

    # wildcard matching
    assert site_probe.host_matches("a.example.com", ["*.example.com"])
    assert not site_probe.host_matches("a.b.example.com", ["*.example.com"])
    assert not site_probe.host_matches("example.com", ["*.example.com"])
    assert site_probe.host_matches("EXAMPLE.com.", ["example.com"])
    assert not site_probe.is_public_ip("10.0.0.5") and not site_probe.is_public_ip("169.254.169.254")
    assert site_probe.is_public_ip("8.8.8.8")
    print("site_probe: all tests passed")

if __name__ == "__main__":
    run()
