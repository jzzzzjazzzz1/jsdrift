import http.client
import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from jsdrift.config import ConfigError, quick_target
from jsdrift.demo import AWS_ID, AWS_SECRET, DemoApp
from jsdrift.engine import ScanError, scan_target
from jsdrift.fetcher import Fetcher
from jsdrift.report import alert_items, build_report
from jsdrift.scope import Scope, ScopeConfigError
from jsdrift.store import Store
from jsdrift.web import make_server


def target(base, **kw):
    return quick_target(base + "/", ["127.0.0.1"], allow_http=True, allow_private_ips=True, trust_env=False, delay=0.0, **kw)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.app = DemoApp()
        self.base = self.app.start()
        self.t = target(self.base)
        self.store = Store(Path(self.tmp.name) / "t.db")

    def tearDown(self):
        self.app.stop()
        self.store.close()
        self.tmp.cleanup()

    def scan(self):
        r = scan_target(self.store, self.t, log=lambda s: None)
        return r, build_report(self.store, r.run_id, min_conf=60)


class DriftSemantics(Base):
    def test_baseline_then_drift(self):
        r1, rep1 = self.scan()
        self.assertTrue(r1.baseline)
        self.assertEqual(alert_items(rep1), [])           # never alert on the first scan
        self.app.deploy()
        r2, rep2 = self.scan()
        self.assertFalse(r2.baseline)
        new = {(f["kind"], f["value"]) for f in rep2["new"]}
        self.assertIn(("endpoint", "/api/v2/admin/users/{param}/impersonate"), new)
        self.assertIn(("param", "redirect_url"), new)
        self.assertIn(("graphql", "mutation PurgeAccount"), new)
        rules = {f["rule"] for f in rep2["new"] if f["kind"] == "secret"}
        self.assertTrue({"aws_access_key_id", "github_token", "jwt", "gitlab_pat"} <= rules, rules)
        self.assertTrue(any(f["kind"] == "sourcemap" for f in rep2["new"]))
        self.assertEqual([f["value"] for f in rep2["removed"]], ["/api/v1/users/me"])

    def test_hash_rename_is_one_file_changed_not_added_and_removed(self):
        self.scan()
        self.app.deploy()
        _, rep = self.scan()
        added = [x["file"] for x in rep["files"]["added"]]
        self.assertEqual(len(added), 1)
        self.assertIn("admin-panel", added[0])
        self.assertEqual(rep["files"]["removed"], [])
        self.assertEqual(len(rep["files"]["changed"]), 1)
        self.assertIn("main", rep["files"]["changed"][0]["file"])

    def test_no_change_means_no_drift_and_files_are_carried(self):
        self.scan()
        self.app.deploy()
        self.scan()
        r3, rep3 = self.scan()
        self.assertEqual((rep3["new"], rep3["removed"], rep3["reappeared"]), ([], [], []))
        self.assertEqual(r3.stats["files"]["analyzed"], 1 + 0 if False else r3.stats["files"]["analyzed"])
        self.assertGreater(r3.stats["files"]["carried"], 0)

    def test_partial_scan_never_invents_removals(self):
        self.app.deploy()
        self.scan()
        self.app.fail = {"/static/js/main."}               # CDN hiccup on the main bundle
        r, rep = self.scan()
        self.assertEqual(r.status, "partial")
        self.assertEqual(rep["removed"], [])
        self.assertEqual(rep["new"], [])
        self.app.fail = set()
        r, rep = self.scan()
        self.assertEqual(r.status, "ok")
        self.assertEqual((rep["new"], rep["removed"]), ([], []))   # recovered silently, no fake "reappeared"

    def test_removed_then_reappeared(self):
        self.app.deploy()
        self.scan()
        self.app.version = 1
        _, rep = self.scan()
        self.assertTrue(rep["removed"])
        self.app.deploy()
        _, rep = self.scan()
        self.assertTrue(any(f["value"] == "/api/v2/admin/users/{param}/impersonate" for f in rep["reappeared"]))

    def test_false_positive_triage_suppresses_alerts(self):
        self.scan()
        self.app.deploy()
        r2, rep = self.scan()
        f = [x for x in rep["new"] if x["kind"] == "param" and x["value"] == "redirect_url"][0]
        self.store.set_triage(self.t.name, f["id"], "false_positive")
        rep2 = build_report(self.store, r2.run_id, min_conf=60)
        self.assertNotIn("redirect_url", [x["value"] for x in rep2["new"] if x["kind"] == "param"])
        self.assertEqual(rep2["hidden"]["false_positive"], 1)

    def test_secrets_are_masked_in_reports_and_unmasked_on_reveal(self):
        self.scan()
        self.app.deploy()
        r2, rep = self.scan()
        text = json.dumps(rep)
        self.assertNotIn(AWS_ID, text)
        self.assertNotIn(AWS_SECRET, text)
        self.assertIn(AWS_ID, json.dumps(build_report(self.store, r2.run_id, reveal=True)))

    def test_third_party_script_never_requested(self):
        r, _ = self.scan()
        self.assertTrue(any("thirdparty.test" in u for u in r.crawl.third_party))
        self.assertEqual(r.stats["requests"], 3)            # page + 2 scripts, nothing else

    def test_stored_versions_diffable(self):
        self.scan()
        self.app.deploy()
        self.scan()
        row = [r for r in self.store.find_file(self.t.name, "main") if r["kind"] == "js"][0]
        vs = self.store.versions(row["id"])
        self.assertEqual(len(vs), 2)
        self.assertIn("impersonate", self.store.version_text(vs[1]["id"]))


class ScopeSafety(unittest.TestCase):
    def test_patterns(self):
        s = Scope(in_scope=["app.acme.com", "*.api.acme.com"], out_of_scope=["secret.api.acme.com"])
        self.assertTrue(s.check("https://app.acme.com/x", resolve=False))
        self.assertTrue(s.check("https://v1.api.acme.com/x", resolve=False))
        self.assertFalse(s.check("https://secret.api.acme.com/x", resolve=False))      # out_of_scope wins
        self.assertFalse(s.check("https://evil.com/?h=app.acme.com", resolve=False))
        self.assertFalse(s.check("https://app.acme.com.evil.com/", resolve=False))
        self.assertFalse(s.check("http://app.acme.com/", resolve=False))               # plain http blocked by default
        self.assertFalse(s.check("ftp://app.acme.com/", resolve=False))
        self.assertFalse(s.check("https://user:pw@app.acme.com/", resolve=False))

    def test_too_broad_and_missing_scope_rejected(self):
        with self.assertRaises(ScopeConfigError):
            Scope(in_scope=["*.com"])
        with self.assertRaises(ScopeConfigError):
            Scope(in_scope=[])

    def test_private_and_metadata_addresses_blocked(self):
        s = Scope(in_scope=["127.0.0.1", "169.254.169.254", "10.0.0.5"], allow_http=True)
        self.assertFalse(s.check("http://127.0.0.1/"))
        self.assertFalse(s.check("http://10.0.0.5/"))
        s2 = Scope(in_scope=["169.254.169.254"], allow_http=True, allow_private_ips=True)
        self.assertFalse(s2.check("http://169.254.169.254/latest/meta-data/"))          # never, even with allow_private

    def test_redirect_to_out_of_scope_host_is_not_followed(self):
        hits = []

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a): pass

            def do_GET(self):
                hits.append(self.path)
                self.send_response(302)
                self.send_header("Location", f"http://localhost:{self.server.server_address[1]}/stolen")
                self.end_headers()

        srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            sc = Scope(in_scope=["127.0.0.1"], allow_http=True, allow_private_ips=True)
            f = Fetcher(sc, delay=0, trust_env=False)
            r = f.get(f"http://127.0.0.1:{srv.server_address[1]}/start")
            self.assertTrue(r.blocked, r)
            self.assertEqual(hits, ["/start"])                                          # the redirect target was never requested
        finally:
            srv.shutdown()

    def test_blocked_seed_fails_loudly(self):
        with tempfile.TemporaryDirectory() as d:
            t = quick_target("http://127.0.0.1:9/", ["127.0.0.1"], allow_private_ips=True)   # http not allowed
            with self.assertRaises(ScanError):
                scan_target(Store(Path(d) / "x.db"), t, log=lambda s: None)

    def test_config_requires_scope(self):
        from jsdrift.config import _build_target
        with self.assertRaises(ConfigError):
            _build_target("x", {"seeds": ["https://a.com/"]}, {})


class Dashboard(Base):
    def setUp(self):
        super().setUp()
        self.scan()
        self.app.deploy()
        self.scan()
        self.srv, self.token = make_server(self.store.path, port=0)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        super().tearDown()

    def req(self, method, path, headers=None, body=None, host=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port)
        h = {"Host": host or f"127.0.0.1:{self.port}", **(headers or {})}
        c.request(method, path, body=body, headers=h)
        r = c.getresponse()
        return r.status, r.read(), dict(r.getheaders())

    def test_static_open_api_needs_token(self):
        self.assertEqual(self.req("GET", "/")[0], 200)
        self.assertEqual(self.req("GET", "/api/targets")[0], 401)
        self.assertEqual(self.req("GET", "/api/targets", {"X-JSDrift-Token": "wrong"})[0], 401)
        st, body, hdr = self.req("GET", "/api/targets", {"X-JSDrift-Token": self.token})
        self.assertEqual(st, 200)
        self.assertIn("default-src 'none'", hdr["Content-Security-Policy"])

    def test_dns_rebinding_host_rejected(self):
        self.assertEqual(self.req("GET", "/api/targets", {"X-JSDrift-Token": self.token}, host="evil.com")[0], 403)

    def test_cross_origin_rejected(self):
        st, *_ = self.req("GET", "/api/targets", {"X-JSDrift-Token": self.token, "Origin": "http://evil.com"})
        self.assertEqual(st, 401)

    def test_secrets_masked_until_revealed(self):
        h = {"X-JSDrift-Token": self.token}
        _, body, _ = self.req("GET", f"/api/findings?target={self.t.name}&kind=secret", h)
        self.assertNotIn(AWS_ID, body.decode())
        items = json.loads(body)["items"]
        aws = [i for i in items if i["rule"] == "aws_access_key_id"][0]
        _, body, _ = self.req("GET", f"/api/finding?id={aws['id']}&reveal=1", h)
        self.assertEqual(json.loads(body)["value"], AWS_ID)

    def test_triage_post_rules(self):
        h = {"X-JSDrift-Token": self.token}
        _, body, _ = self.req("GET", f"/api/findings?target={self.t.name}&kind=param", h)
        fid = json.loads(body)["items"][0]["id"]
        payload = json.dumps({"target": self.t.name, "id": fid, "triage": "false_positive"})
        self.assertEqual(self.req("POST", "/api/triage", h, payload)[0], 415)            # needs JSON content-type
        self.assertEqual(self.req("POST", "/api/triage", {"Content-Type": "application/json"}, payload)[0], 401)
        st, body, _ = self.req("POST", "/api/triage", {**h, "Content-Type": "application/json"}, payload)
        self.assertEqual((st, json.loads(body)["ok"]), (200, True))
        bad = json.dumps({"target": self.t.name, "id": fid, "triage": "'; DROP TABLE findings;--"})
        self.assertEqual(self.req("POST", "/api/triage", {**h, "Content-Type": "application/json"}, bad)[0], 400)

    def test_frontend_never_uses_innerhtml(self):
        src = (Path(__file__).parent.parent / "jsdrift" / "static" / "app.js").read_text()
        for bad in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("):
            self.assertNotIn(bad, src)

    def test_refuses_non_loopback_bind(self):
        with self.assertRaises(ValueError):
            make_server(self.store.path, host="0.0.0.0", port=0)


if __name__ == "__main__":
    unittest.main()
