import unittest
import zlib

from jsdrift.demo import AWS_ID, gh_token, service_role_jwt, stripe_placeholder
from jsdrift.extract import Extractor
from jsdrift.models import SEV_RANK
from jsdrift.secrets import _base62
from jsdrift.util import entropy, identity_key


def run(src, vendor=False):
    return Extractor(explain=True).run(src, "t.js", vendor)


def by(res, kind):
    return [f for f in res.findings if f.kind == kind]


# Things a naive regex scanner reports and a human would call noise.
FP_CORPUS = r'''
var a={password:"Password",forgot_password:"Forgot your password?",token:"authToken",secret:"secretKey",
 apiKey:"YOUR_API_KEY_HERE",client_secret:"<client-secret>",pwd:"changeme",passwd:"xxxxxxxx",title:"Reset password"};
var csrf={csrfToken:"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",nonce:"Zk3q9XvT2mLp8RwY5nB7cD1eF4gH6jKa",siteKey:"6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI"};
var docs={aws:"__DOC_AWS__",secret:"__DOC_SECRET__",
 jwt:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
 pem:"-----BEGIN PRIVATE KEY-----",pem2:"-----BEGIN RSA PRIVATE KEY-----",stripe:"__STRIPE_PH__"};
var m={ns:"http://www.w3.org/2000/svg",x:"http://www.w3.org/1999/xhtml",mime:"application/json",m2:"text/html; charset=utf-8",
 fmt:"DD/MM/YYYY",fmt2:"HH:mm:ss",img:"/static/img/logo.png",css:"/assets/app.css",font:"/fonts/a.woff2",
 mod:"/node_modules/lodash/fp.js",re:/^[\w.+-]+@[\w-]+\.[\w.-]+$/,r2:/["']\s*\/\/[a-z]+/g,loc:"en/US",ratio:"16/9",
 docs:"https://reactjs.org/docs/error-decoder.html?invariant=",cdn:"https://cdnjs.cloudflare.com/ajax/libs/x/1.0/x.js"};
var d=a/b/c, e=x/y;
'''

# Documentation/placeholder keys are assembled at import time so no complete credential-shaped
# literal exists in the repository (GitHub push protection scans for those).
FP_CORPUS = (FP_CORPUS
             .replace("__DOC_AWS__", "AKIA" + "IOSFODNN7" + "EXAMPLE")
             .replace("__DOC_SECRET__", "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY")
             .replace("__STRIPE_PH__", stripe_placeholder()))


class FalsePositives(unittest.TestCase):
    def test_corpus_yields_no_secrets_and_no_noise_endpoints(self):
        res = run(FP_CORPUS)
        self.assertEqual(by(res, "secret"), [], [f.display for f in by(res, "secret")])
        bad = [f.value for f in res.findings if f.kind in ("endpoint", "host", "route")]
        self.assertEqual(bad, [], bad)

    def test_rejections_are_explained(self):
        why = " ".join(r.reason for r in run(FP_CORPUS).rejected)
        for needle in ("placeholder", "documentation", "public by design", "PEM header only", "identifier"):
            self.assertIn(needle, why)

    def test_low_entropy_and_words_rejected(self):
        res = run('var x={secret:"abcdefghij",password:"aaaaaaaaaa",apiKey:"averylongplainenglishword"};')
        self.assertEqual(by(res, "secret"), [])


class TruePositives(unittest.TestCase):
    def test_vendor_secrets(self):
        src = f'var a="{gh_token()}",b="{AWS_ID}",c="{service_role_jwt()}";'
        res = run(src)
        rules = {f.rule for f in by(res, "secret")}
        self.assertTrue({"github_token", "aws_access_key_id", "jwt"} <= rules, rules)
        jwt = [f for f in by(res, "secret") if f.rule == "jwt"][0]
        self.assertEqual(jwt.severity, "critical")

    def test_github_checksum_mismatch_penalised(self):
        core = "aB3dE5gH7jK9mN1pQ3sT5vX7zA9cD1"
        good = "ghp_" + core + _base62(zlib.crc32(core.encode()) & 0xFFFFFFFF, 6)
        bad = "ghp_" + core + "000000"
        g = by(run(f'x="{good}";'), "secret")[0]
        b = by(run(f'x="{bad}";'), "secret")[0]
        self.assertGreater(g.confidence, b.confidence + 20)

    def test_generic_high_entropy_assignment(self):
        res = run('var c={apiKey:"Zk3q9XvT2mLp8RwY5nB7cD1eF4gH6jKa"};')
        f = by(res, "secret")[0]
        self.assertEqual(f.rule, "generic_assignment")
        self.assertGreaterEqual(f.confidence, 60)

    def test_pem_with_body_is_critical(self):
        body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7" * 4
        res = run(f'k="-----BEGIN PRIVATE KEY-----\\n{body}\\n-----END PRIVATE KEY-----";')
        self.assertEqual(by(res, "secret")[0].severity, "critical")

    def test_expired_jwt_demoted(self):
        import base64, json
        b = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
        tok = f"{b({'alg': 'HS256'})}.{b({'sub': 'u1', 'exp': 1000})}.c2ln"
        f = by(run(f'x="{tok}";'), "secret")[0]
        self.assertEqual(f.severity, "low")

    def test_public_by_design_keys_are_info(self):
        f = by(run('x="pk_live_51HqZ3xT9mLpV8wYk2nB7cD1e";'), "secret")[0]
        self.assertEqual(f.severity, "info")

    def test_vendor_file_downweighted(self):
        src = 'var c={apiKey:"Zk3q9XvT2mLp8RwY5nB7cD1eF4gH6jKa"};'
        self.assertLess(by(run(src, True), "secret")[0].confidence, by(run(src), "secret")[0].confidence)


class Endpoints(unittest.TestCase):
    def test_concatenation_joined(self):
        res = run('fetch("/api/v2/admin/users/"+id+"/impersonate",{method:"POST"});')
        vals = [f.value for f in by(res, "endpoint")]
        self.assertEqual(vals, ["/api/v2/admin/users/{param}/impersonate"])
        self.assertEqual(by(res, "endpoint")[0].severity, "high")

    def test_template_and_params(self):
        res = run('axios.get(`/api/orders/${id}/invoice?download=1&redirect_url=` + u);')
        self.assertIn("/api/orders/{param}/invoice", [f.value for f in by(res, "endpoint")])
        names = {f.value for f in by(res, "param")}
        self.assertTrue({"download", "redirect_url"} <= names)

    def test_graphql_and_sourcemap_and_chunks(self):
        res = run('var q="mutation Purge($id: ID!) { purge(id:$id){ok} }"; import("/static/js/admin.9f8e7d6c.js");\n//# sourceMappingURL=a.js.map')
        self.assertEqual([f.value for f in by(res, "graphql")], ["mutation Purge"])
        self.assertIn("/static/js/admin.9f8e7d6c.js", res.js_refs)
        self.assertEqual(res.sourcemaps, ["a.js.map"])

    def test_webpack_chunk_map(self):
        src = '__webpack_require__.u=e=>"static/js/"+e+"."+{12:"abc123",34:"def456"}[e]+".chunk.js";__webpack_require__.p="/";'
        res = run(src)
        self.assertIn("/static/js/12.abc123.chunk.js", res.js_refs)

    def test_cloud_host_hint(self):
        f = by(run('x="https://acme-backups.s3.amazonaws.com/a/b";'), "host")[0]
        self.assertIn("Cloud storage", f.hint)

    def test_regex_literals_dont_derail_lexer(self):
        res = run('var r=/["\']\\s*x/g; fetch("/api/after/regex");')
        self.assertIn("/api/after/regex", [f.value for f in by(res, "endpoint")])


class Identity(unittest.TestCase):
    def test_hash_rename_is_same_file(self):
        a = identity_key("https://a.com/static/js/main.5f3e2a1b.chunk.js?v=3")
        b = identity_key("https://a.com/static/js/main.9c8d7e6f.chunk.js?v=4")
        self.assertEqual(a, b)

    def test_vite_and_next(self):
        self.assertEqual(identity_key("https://a.com/assets/index-DiwrgTda.js"), identity_key("https://a.com/assets/index-Xy12AbCd.js"))
        self.assertEqual(identity_key("https://a.com/_next/static/AbC123xyZ789qwErT45/_buildManifest.js"),
                         identity_key("https://a.com/_next/static/ZzZ999yyY888wwWvV77/_buildManifest.js"))

    def test_real_names_not_collapsed(self):
        self.assertNotEqual(identity_key("https://a.com/js/admin.js"), identity_key("https://a.com/js/billing.js"))
        self.assertEqual(identity_key("https://a.com/js/chunk-vendors.js"), "a.com/js/chunk-vendors.js")

    def test_entropy(self):
        self.assertAlmostEqual(entropy("aaaa"), 0.0)
        self.assertGreater(entropy("Zk3q9XvT2mLp8RwY"), 3.5)


if __name__ == "__main__":
    unittest.main()
