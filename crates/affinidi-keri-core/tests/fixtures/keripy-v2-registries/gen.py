"""Generate KERI/ACDC v2 registry conformance fixtures with keripy.

Each scenario is a published `did:webs`-style stream for one issuer AID: its
KEL as keripy replays it (`clonePreIter`), then a v2 registry (`rip`), a v2
designated-aliases ACDC (`acm`) bound to it, and blindable updates (`bup`).
Every message is composed with keripy's own `messagize`:

- `rip`: attachment group with the seal source couple (`-S`) naming the KEL
  event that anchors it;
- `acm`: the body alone (an ACDC v2 is not signed; its issuance is the anchored
  registry update that binds it);
- `bup`: attachment group with its seal source couple and its disclosed blinded
  state (`-a`, public mode: empty UUID).

keripy has no published-stream format for v2 registries (it verifies registry
state from objects, `keri.acdc.regeventing.vet` / `vetBinds`), so this is the
form keripy's own composer produces. keripy re-reads every stream (the KEL
must reach the same state) and its registry verifier rules on the objects that
went into it; both are recorded.

Usage (keripy 2.x installed, libsodium on the library path):

    DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib python -I gen.py .

Regeneration is byte-identical.
"""

import json
import os
import subprocess
import sys

import keri
from keri import Vrsn_1_0, Vrsn_2_0
from keri.acdc import acdcmap, blindate, regcept
from keri.acdc.regeventing import vet, vetBinds
from keri.app import habbing
from keri.core import Blinder, BlindState, Counter, Kevery, Parser, SealSource, messagize
from keri.core.signing import Salter
from keri.db import openDB
from keri.help import helping

helping.nowUTC = lambda: helping.fromIso8601("2026-01-01T00:00:00.000000+00:00")

STAMPS = [f"2026-01-0{i}T00:00:00.000000+00:00" for i in range(1, 9)]
ALIASES_V2 = "EF9Iy-vwD8GRKghnzHHGwAA6sC0VEWNtZ2Sf4tfd4IAA"


def blinder(acdc_said, state):
    """Public-mode disclosure: empty UUID, as the ACDC specification allows
    for a registry whose state is meant to be read by anyone."""
    return Blinder(crew=BlindState(d="", u="", td=acdc_said, ts=state), makify=True)


class Issuer:
    def __init__(self, stack, name, version):
        self.hby, self.hab = stack.enter_context(habbing.openHab(
            name=name, temp=True, version=version,
            salt=Salter(raw=b"vti-keri-v2-regs").qb64b))
        self.version = version
        self.anchors = {}  # registry event SAID -> (kel sn, kel said)

    def anchor(self, *serders):
        self.hab.interact(data=[dict(s=s.sad["n"], d=s.said) for s in serders])
        ev = self.hab.kever.serder
        for s in serders:
            self.anchors[s.said] = (ev.sn, ev.said)
        return ev.sn

    def kel(self):
        out = bytearray()
        if self.version.major >= 2:
            out.extend(Counter.makeGVC(version=Vrsn_2_0))
        for m in self.hby.db.clonePreIter(pre=self.hab.pre, gvrsn=self.version):
            out.extend(m)
        return bytes(out)

    def source(self, serder):
        sn, said = self.anchors[serder.said]
        return SealSource(s=sn, d=said)


def compose(issuer, rip, acdc, updates, *, omit=(), undisclosed=(), unanchored=()):
    """The published stream. `updates` is [(bup, blinder)]."""
    out = bytearray(issuer.kel())
    if issuer.version.major < 2:
        out.extend(Counter.makeGVC(version=Vrsn_2_0))  # the registry is v2 either way
    out.extend(messagize(rip, bonds=[issuer.source(rip)]))
    out.extend(acdc.raw)
    for bup, bl in updates:
        if bup.said in omit:
            continue
        bonds = [] if bup.said in unanchored else [issuer.source(bup)]
        if bup.said not in undisclosed:
            bonds.append(bl.data)
        out.extend(messagize(bup, bonds=bonds) if bonds else bup.raw)
    return bytes(out)


def keripy_verdict(issuer, rip, acdc, updates):
    """What keripy's registry verifier concludes from the given objects."""
    try:
        rec = vetBinds(rip=rip, updates=[b for b, _ in updates], db=issuer.hby.db,
                       blinders=[bl for _, bl in updates], target=acdc.said,
                       controller=issuer.hab.pre, acdc=acdc)
        return {"status": rec.state, "binding": rec.binding, "head": rec.said}
    except Exception as ex:  # keripy's named refusal
        return {"error": type(ex).__name__}


def reread(issuer, stream):
    """keripy must re-read the published stream's KEL to the same state."""
    with openDB(name="reread", temp=True) as db:
        kvy = Kevery(db=db, lax=False, local=False)
        Parser(version=Vrsn_1_0 if issuer.version.major < 2 else Vrsn_2_0).parse(
            ims=bytearray(stream), kvy=kvy)
        if issuer.hab.pre not in db.kevers:
            raise SystemExit("keripy does not re-read the KEL of its own stream")
        if db.kevers[issuer.hab.pre].sn != issuer.hab.kever.sn:
            raise SystemExit(f"keripy re-reads the KEL to a different state: "
                             f"{db.kevers[issuer.hab.pre].sn} != {issuer.hab.kever.sn}; "
                             f"stream head {stream[:120]!r}")


def write(outdir, name, issuer, rip, acdc, stream, *, expect, keripy, note, limit=None):
    reread(issuer, stream)
    with open(os.path.join(outdir, f"{name}.cesr"), "wb") as f:
        f.write(stream)
    body = {
        "note": note,
        "issuer": issuer.hab.pre,
        "schema": ALIASES_V2,
        "registry": rip.said,
        "credential": acdc.said,
        "limit": limit,
        "expect": expect,
        "keripy": keripy,
    }
    with open(os.path.join(outdir, f"{name}.json"), "w") as f:
        json.dump(body, f, indent=2)
        f.write("\n")
    print(f"{name:34} {len(stream):6} bytes  expect={expect}  keripy={keripy}")


def registry(issuer):
    rip = regcept(israid=issuer.hab.pre, uuid=Salter(raw=b"registry-uuid-01").qb64, stamp=STAMPS[0])
    issuer.anchor(rip)
    acdc = acdcmap(israid=issuer.hab.pre, regid=rip.said, schema=ALIASES_V2,
                   attribute=dict(d="", dt=STAMPS[0],
                                  ids=[f"did:webs:example.com:{issuer.hab.pre}"]))
    return rip, acdc


SALT = Salter(raw=b"vti-blind-salt01").qb64


def update(issuer, rip, prior, n, acdc_said, state, anchored=True, salted=False):
    # salted: a fresh UUID per update, derived as keripy's Blinder.blind does and
    # disclosed with the state. Without it the UUID is empty (public mode), and
    # two updates disclosing the same state have the same BLID.
    bl = (Blinder.blind(acdc=acdc_said, state=state, salt=SALT, sn=n) if salted
          else blinder(acdc_said, state))
    bup = blindate(regid=rip.said, prior=prior.said, blid=bl.said, sn=n, stamp=STAMPS[n])
    if anchored:
        issuer.anchor(bup)
    return bup, bl


def scenarios(outdir, stack):
    def fresh(name, version=Vrsn_2_0):
        iss = Issuer(stack, name, version)
        rip, acdc = registry(iss)
        return iss, rip, acdc

    iss, rip, acdc = fresh("issued")
    u = [update(iss, rip, rip, 1, acdc.said, "issued")]
    write(outdir, "v2-issued", iss, rip, acdc, compose(iss, rip, acdc, u),
          expect="issued", keripy=keripy_verdict(iss, rip, acdc, u),
          note="rip, acm, bup(issued); every event anchored and disclosed")

    iss, rip, acdc = fresh("revoked")
    u = [update(iss, rip, rip, 1, acdc.said, "issued")]
    u.append(update(iss, rip, u[0][0], 2, acdc.said, "revoked"))
    write(outdir, "v2-revoked", iss, rip, acdc, compose(iss, rip, acdc, u),
          expect="revoked", keripy=keripy_verdict(iss, rip, acdc, u),
          note="issued, then revoked")
    # As of the KEL event that anchored the issuance, before the revocation.
    write(outdir, "v2-revoked-as-of-issuance", iss, rip, acdc, compose(iss, rip, acdc, u),
          expect="issued", keripy=keripy_verdict(iss, rip, acdc, u[:1]),
          limit=iss.anchors[u[0][0].said][0],
          note="the revoked stream resolved as of the KEL event anchoring the issuance "
               "(versionId): the later revocation is not yet anchored, so the credential "
               "stands. keripy has no KEL-position cutoff (vetBinds' cutoff is a time); "
               "its verdict here is over the updates anchored by then")
    write(outdir, "v2-revocation-withheld", iss, rip, acdc,
          compose(iss, rip, acdc, u, omit={u[1][0].said}),
          expect="error:missing-anchored-event",
          keripy=keripy_verdict(iss, rip, acdc, u[:1]),
          note="the KEL anchors the revoking bup but the stream leaves it out. keripy checks "
               "that what is presented is anchored, not that everything anchored is "
               "presented, so it rules on what it is given (issued); P5 refuses")

    iss, rip, acdc = fresh("reissued")
    u = [update(iss, rip, rip, 1, acdc.said, "issued", salted=True)]
    u.append(update(iss, rip, u[0][0], 2, acdc.said, "revoked", salted=True))
    u.append(update(iss, rip, u[1][0], 3, acdc.said, "issued", salted=True))
    write(outdir, "v2-reissued", iss, rip, acdc, compose(iss, rip, acdc, u),
          expect="issued", keripy=keripy_verdict(iss, rip, acdc, u),
          note="issued, revoked, issued again, each update with its own disclosed UUID: "
               "the latest non-vacuous update rules")

    iss, rip, acdc = fresh("reissued-empty")
    u = [update(iss, rip, rip, 1, acdc.said, "issued")]
    u.append(update(iss, rip, u[0][0], 2, acdc.said, "revoked"))
    u.append(update(iss, rip, u[1][0], 3, acdc.said, "issued"))
    write(outdir, "v2-reissued-empty-uuid", iss, rip, acdc, compose(iss, rip, acdc, u),
          expect="issued", keripy=keripy_verdict(iss, rip, acdc, u),
          note="the same re-issuance in public mode (empty UUID): updates 1 and 3 disclose "
               "the same state, so they have the same BLID. keripy's vetBinds matches "
               "disclosures to updates by BLID from a detached list and refuses two matches "
               "(UnverifiedBlindError). In the stream each disclosure is attached to its "
               "own bup, so it is unambiguous; a reader that binds by attachment accepts it. "
               "Writers should use a fresh UUID per update (v2-reissued)")

    iss, rip, acdc = fresh("vacuous")
    u = [update(iss, rip, rip, 1, acdc.said, "issued")]
    u.append(update(iss, rip, u[0][0], 2, "", ""))
    write(outdir, "v2-vacuous-head", iss, rip, acdc, compose(iss, rip, acdc, u),
          expect="issued", keripy=keripy_verdict(iss, rip, acdc, u),
          note="issued, then a vacuous (placeholder) update: the latest non-vacuous one rules")

    iss, rip, acdc = fresh("undisclosed")
    u = [update(iss, rip, rip, 1, acdc.said, "issued")]
    u.append(update(iss, rip, u[0][0], 2, acdc.said, "revoked"))
    write(outdir, "v2-head-undisclosed", iss, rip, acdc,
          compose(iss, rip, acdc, u, undisclosed={u[1][0].said}),
          expect="error:undisclosed-update",
          keripy=keripy_verdict(iss, rip, acdc, [(u[0][0], u[0][1]), (u[1][0], Blinder(
              crew=BlindState(d="", u="", td="", ts=""), makify=True))]),
          note="the head bup carries no disclosure: every update back to the latest "
               "non-vacuous one must be disclosed")

    iss, rip, acdc = fresh("unanchored")
    u = [update(iss, rip, rip, 1, acdc.said, "issued")]
    u.append(update(iss, rip, u[0][0], 2, acdc.said, "revoked", anchored=False))
    write(outdir, "v2-update-unanchored", iss, rip, acdc,
          compose(iss, rip, acdc, u, unanchored={u[1][0].said}),
          expect="error:unanchored-event", keripy=keripy_verdict(iss, rip, acdc, u),
          note="a bup the issuer's KEL never anchored is in the stream: it establishes "
               "nothing, and keripy refuses the whole determination")

    # A v1 KEL anchoring a v2 registry is allowed (P2) but not generated here:
    # keripy's Hab(version=Vrsn_1_0) writes a v1 icp and then v2 ixn events, and
    # replaying that log with a v1 genus emits v2 attachments without a genus
    # switch, which keripy itself cannot re-read past sn 0. See README.


def main(outdir):
    import contextlib
    commit = subprocess.run(["git", "-C", os.path.dirname(keri.__file__), "rev-parse", "--short", "HEAD"],
                            capture_output=True, text=True).stdout.strip()
    with contextlib.ExitStack() as stack:
        scenarios(outdir, stack)
    with open(os.path.join(outdir, "KERIPY_VERSION"), "w") as f:
        f.write(f"keripy {keri.__version__} {commit}\n")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else ".")
