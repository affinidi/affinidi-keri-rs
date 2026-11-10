"""Generate KERI v2 conformance fixtures with keripy.

Every fixture is built with keripy's own event builders, processed by keripy's
`Kevery`, published the way keripy replays a log (`clonePreIter`, what a
did:webs `keri.cesr` generator emits), and then re-parsed into a fresh keripy
database. A fixture is written only if keripy accepts its own published stream
and reaches the same key state.

Usage (from this directory, keripy 2.x installed, libsodium on the library path):

    DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib python -I gen.py .

Outputs, per scenario:
    <name>.cesr   the published stream
    <name>.json   keripy's resulting key state, and the scenario's expectation
                  for a conforming verifier

Regenerating must produce identical bytes: every key comes from a fixed salt and
Ed25519 signatures are deterministic. A diff after re-pinning keripy is a
behaviour change to review, not noise.
"""

import json
import os
import subprocess
import sys

import keri
from keri import Kinds, Vrsn_1_0, Vrsn_2_0
from keri.core import Counter, DigDex, Diger, Kevery, Number, Parser, Prefixer, Salter, incept, interact, messagize, reply, rotate
from keri.core import routing
import contextlib
import itertools

from keri.db import openDB
from keri.help import helping

# First-seen replay couples carry the time an event was first seen. Pin it, as
# keripy's own tests do (tests/conftest.py, mockHelpingNowUTC), so regeneration
# is byte-identical.
helping.nowUTC = lambda: helping.fromIso8601("2026-01-01T00:00:00.000000+00:00")

KIND = Kinds.json  # what VTI writes (P8); native CESR bodies are covered by basic(..., kind=Kinds.cesr)
SALT = b"vti-keri-v2-fixt"
_DBS = itertools.count()
_OPEN = contextlib.ExitStack()  # databases stay open until the generator exits  # 16 bytes; every key below derives from it


def keys(n, path):
    return Salter(raw=SALT).signers(count=n, path=path, transferable=True)


def ndig(signer):
    return Diger(ser=signer.verfer.qb64b).qb64


def msg(serder, signed):
    """`signed` is [(signer, index, ondex)]; ondex None means same as index."""
    sigers = [s.sign(serder.raw, index=i, ondex=o) for s, i, o in signed]
    # Attachments in the genus of the message's own version. keripy's
    # messagize defaults to v2 attachment groups even on a v1 event; a v1
    # producer emits v1 groups, and #216 proposes that a message's body version
    # and attachment genus agree.
    return bytes(messagize(serder, sigers=sigers, gvrsn=serder.pvrsn))


def state(kever):
    if kever is None:
        return None
    return {
        "prefix": kever.prefixer.qb64,
        "sn": kever.sn,
        "said": kever.serder.said,
        "ilk": kever.serder.ilk,
        "version": f"{kever.serder.pvrsn.major}.{kever.serder.pvrsn.minor}",
        "keys": [v.qb64 for v in kever.verfers],
        "kt": kever.tholder.sith,
        "n": list(kever.ndigs),
        "nt": kever.ntholder.sith,
        "establishment": {"sn": kever.lastEst.s, "said": kever.lastEst.d},
    }


def genus_of(m):
    return Vrsn_1_0 if m.startswith(b'{"v":"KERI10') else Vrsn_2_0


def process(msgs, version=None):
    """Feed messages to a fresh keripy Kevery.

    `version` is the stream genus the parser starts in. keripy's Parser defaults
    to v2, so a v1 stream with no genus counter is only read correctly when told
    (P1: a stream without a genus counter is v1, never the library default)."""
    db = _OPEN.enter_context(openDB(name=f"fixture{next(_DBS)}", temp=True))
    kvy = Kevery(db=db, lax=False, local=False)
    for m in msgs:
        Parser(version=version or genus_of(m)).parse(ims=bytearray(m), kvy=kvy)
    return db, kvy


def publish(db, pre, genus):
    out = bytearray()
    if genus is not None:
        out.extend(Counter.makeGVC(version=genus))
    for m in db.clonePreIter(pre=pre, gvrsn=genus or Vrsn_1_0):
        out.extend(m)
    return bytes(out)


def scenario(outdir, name, pre, msgs, *, genus, expect, note):
    db, kvy = process(msgs)
    kever = kvy.kevers[pre] if pre in kvy.kevers else None
    published = publish(db, pre, genus) if kever else b"".join(msgs)

    # keripy must accept its own published stream and reach the same state.
    _, kvy2 = process([published], version=genus or Vrsn_1_0)
    replayed = state(kvy2.kevers[pre] if pre in kvy2.kevers else None)
    if replayed != state(kever):
        raise SystemExit(f"{name}: keripy does not re-read its own stream the same way\n direct  {state(kever)}\n replay  {replayed}\n stream  {published[:400]!r}")

    with open(os.path.join(outdir, f"{name}.cesr"), "wb") as f:
        f.write(published)

    if expect != "accept":
        # keripy publishes only what it accepted, so the refused event is not
        # in <name>.cesr. Write what was submitted too, with a genus-version
        # counter wherever the version changes, and check keripy reads that
        # stream to the same result.
        submitted = bytearray()
        current = None
        for m in msgs:
            g = genus_of(m)
            if g != current and not (current is None and g == Vrsn_1_0):
                submitted.extend(Counter.makeGVC(version=g))
            current = g
            submitted.extend(m)
        _, kvy3 = process([bytes(submitted)], version=Vrsn_1_0)
        if state(kvy3.kevers[pre] if pre in kvy3.kevers else None) != state(kever):
            raise SystemExit(f"{name}: keripy reads the submitted stream differently")
        with open(os.path.join(outdir, f"{name}.submitted.cesr"), "wb") as f:
            f.write(bytes(submitted))
    with open(os.path.join(outdir, f"{name}.json"), "w") as f:
        json.dump({"note": note, "expect": expect, "keripy": state(kever)}, f, indent=2)
        f.write("\n")
    print(f"{name:32} {len(published):6} bytes  keripy sn={kever.sn if kever else None}")


def basic(outdir, version, genus, name, kind=Kinds.json):
    KIND = kind
    s = keys(4, "basic")
    icp = incept(code=DigDex.Blake3_256, keys=[s[0].verfer.qb64], ndigs=[ndig(s[1])], pvrsn=version, kind=KIND)
    pre = icp.pre
    ixn1 = interact(pre=pre, dig=icp.said, sn=1, data=[{"d": icp.said}], pvrsn=version, kind=KIND)
    rot = rotate(pre=pre, keys=[s[1].verfer.qb64], dig=ixn1.said, ndigs=[ndig(s[2])], sn=2, pvrsn=version, kind=KIND)
    ixn2 = interact(pre=pre, dig=rot.said, sn=3, data=[], pvrsn=version, kind=KIND)
    msgs = [msg(icp, [(s[0], 0, None)]), msg(ixn1, [(s[0], 0, None)]),
            msg(rot, [(s[1], 0, None)]), msg(ixn2, [(s[1], 0, None)])]
    scenario(outdir, name, pre, msgs, genus=genus, expect="accept",
             note=f"icp, ixn (one digest seal), rot, ixn; single Ed25519 key; KERI {version.major}.{version.minor}, {kind} bodies")


def recovery(outdir):
    """The VTI level-3 shape: n [H(R'), H(K)], nt [["1/2","1"]]."""
    r0, r1, k, r2, k2 = keys(5, "recovery")
    nt = [["1/2", "1"]]
    icp = incept(code=DigDex.Blake3_256, keys=[r0.verfer.qb64], ndigs=[ndig(r1), ndig(k)], nsith=nt, kind=KIND)
    pre = icp.pre
    ixn = interact(pre=pre, dig=icp.said, sn=1, data=[], kind=KIND)
    base = [msg(icp, [(r0, 0, None)]), msg(ixn, [(r0, 0, None)])]

    def rot(signed, name, expect, note):
        ev = rotate(pre=pre, keys=[r1.verfer.qb64, k.verfer.qb64], dig=ixn.said,
                    ndigs=[ndig(r2), ndig(k2)], nsith=nt, sn=2, kind=KIND)
        scenario(outdir, name, pre, base + [msg(ev, signed)], genus=Vrsn_2_0, expect=expect, note=note)

    rot([(k, 1, None)], "v2-recovery-by-k", "accept",
        "rotation signed by the recovery key K alone meets the prior nt")
    rot([(r1, 0, None), (k, 1, None)], "v2-recovery-by-r-and-k", "accept",
        "rotation signed by R' and K")
    rot([(r1, 0, None)], "v2-recovery-routine-alone", "refuse-rotation",
        "rotation signed by R' alone meets kt but not the prior nt: a verifier stops at sn 1")


def weighted(outdir):
    s = keys(6, "weighted")
    icp = incept(code=DigDex.Blake3_256, keys=[x.verfer.qb64 for x in s[:3]], isith="2",
                 ndigs=[ndig(x) for x in s[3:]], nsith="2", kind=KIND)
    pre = icp.pre
    ixn = interact(pre=pre, dig=icp.said, sn=1, data=[], kind=KIND)
    msgs = [msg(icp, [(s[0], 0, None), (s[2], 2, None)]), msg(ixn, [(s[1], 1, None), (s[2], 2, None)])]
    scenario(outdir, "v2-multisig-2of3", pre, msgs, genus=Vrsn_2_0, expect="accept",
             note="kt 2 over three keys; icp signed by keys 0 and 2, ixn by 1 and 2")


def reordered(outdir):
    """A rotation whose new keys are in a different order from the prior
    next-key list, plus a key the prior event did not commit to. keripy signs
    each committed key with `2A` (both lists, its own ondex) and the new key
    current-only (`B`, no ondex). A reader must take the ondex from the code."""
    r, a, b, x, n1, n2, n3 = keys(7, "reordered")
    icp = incept(code=DigDex.Blake3_256, keys=[r.verfer.qb64], ndigs=[ndig(a), ndig(b)], nsith="2", kind=KIND)
    pre = icp.pre
    rot = rotate(pre=pre, keys=[b.verfer.qb64, a.verfer.qb64, x.verfer.qb64], dig=icp.said, isith="2",
                 ndigs=[ndig(n1), ndig(n2), ndig(n3)], nsith="2", sn=1, kind=KIND)
    sigers = [b.sign(rot.raw, index=0, ondex=1), a.sign(rot.raw, index=1, ondex=0),
              x.sign(rot.raw, index=2, only=True)]
    codes = [(z.code, z.index, z.ondex) for z in sigers]
    if codes != [("2A", 0, 1), ("2A", 1, 0), ("B", 2, None)]:
        raise SystemExit(f"v2-reordered-rotation: keripy chose {codes}")
    msgs = [msg(icp, [(r, 0, None)]), bytes(messagize(rot, sigers=sigers, gvrsn=rot.pvrsn))]
    scenario(outdir, "v2-reordered-rotation", pre, msgs, genus=Vrsn_2_0, expect="accept",
             note="rotation to [B, A, X] after n [H(A), H(B)]: A and B sign 2A with their prior positions as ondex, X current-only (B)")


def superseding(outdir):
    """KERI recovery: a rotation supersedes interaction events after the last
    establishment event (keripy superseding rules A0-A2). The routine key R0
    signs ixn 1 and ixn 2; the recovery key K then signs a rotation at sn 2
    whose prior is ixn 1. keripy accepts it, and ixn 2 is superseded."""
    r0, r1, k, r2, k2 = keys(5, "superseding")
    nt = [["1/2", "1"]]
    icp = incept(code=DigDex.Blake3_256, keys=[r0.verfer.qb64], ndigs=[ndig(r1), ndig(k)], nsith=nt, kind=KIND)
    pre = icp.pre
    ixn1 = interact(pre=pre, dig=icp.said, sn=1, data=[], kind=KIND)
    seal = {"i": pre, "s": "0", "d": icp.said}
    ixn2 = interact(pre=pre, dig=ixn1.said, sn=2, data=[seal], kind=KIND)
    rot = rotate(pre=pre, keys=[r1.verfer.qb64, k.verfer.qb64], dig=ixn1.said,
                 ndigs=[ndig(r2), ndig(k2)], nsith=nt, sn=2, kind=KIND)
    msgs = [msg(icp, [(r0, 0, None)]), msg(ixn1, [(r0, 0, None)]), msg(ixn2, [(r0, 0, None)]),
            msg(rot, [(k, 1, None)])]
    scenario(outdir, "v2-superseding-recovery", pre, msgs, genus=Vrsn_2_0, expect="accept",
             note="icp, ixn 1, ixn 2 (anchoring a seal), then K's rotation at sn 2 after ixn 1: the rotation supersedes ixn 2 and its seal")

    # A1: a rotation never supersedes a rotation.
    rot1 = rotate(pre=pre, keys=[r1.verfer.qb64, k.verfer.qb64], dig=icp.said,
                  ndigs=[ndig(r2), ndig(k2)], nsith=nt, sn=1, kind=KIND)
    rot1b = rotate(pre=pre, keys=[r1.verfer.qb64, k.verfer.qb64], dig=icp.said,
                   ndigs=[ndig(k2), ndig(r2)], nsith=nt, sn=1, kind=KIND)
    msgs = [msg(icp, [(r0, 0, None)]), msg(rot1, [(k, 1, None)]), msg(rot1b, [(k, 1, None)])]
    scenario(outdir, "v2-rotation-cannot-supersede-rotation", pre, msgs, genus=Vrsn_2_0,
             expect="refuse-event-2", note="two rotations at sn 1: the second supersedes nothing (rule A1)")

    # A stale recovery: a rotation at or before the last establishment event.
    ixn_a = interact(pre=pre, dig=rot1.said, sn=2, data=[], kind=KIND)
    rot_stale = rotate(pre=pre, keys=[r2.verfer.qb64, k2.verfer.qb64], dig=icp.said,
                       ndigs=[ndig(r0), ndig(k)], nsith=nt, sn=1, kind=KIND)
    msgs = [msg(icp, [(r0, 0, None)]), msg(rot1, [(k, 1, None)]), msg(ixn_a, [(r1, 0, None)]),
            msg(rot_stale, [(k2, 1, None)])]
    scenario(outdir, "v2-stale-recovery", pre, msgs, genus=Vrsn_2_0, expect="refuse-event-3",
             note="a rotation at sn 1, before the last establishment event: stale, not a recovery")


def migrated(outdir):
    s = keys(4, "migrated")
    icp = incept(code=DigDex.Blake3_256, keys=[s[0].verfer.qb64], ndigs=[ndig(s[1])], pvrsn=Vrsn_1_0, kind=KIND)
    pre = icp.pre
    ixn1 = interact(pre=pre, dig=icp.said, sn=1, data=[], pvrsn=Vrsn_1_0, kind=KIND)
    rot = rotate(pre=pre, keys=[s[1].verfer.qb64], dig=ixn1.said, ndigs=[ndig(s[2])], sn=2, pvrsn=Vrsn_2_0, kind=KIND)
    ixn2 = interact(pre=pre, dig=rot.said, sn=3, data=[], pvrsn=Vrsn_2_0, kind=KIND)
    msgs = [msg(icp, [(s[0], 0, None)]), msg(ixn1, [(s[0], 0, None)]),
            msg(rot, [(s[1], 0, None)]), msg(ixn2, [(s[1], 0, None)])]
    scenario(outdir, "migrated-v1-to-v2", pre, msgs, genus=Vrsn_2_0, expect="accept",
             note="v1 icp and ixn, then v2 rot and ixn: a KEL may move up a version (P2)")


def downgrade(outdir):
    s = keys(3, "downgrade")
    icp = incept(code=DigDex.Blake3_256, keys=[s[0].verfer.qb64], ndigs=[ndig(s[1])], pvrsn=Vrsn_2_0, kind=KIND)
    pre = icp.pre
    ixn = interact(pre=pre, dig=icp.said, sn=1, data=[], pvrsn=Vrsn_1_0, kind=KIND)
    msgs = [msg(icp, [(s[0], 0, None)]), msg(ixn, [(s[0], 0, None)])]
    scenario(outdir, "downgrade-v2-to-v1", pre, msgs, genus=Vrsn_2_0, expect="refuse-event-1",
             note="v2 icp then a v1 ixn: P2 refuses a version decrease; keripy's own result is recorded")


def endorsed(outdir):
    """Replies endorsed by a transferable AID after a rotation: a transferable
    indexed signature group (`-X`) naming the establishment event at sn 1, its
    sequence number a 2.x `Number`. keripy must accept both replies."""
    s = keys(3, "endorsed")
    icp = incept(code=DigDex.Blake3_256, keys=[s[0].verfer.qb64], ndigs=[ndig(s[1])], pvrsn=Vrsn_2_0, kind=KIND)
    pre = icp.pre
    rot = rotate(pre=pre, keys=[s[1].verfer.qb64], dig=icp.said, ndigs=[ndig(s[2])], sn=1, pvrsn=Vrsn_2_0, kind=KIND)
    msgs = [msg(icp, [(s[0], 0, None)]), msg(rot, [(s[1], 0, None)])]
    db, kvy = process(msgs)
    kel = publish(db, pre, Vrsn_2_0)

    stamp = "2026-01-01T00:00:00.000000+00:00"
    replies = [
        reply(pre=pre, route="/end/role/add", data=dict(cid=pre, role="controller", eid=pre),
              stamp=stamp, pvrsn=Vrsn_2_0, kind=KIND),
        reply(pre=pre, route="/loc/scheme", data=dict(eid=pre, scheme="https", url="https://example.com/"),
              stamp=stamp, pvrsn=Vrsn_2_0, kind=KIND),
    ]
    out = bytearray(kel)
    for r in replies:
        tsg = (Prefixer(qb64=pre), Number(num=1), Diger(qb64=rot.said), [s[1].sign(r.raw, index=0)])
        out.extend(messagize(r, tsgs=[tsg], gvrsn=Vrsn_2_0))
    published = bytes(out)

    db2 = _OPEN.enter_context(openDB(name=f"fixture{next(_DBS)}", temp=True))
    rvy = routing.Revery(db=db2)
    kvy2 = Kevery(db=db2, lax=False, local=False, rvy=rvy)
    kvy2.registerReplyRoutes(router=rvy.rtr)
    Parser(version=Vrsn_2_0).parse(ims=bytearray(published), kvy=kvy2, rvy=rvy)
    ends = [list(k) for k, v in db2.ends.getTopItemIter() if v.allowed]
    locs = [[k[0], k[1], v.url] for k, v in db2.locs.getTopItemIter()]
    if ends != [[pre, "controller", pre]] or locs != [[pre, "https", "https://example.com/"]]:
        raise SystemExit(f"v2-endorsed-replies: keripy did not accept its replies: {ends} {locs}")

    with open(os.path.join(outdir, "v2-endorsed-replies.cesr"), "wb") as f:
        f.write(published)
    with open(os.path.join(outdir, "v2-endorsed-replies.json"), "w") as f:
        json.dump({"note": "two rpy messages endorsed under the key state of the rotation at sn 1",
                   "expect": "accept", "keripy": state(kvy2.kevers[pre]),
                   "ends": ends, "locs": locs}, f, indent=2)
        f.write("\n")
    print(f"{'v2-endorsed-replies':32} {len(published):6} bytes  keripy accepted {len(ends)} end, {len(locs)} loc")


def main(outdir):
    commit = subprocess.run(["git", "-C", os.path.dirname(keri.__file__), "rev-parse", "--short", "HEAD"],
                            capture_output=True, text=True).stdout.strip()
    basic(outdir, Vrsn_1_0, None, "v1-basic")
    basic(outdir, Vrsn_2_0, Vrsn_2_0, "v2-basic")
    basic(outdir, Vrsn_2_0, Vrsn_2_0, "v2-basic-native", kind=Kinds.cesr)
    recovery(outdir)
    weighted(outdir)
    reordered(outdir)
    superseding(outdir)
    migrated(outdir)
    downgrade(outdir)
    endorsed(outdir)
    with open(os.path.join(outdir, "KERIPY_VERSION"), "w") as f:
        f.write(f"keripy {keri.__version__} {commit}\n")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else ".")
