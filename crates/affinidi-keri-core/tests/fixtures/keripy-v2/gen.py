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
from keri.core import Counter, DigDex, Diger, Kevery, Number, Parser, Prefixer, Salter, SealSource, delcept, deltate, incept, interact, messagize, reply, rotate
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


def native(outdir):
    """KERI 2.0 native CESR bodies (P8), keripy's default kind. The recovery
    custodian's shape with every native field type a KEL uses: a weighted
    threshold (written as one clause, read back flat), a configuration trait,
    and an interaction event carrying one seal of each type keripy writes, in
    groups of one type each."""
    K = Kinds.cesr
    r0, r1, k, r2, k2 = keys(5, "native")
    nt = [["1/2", "1"]]
    icp = incept(code=DigDex.Blake3_256, keys=[r0.verfer.qb64], ndigs=[ndig(r1), ndig(k)],
                 nsith=nt, cnfg=["DND"], kind=K)
    pre = icp.pre
    seals = [
        {"i": pre, "s": "0", "d": icp.said},
        {"d": icp.said},
        {"d": ndig(r2)},
        {"s": "0", "d": icp.said},
        {"i": pre},
        {"bi": pre, "d": icp.said},
        {"rd": ndig(k2)},
    ]
    ixn = interact(pre=pre, dig=icp.said, sn=1, data=seals, kind=K)
    if [dict(x) for x in ixn.sad["a"]] != seals:
        raise SystemExit(f"v2-native-recovery: keripy did not keep the seals: {ixn.sad['a']}")
    rot = rotate(pre=pre, keys=[r1.verfer.qb64, k.verfer.qb64], isith=["1/2", "1"], dig=ixn.said,
                 ndigs=[ndig(r2), ndig(k2)], nsith=nt, sn=2, kind=K)
    msgs = [msg(icp, [(r0, 0, None)]), msg(ixn, [(r0, 0, None)]), msg(rot, [(k, 1, None)])]
    scenario(outdir, "v2-native-recovery", pre, msgs, genus=Vrsn_2_0, expect="accept",
             note="native bodies: icp (nt [[1/2, 1]], c [DND]), ixn with seven seals of six "
                  "types, rot by the recovery key K under kt [1/2, 1]")


def native_delegated(outdir):
    """A delegator and a delegate, every body native: the delegator's ixn
    events anchor the delegate's dip and drt, which carry seal source couples
    naming them (`-S`, a 2.x `Number` and a SAID)."""
    K = Kinds.cesr
    dr = keys(3, "delegator")
    de = keys(3, "delegate")
    icp = incept(code=DigDex.Blake3_256, keys=[dr[0].verfer.qb64], ndigs=[ndig(dr[1])], kind=K)
    delegator = icp.pre
    dip = delcept(keys=[de[0].verfer.qb64], delpre=delegator, ndigs=[ndig(de[1])], kind=K)
    ixn1 = interact(pre=delegator, dig=icp.said, sn=1,
                    data=[{"i": dip.pre, "s": "0", "d": dip.said}], kind=K)
    drt = deltate(pre=dip.pre, keys=[de[1].verfer.qb64], dig=dip.said, ndigs=[ndig(de[2])], sn=1, kind=K)
    ixn2 = interact(pre=delegator, dig=ixn1.said, sn=2,
                    data=[{"i": dip.pre, "s": "1", "d": drt.said}], kind=K)

    def signed(serder, signer, source=None):
        sigers = [signer.sign(serder.raw, index=0)]
        bonds = [source] if source else None
        return bytes(messagize(serder, sigers=sigers, bonds=bonds, gvrsn=Vrsn_2_0))

    msgs = [signed(icp, dr[0]), signed(ixn1, dr[0]), signed(ixn2, dr[0]),
            signed(dip, de[0], SealSource(s=1, d=ixn1.said)),
            signed(drt, de[1], SealSource(s=2, d=ixn2.said))]
    db, kvy = process(msgs)
    if dip.pre not in kvy.kevers or kvy.kevers[dip.pre].sn != 1:
        raise SystemExit("v2-native-delegated: keripy did not accept the delegation")
    published = bytearray(Counter.makeGVC(version=Vrsn_2_0))
    for p in (delegator, dip.pre):
        for m in db.clonePreIter(pre=p, gvrsn=Vrsn_2_0):
            published.extend(m)
    published = bytes(published)
    _, kvy2 = process([published], version=Vrsn_2_0)
    for p in (delegator, dip.pre):
        if state(kvy2.kevers.get(p)) != state(kvy.kevers[p]):
            raise SystemExit("v2-native-delegated: keripy re-reads its stream differently")
    with open(os.path.join(outdir, "v2-native-delegated.cesr"), "wb") as f:
        f.write(published)
    with open(os.path.join(outdir, "v2-native-delegated.json"), "w") as f:
        json.dump({"note": "native delegator KEL (icp, ixn, ixn) then the delegate's dip and drt, "
                           "each with a seal source couple naming the anchoring ixn",
                   "expect": "accept", "delegator": state(kvy.kevers[delegator]),
                   "keripy": state(kvy.kevers[dip.pre])}, f, indent=2)
        f.write("\n")
    print(f"{'v2-native-delegated':32} {len(published):6} bytes  keripy sn={kvy.kevers[dip.pre].sn}")


def traits(outdir):
    """Configuration traits. `EO`, `DND` and `DID` are inception-only (KERI
    spec, Configuration traits field): `EO` drops any interaction event, and
    a delegated event is dropped when its delegator's KEL has `DND`. keripy
    applies traits at inception and ignores them in a rotation's `c`."""
    s = keys(4, "traits")
    icp = incept(code=DigDex.Blake3_256, keys=[s[0].verfer.qb64], ndigs=[ndig(s[1])], cnfg=["EO"], kind=KIND)
    pre = icp.pre
    ixn = interact(pre=pre, dig=icp.said, sn=1, data=[], kind=KIND)
    scenario(outdir, "v2-eo-interaction", pre, [msg(icp, [(s[0], 0, None)]), msg(ixn, [(s[0], 0, None)])],
             genus=Vrsn_2_0, expect="refuse-event-1", note="EO at inception: an interaction event is dropped")
    rot = rotate(pre=pre, keys=[s[1].verfer.qb64], dig=icp.said, ndigs=[ndig(s[2])], sn=1, kind=KIND)
    scenario(outdir, "v2-eo-rotation", pre, [msg(icp, [(s[0], 0, None)]), msg(rot, [(s[1], 0, None)])],
             genus=Vrsn_2_0, expect="accept", note="EO at inception: a rotation is accepted")

    t = keys(4, "traits-late")
    icp = incept(code=DigDex.Blake3_256, keys=[t[0].verfer.qb64], ndigs=[ndig(t[1])], kind=KIND)
    pre = icp.pre
    rot = rotate(pre=pre, keys=[t[1].verfer.qb64], dig=icp.said, ndigs=[ndig(t[2])], sn=1,
                 cnfg=["EO", "DND"], kind=KIND)
    ixn = interact(pre=pre, dig=rot.said, sn=2, data=[], kind=KIND)
    scenario(outdir, "v2-eo-in-rotation", pre,
             [msg(icp, [(t[0], 0, None)]), msg(rot, [(t[1], 0, None)]), msg(ixn, [(t[1], 0, None)])],
             genus=Vrsn_2_0, expect="accept",
             note="EO and DND in a rotation's c: inception-only traits, which keripy ignores there; the ixn is accepted")

    dr = keys(2, "dnd-delegator")
    de = keys(2, "dnd-delegate")
    icp = incept(code=DigDex.Blake3_256, keys=[dr[0].verfer.qb64], ndigs=[ndig(dr[1])], cnfg=["DND"], kind=KIND)
    delegator = icp.pre
    dip = delcept(keys=[de[0].verfer.qb64], delpre=delegator, ndigs=[ndig(de[1])], kind=KIND)
    ixn = interact(pre=delegator, dig=icp.said, sn=1, data=[{"i": dip.pre, "s": "0", "d": dip.said}], kind=KIND)

    def signed(serder, signer, source=None):
        sigers = [signer.sign(serder.raw, index=0)]
        return bytes(messagize(serder, sigers=sigers, bonds=[source] if source else None, gvrsn=Vrsn_2_0))

    msgs = [signed(icp, dr[0]), signed(ixn, dr[0]), signed(dip, de[0], SealSource(s=1, d=ixn.said))]
    db, kvy = process(msgs)
    if delegator not in kvy.kevers or kvy.kevers[delegator].sn != 1:
        raise SystemExit("v2-dnd-delegator: keripy did not accept the delegator's KEL")
    if dip.pre in kvy.kevers:
        raise SystemExit("v2-dnd-delegator: keripy accepted a dip under a DND delegator")
    submitted = bytearray(Counter.makeGVC(version=Vrsn_2_0))
    for m in msgs:
        submitted.extend(m)
    with open(os.path.join(outdir, "v2-dnd-delegator.cesr"), "wb") as f:
        f.write(bytes(submitted))
    with open(os.path.join(outdir, "v2-dnd-delegator.json"), "w") as f:
        json.dump({"note": "a delegator with DND at inception anchors a dip: keripy drops the dip",
                   "expect": "refuse-dip", "delegator": state(kvy.kevers[delegator]),
                   "keripy": None}, f, indent=2)
        f.write("\n")
    print(f"{'v2-dnd-delegator':32} {len(submitted):6} bytes  keripy dip refused")


def native_messages(outdir):
    """One native message of every type keripy reads natively, each with the
    SAD keripy reads from it. A reader must read the same SAD, and verify the
    same SAID. The field values exercise every primitive a native body uses:
    field maps with every value kind (keripy `Mapper`), paths, date-times,
    nonces, a nested weighted threshold, and text that is itself a primitive
    (written escaped)."""
    from keri.core.serdering import SerderKERI, SerderACDC
    from keri.acdc import acdcmap, blindate, regcept, update as regupdate
    from keri.core import Noncer, Verser
    K = Kinds.cesr
    s = keys(4, "messages")
    pre = incept(code=DigDex.Blake3_256, keys=[s[0].verfer.qb64], ndigs=[ndig(s[1])], kind=K).pre
    said = ndig(s[2])
    stamp = "2026-01-01T00:00:00.000000+00:00"
    attributes = {
        "yes": True, "no": False, "none": None, "n": 3, "neg": -5, "x": 1.5,
        "empty": "", "said": said, "short": "abc", "long": "abcdefghijklmnopq",
        "leadingA": "AAAAAAAAAAAAA", "tagLike": "Xicp", "url": "https://example.com/a?b=c",
        "list": [1, "two", {"m": "Xicp"}, [], {}],
        "nested": {"d": "", "deeper": {"k": "v"}},
    }
    out = []

    def add(name, serder):
        out.append({"name": name, "raw": serder.raw.decode(), "sad": serder.sad,
                    "said": serder.said})

    def keri(ilk, **fields):
        return SerderKERI(sad=dict(t=ilk, **fields), makify=True, kind=K, ilk=ilk, pvrsn=Vrsn_2_0, gvrsn=Vrsn_2_0)

    add("icp-nested-weights", keri("icp", i=pre, s="0",
        kt=[[{"1/2": ["1/2", "1/2"]}, "1/2"], ["1"]],
        k=[x.verfer.qb64 for x in s[:3]], nt="2", n=[ndig(x) for x in s[:3]],
        bt="0", b=[], c=["EO", "DND", "RB", "NB", "NRB", "DID"], a=[]))
    add("rct", keri("rct", d=said, i=pre, s="a"))
    add("rpy-end-role", reply(pre=pre, route="/end/role/add",
        data=dict(cid=pre, role="controller", eid=pre), stamp=stamp, pvrsn=Vrsn_2_0, kind=K))
    add("rpy-loc-scheme", reply(pre=pre, route="/loc/scheme",
        data=dict(eid=pre, scheme="https", url="https://example.com/"), stamp=stamp, pvrsn=Vrsn_2_0, kind=K))
    add("rpy-every-value", reply(pre=pre, route="/a/b_c/Abc", data=attributes, stamp=stamp,
        pvrsn=Vrsn_2_0, kind=K))
    add("qry", keri("qry", i=pre, dt=stamp, r="ksn", rr="/reply/to", q=dict(i=pre, s="0", src=pre)))
    add("pro", keri("pro", i=pre, dt=stamp, r="/a", rr="", q={}))
    add("bar", keri("bar", i=pre, dt=stamp, r="/b", a=attributes))
    add("xip", keri("xip", u=Noncer(raw=b"0123456789abcdef").qb64, i=pre, ri=pre, dt=stamp,
        r="/exn/start", q={}, a={"m": "hello"}))
    add("exn", keri("exn", i=pre, ri=pre, x=said, p=said, dt=stamp, r="/exn/next", q={}, a={"m": "hi"}))
    rip = regcept(israid=pre, uuid=Salter(raw=b"registry-uuid-01").qb64, stamp=stamp, kind=K)
    add("rip", rip)
    add("bup", blindate(regid=rip.said, prior=rip.said, blid=said, sn=1, stamp=stamp, kind=K))
    add("upd", regupdate(regid=rip.said, prior=rip.said, acdc=said, state="issued", sn=1, stamp=stamp, kind=K))
    add("acm", acdcmap(israid=pre, regid=rip.said, schema=said, attribute=attributes, kind=K))
    add("acm-bare", acdcmap(israid=pre, ilk=None, schema=said, attribute={"d": "", "a": "b"}, kind=K))

    with open(os.path.join(outdir, "v2-native-messages.json"), "w") as f:
        json.dump({"note": "one native body per message type, with the SAD keripy reads from it",
                   "messages": out}, f, indent=2)
        f.write("\n")
    print(f"{'v2-native-messages':32} {len(out):6} messages")


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
    native(outdir)
    native_delegated(outdir)
    native_messages(outdir)
    traits(outdir)
    with open(os.path.join(outdir, "KERIPY_VERSION"), "w") as f:
        f.write(f"keripy {keri.__version__} {commit}\n")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else ".")
