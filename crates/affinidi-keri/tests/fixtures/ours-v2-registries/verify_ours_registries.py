"""Check that keripy accepts the v2 registries and designations we write.

Each `<name>.cesr` here was written by this library: the issuer's KEL by
`affinidi_keri::controller`, its registries and designations by
`affinidi_keri_core::registry::write`
(`cargo run -p affinidi-keri --example emit_registry_conformance`). For each
scenario this checks, with keripy:

1. keripy reads the KEL from the stream, as a `did:webs` resolver built on
   keripy would, starting in genus 1 (a stream with no genus counter is v1),
   and reaches the KEL state in `<name>.json`;
2. every registry message is what keripy's own `messagize` makes of it: the
   `rip` with its seal source couple, each `bup` with its seal source couple
   and its disclosed state, found byte for byte in the stream;
3. keripy's `SerderACDC` verifies every SAID (the credential's over its
   compact form), keripy's `Blinder` reproduces every BLID, and keripy's
   registry verifier (`keri.acdc.regeventing.vetBinds`), given the KEL keripy
   read, reaches each credential's expected status.

keripy's parser does not route ACDC registry messages from a stream (it
refuses an ACDC message with an ilk), so (3) builds keripy's objects from the
message bodies the `.json` records, and (2) ties those bodies to the stream.

    DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib python -I verify_ours_registries.py .

Exits non-zero if any scenario disagrees.
"""

import contextlib
import itertools
import json
import os
import sys

import keri
from keri import Vrsn_1_0
from keri.acdc.regeventing import vetBinds
from keri.core import Blinder, BlindState, Kevery, Parser, SealSource, SerderACDC, messagize
from keri.db import openDB
from keri.help import helping

helping.nowUTC = lambda: helping.fromIso8601("2026-01-01T00:00:00.000000+00:00")
_DBS = itertools.count()
_OPEN = contextlib.ExitStack()


def read_kel(stream):
    db = _OPEN.enter_context(openDB(name=f"ours-reg{next(_DBS)}", temp=True))
    kvy = Kevery(db=db, lax=False, local=False)
    Parser(version=Vrsn_1_0).parse(ims=bytearray(stream), kvy=kvy)
    return db, kvy


def check(name, stream, spec):
    problems = []
    db, kvy = read_kel(stream)
    pre = spec["kel"]["prefix"]
    kever = kvy.kevers[pre] if pre in kvy.kevers else None
    if kever is None or kever.sn != spec["kel"]["sn"] or kever.serder.said != spec["kel"]["said"]:
        got = None if kever is None else (kever.sn, kever.serder.said)
        problems.append(f"KEL: keripy reached {got}, ours {spec['kel']['sn']}, {spec['kel']['said']}")
        return problems

    for c in spec["credentials"]:
        rip = SerderACDC(raw=c["rip"]["raw"].encode(), verify=True)
        acdc = SerderACDC(raw=c["acm"]["raw"].encode(), verify=True)
        if rip.said != c["registry"]:
            problems.append(f"rip SAID {rip.said} != {c['registry']}")
        if acdc.said != c["credential"]:
            problems.append(f"acm SAID {acdc.said} != {c['credential']}")

        framed = messagize(rip, bonds=[SealSource(s=c["rip"]["anchor"]["sn"], d=c["rip"]["anchor"]["said"])])
        if bytes(framed) not in stream:
            problems.append("the rip as keripy frames it is not in the stream")
        if acdc.raw not in stream:
            problems.append("the acm body is not in the stream")

        bups, blinders = [], []
        for u in c["updates"]:
            bup = SerderACDC(raw=u["raw"].encode(), verify=True)
            d = u["disclosure"]
            bl = Blinder(crew=BlindState(d="", u=d["uuid"], td=d["acdc"], ts=d["state"]), makify=True)
            if bl.said != d["blid"]:
                problems.append(f"BLID: keripy computes {bl.said}, ours {d['blid']}")
            if bup.sad["b"] != bl.said:
                problems.append(f"bup {bup.said} names BLID {bup.sad['b']}, keripy's is {bl.said}")
            framed = messagize(bup, bonds=[SealSource(s=u["anchor"]["sn"], d=u["anchor"]["said"]), bl.data])
            if bytes(framed) not in stream:
                problems.append(f"bup {bup.said} as keripy frames it is not in the stream")
            bups.append(bup)
            blinders.append(bl)

        try:
            rec = vetBinds(rip=rip, updates=bups, db=db, blinders=blinders, target=acdc.said,
                           controller=pre, acdc=acdc)
            status = rec.state
        except Exception as ex:
            status = f"error:{type(ex).__name__}: {ex}"
        if status != c["expect"]:
            problems.append(f"{c['schema']}: keripy's vetBinds says {status}, ours {c['expect']}")
    return problems


def main(d):
    print(f"keripy {keri.__version__}")
    names = sorted(f[:-5] for f in os.listdir(d) if f.endswith(".cesr"))
    failed = 0
    for name in names:
        with open(os.path.join(d, f"{name}.cesr"), "rb") as f:
            stream = f.read()
        with open(os.path.join(d, f"{name}.json")) as f:
            spec = json.load(f)
        problems = check(name, stream, spec)
        statuses = ", ".join(c["expect"] for c in spec["credentials"])
        if problems:
            failed += 1
            print(f"FAIL {name:32} {statuses}")
            for p in problems:
                print(f"       {p}")
        else:
            print(f"ok   {name:32} {statuses:18} keripy kel sn={spec['kel']['sn']}")
    print(f"{len(names) - failed}/{len(names)} agree")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    with _OPEN:
        main(sys.argv[1] if len(sys.argv) > 1 else ".")
