"""Check that keripy accepts the key event logs our controller writes.

Each `<name>.cesr` here was written by `affinidi_keri::controller`
(`cargo run -p affinidi-keri --example emit_conformance`). This feeds each one
to a fresh keripy `Kevery`, as a `did:webs` resolver built on keripy would read
it, and checks keripy reaches exactly the state in `<name>.json` (`ours`).

    DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib python -I verify_ours.py .

Exits non-zero if any scenario disagrees.
"""

import contextlib
import itertools
import json
import os
import sys

import keri
from keri import Vrsn_1_0, Vrsn_2_0
from keri.core import Kevery, Parser
from keri.db import openDB
from keri.help import helping

helping.nowUTC = lambda: helping.fromIso8601("2026-01-01T00:00:00.000000+00:00")
_DBS = itertools.count()
_OPEN = contextlib.ExitStack()


def norm(sith):
    """keripy reports a single-clause weighted threshold flat."""
    if isinstance(sith, list) and len(sith) == 1 and isinstance(sith[0], list):
        return sith[0]
    return sith


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
        "kt": norm(kever.tholder.sith),
        "n": list(kever.ndigs),
        "nt": norm(kever.ntholder.sith),
        "establishment": {"sn": kever.lastEst.s, "said": kever.lastEst.d},
    }


def keripy_reads(stream, prefix):
    # P1: a stream that does not open with a genus-version counter is v1.
    genus = Vrsn_2_0 if stream.startswith(b"-_AAA") else Vrsn_1_0
    db = _OPEN.enter_context(openDB(name=f"ours{next(_DBS)}", temp=True))
    kvy = Kevery(db=db, lax=False, local=False)
    Parser(version=genus).parse(ims=bytearray(stream), kvy=kvy)
    return state(kvy.kevers[prefix]) if prefix in kvy.kevers else None


def main(directory):
    print(f"keripy {keri.__version__}")
    failures = 0
    names = sorted(f[:-5] for f in os.listdir(directory) if f.endswith(".cesr"))
    for name in names:
        with open(os.path.join(directory, f"{name}.cesr"), "rb") as f:
            stream = f.read()
        with open(os.path.join(directory, f"{name}.json")) as f:
            fixture = json.load(f)
        ours = fixture["ours"]
        got = keripy_reads(stream, ours["prefix"])
        ok = got == ours
        failures += not ok
        sn = got["sn"] if got else None
        print(f"{'ok  ' if ok else 'FAIL'} {name:32} {fixture['expect']:16} keripy sn={sn}")
        if not ok:
            print(f"     ours   {ours}\n     keripy {got}")
    print(f"{len(names) - failures}/{len(names)} agree")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else ".")
