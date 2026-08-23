# Test fixtures

`did-webs-ENro7uf0.keri.cesr` is the `keri.cesr` artifact published for the
`did:webs` identifier

    did:webs:did-webs-service%3a7676:ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe

reproduced verbatim from the Apache-2.0 licensed
[hyperledger-labs/did-webs-resolver](https://github.com/hyperledger-labs/did-webs-resolver)
reference implementation, at
`volume/dkr/examples/ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe/keri.cesr`.

It is used unmodified, as a conformance vector: it is a stream produced by
keripy rather than by this library, so it is the only test here that can catch
us encoding or decoding CESR in a way that only we understand.
