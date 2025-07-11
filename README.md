# HyperEVM sync

Proof of concept to execute all transactions from genesis for the entire HyperEVM. This should be enough to implement an archive node.

To replay, one can first sync all the historical blocks from s3, for example using

`aws s3 sync --request-payer <REQUESTER> s3://hl-mainnet-evm-blocks ~/hl-mainnet-evm-blocks`

One can also download specific blocks via the following command:

`cargo run --release download-blocks -d tmp/hl-mainnet-evm-blocks -s <STARTBLOCK> -e <ENDBLOCK>`

To run from genesis, one can use the following `sync-from-state` command:

`cargo run --release sync-from-state -b tmp/hl-mainnet-evm-blocks -e <ENDBLOCK>`

To run from a specific `EvmState` or `AbciState` (use `--is-abci` flag), use the following:

`cargo run --release sync-from-state -b tmp/hl-mainnet-evm-blocks -e <ENDBLOCK> -f <STATEFLN>`

To take snapshots as the command goes, add the `-s <SNAPSHOTDIR>` and `-c <CHUNKSIZE>` arguments. The former specifies which directory the snapshots go into and the latter specifies how often a snapshot is taken. The default chunk size is 1000.