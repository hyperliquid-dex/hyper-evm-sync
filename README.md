# HyperEVM sync

Proof of concept to execute all transactions from genesis for the entire HyperEVM. This should be enough to implement an archive node.

To replay, one can first sync all the historical blocks from s3, for example using

`aws s3 sync --request-payer <REQUESTER> s3://hl-mainnet-evm-blocks ~/hl-mainnet-evm-blocks`

`cargo run --release ~/hl-mainnet-evm-blocks <ENDBLOCK>`
