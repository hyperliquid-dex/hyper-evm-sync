# HyperEVM sync

Proof of concept to execute all transactions from genesis for the entire HyperEVM. This should be enough to implement an archive node.

To replay, one can first sync all the historical blocks from s3, for example using

`aws s3 sync --request-payer <REQUESTER> s3://hl-mainnet-evm-blocks ~/hl-mainnet-evm-blocks`

and then unlz4 all the `.rmp` files, for example by running `unlz4 -m --rm *.lz4` in all subdirectories, and then run

`cargo run --release ~/hl-mainnet-evm-blocks`
