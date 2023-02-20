# DeFiTainter

## Description

A static analysis tool for detecting price manipulation vulnerabilities in DeFi protocols based on a inter-contract taint analysis framework.

## How to use

First follow the instructions in [gigahorse-toolchain](gigahorse-toolchain/README.md) for instructions on installation of Gigahorse.

Then, run DeFiTainter with the following incantation:

```shell
    $ python3 defi_tainter.py -bp <chain ID> -la <address1> -sa <address2> -fs <function signature> -bn <block number>
```
- Where `<chain ID>` is the blockchain platform where the test contracts is deployed. The blockchain platforms supported by DeFiTainter include ETH, BSC, Avalanche, Polygon, Solana, Fantom, Gnosis.
- Where `<address1>` is the address of the contract that stores the business logic of the detected DeFi protocol. 
- Where `<address2>` is the address of the contract that stores the business data of the detected DeFi protocol. 
- Where `<function signature>` is the signature of the function to instrument.
- Where `<block number>` is the block number of the blockchain for setting the context of the test environment.

The test cases in the paper can be found in the `./dataset` folder. Within 2 minutes, the result will be output to the screen. It may take a long time to use it for the first time due to compilation.


## Datasets

The `./dataset` folder contains the following datasets:

- `incident.csv`: 23 DeFi protocols exploited in real-world price manipulation attacks.
- `high_value.csv`: 1195 high-value DeFi protocols.






