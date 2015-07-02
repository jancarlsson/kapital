kapital: zero knowledge exchange of value
================================================================================

--------------------------------------------------------------------------------
Introduction
--------------------------------------------------------------------------------

This project started with the [Zerocash] decentralized anonymous payments
scheme, i.e. a zero knowledge pour transaction which spends two old coins and
creates two new coins.

At present, this project contains:

- a C++ template library
- a generalized implementation of the Zerocash pour transaction
- pour one or two old coins to any number of new coins
- refundable contingent payments locked by SHA-256

At present, this project is not a crypto-currency and lacks:

- a minting solution for economic scarcity
- a ledger solution for market history
- a solution for decentralized ("trustless") key generation

Some observations:

1. **Zero knowledge is expensive.**
The practical challenges are not to be underestimated. Privacy is a significant
cost for all participants.

2. **Zero knowledge is a sunk cost.**
Complexity overheads of space, time, and trust are so large that smart
contracts and payments have comparable cost.

My speculation:

The economics of financial privacy may imply a qualitative difference from
conventional crypto-currencies based on public ledgers which are, in some
sense, perfect information. Zero knowledge is the absence of information.

Most capital is not money. Contracts are the dominant value form of capital.
As in the real world, that may be true for zero knowledge financial systems.

--------------------------------------------------------------------------------
[TOC]

<!---
  NOTE: the file you are reading is in Markdown format, which is is fairly readable
  directly, but can be converted into an HTML file with much nicer formatting.
  To do so, run "make doc" (this requires the python-markdown package) and view
  the resulting file README.html.
-->

--------------------------------------------------------------------------------
Comparison with Zerocash
--------------------------------------------------------------------------------

Good:

* zero knowledge coin value arithmetic does not overflow
* coin commitment may be smart contract
* encapsulated pour transaction

Bad:

* bigger and slower than official Zerocash implementation
* elliptic curve point compression not implemented
* uses malleable standard ECDSA signature

--------------------------------------------------------------------------------
Build instructions
--------------------------------------------------------------------------------

The following libraries are required.

- [GNU Multiple Precision Arithmetic Library]
- [Crypto++]
- [GitHub snarklib project]
- [GitHub cryptl project]
- [GitHub snarkfront project]

To build the test application:

    $ make smoketest PREFIX=/usr/local

When building, the $(PREFIX)/include and $(PREFIX)/lib directories are added
to the compiler header file and library paths.

Running is simple:

    $ ./smoketest 
    Usage: ./smoketest -p <pairing> -d <number>
    Options:
      -p <pairing>  Elliptic curve pairing: BN128, Edwards
      -d <number>   Merkle tree authentication path length: 1, 2,.., 64

To install:

    $ make install PREFIX=/usr/local

This copies the library files to $(PREFIX)/include/kapital .

--------------------------------------------------------------------------------
References
--------------------------------------------------------------------------------

[Zerocash]: http://eprint.iacr.org/2014/349

[GNU Multiple Precision Arithmetic Library]: https://gmplib.org/

[Crypto++]: http://www.cryptopp.com/

[GitHub cryptl project]: https://github.com/jancarlsson/cryptl

[GitHub snarklib project]: https://github.com/jancarlsson/snarklib

[GitHub snarkfront project]: https://github.com/jancarlsson/snarkfront
