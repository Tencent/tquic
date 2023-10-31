---
title: Conformance
sidebar_position: 3
---

# Protocol conformance test

We perform protocol conformance tests based on the methodology introduced in a paper titled ["Formal specification and testing of QUIC"](https://dl.acm.org/doi/10.1145/3341302.3342087) published at SIGCOMM 2019. We have upgraded the initial formal specification to incorporate support for QUIC v1 and resolved some issues in the ivy toolchain.


## Formal specification of QUIC

The formal specification of the QUIC protocol is written in the [Ivy](http://microsoft.github.io/ivy/) language. It can be used to test implementations of QUIC using compositional specification-based testing methods.

The currently targeted version is IETF QUIC v1.


## How it works

The specification is written in a way that allows monitoring of packets on the wire, as well as modular testing of implementations.

That is, from the specification we can produce an automated tester that takes one role in the protocol. The tester uses symbolic execution and an SMT solver to randomly generate protocol traffic that complies with the specification. For example, if the tester is taking the client role, it generates packets that are legal for the client to send, and these are transmitted to the server being tested. The responses sent by the server are then checked for compliance with the specification.


## Advantages

This approach has certain advantages when compared to interoperability testing.

* The specification-based tester can generate stimulus that can't be produced by any current implementation and perhaps would only be produced by attackers. Because it is randomized, it tends to generate unusual cases that specifiers may not have considered.

* It checks for actual specification compliance and not just for correct interopation. Compliance with the specification is important for future protocol developers who need to ensure compatibility with legacy implementations.

* The formal specification can be seen as documentation, since it gives an unambiguous interpretation of statements made in natural language in the IETF specification documents.


## Usage

The formal specification of QUIC v1 will soon be made available as open source, along with detailed instructions on how to use it in its project documentation. 

