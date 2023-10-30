---
title: Core concepts
sidebar_position: 1
---

# Core Concepts

Commonly used terms in the TQUIC APIs are described below.

## Endpoint

The **Endpoint** is responsible for managing connections, processing incoming packets, and scheduling outgoing packets. 

There are only two types of endpoints in QUIC: client and server. The Endpoint can operate in either server or client mode.


## Connection

The QUIC **Connection** can carry multiple simultaneous streams, which are ordered sequences of bytes.

The QUIC connection is not strictly bound to a single network path. It uses connection identifiers to allow it to transfer to a new network path or simultaneous use of different paths. Only clients are allowed to initiate a new path on the QUIC connection.


## Stream

The **Stream** provides a lightweight, ordered byte-stream abstraction to an application. 

Streams can be unidirectional or bidirectional: **unidirectional** streams carry data from the initiator to its peer; **bidirectional** streams allow for data to be sent in both directions.

The Stream can be created by either client or server, can concurrently send data interleaved with other streams, and can be canceled. 


## Path

The **path** is determined by the 4-tuple consisting of the source and destination IP addresses, as well as the source and destination ports.


## QUIC packet

The **QUIC packet** is a complete and processable unit of QUIC that can be encapsulated in a UDP datagram. Multiple QUIC packets can be encapsulated in a single UDP datagram.

