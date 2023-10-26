---
title: Trouble shooting
sidebar_position: 4
---

# Trouble shooting

## How to analyze encrypted QUIC traffic?

The TLS key log can be saved by using the `--keylog-file` option in example tools or by utilizing the [keylog API](../api_reference/c_quic#connection-logging-and-tracing) for your own programs. 

This saved key log file can then be used to decrypt QUIC traffic in Wireshark.

:::tip
In Wireshark, navigate to `Edit-> Preferences-> Protocols-> TLS`, and update the `(Pre)-Master-Secret log filename preference` with the path of the TLS key log.
:::
