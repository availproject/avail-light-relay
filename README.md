<div align="Center">
<h1>avail-light-relay</h1>
<h3>Relay Server Node for the Avail blockchain Light client</h3>
</div>

<br>

## Introduction

`avail-light-relay` is a server node, which utilizes Circuit Relay transport protocol.

This node routes traffic between two peers as a third-party “relay” peer. 

In peer-to-peer networks, on the whole, there will come a time when peers will be unable to traverse their NAT and/or firewalls. Which makes them publicly unavailable. To face these connectivity hurdles, when a peer isn't able to listen to a public address, it can dial out to a relay peer, which will retain a long-lived open connection.

Other peers can dial through the relay peer using a `p2p-circuit` address, which forwards called for traffic to its destination.

An important aspect here is that the employed protocol is not "transparent". Both the source and the destination are aware that traffic is being relayed. This can potentially be used to construct a path from the destination back to the source.

All participants are identified using their Peer ID, including the relay node, which leads to an obvious conclusion that this protocol is not anonymous, by any means.

## Address

A relay node is identified using a multiaddr that includes the Peer ID of the peer whose traffic is being relayed (the listening peer or “relay target”). With this in mind, we could construct an address that describes a path to the source through some specific relay with selected transport:

```/ip4/198.51.100.0/tcp/55555/p2p/SomeRelay/p2p-circuit/p2p/SomeDude```
