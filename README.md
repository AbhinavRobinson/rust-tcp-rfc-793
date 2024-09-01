# RFC 793 (TCP) implementation in Rust

Handles TCP States:
```
[X] SYN
[ ] ACK
[ ] FIN
[ ] ...rest of tcp state
```

(Educational Purpose Only) Current version of program responds to IPv4 SYN packets and is able to recieve successful ACK packets from sender (netcat).

![Get ACK Packet](/_artifacts/get_ack.png?raw=true "Get ACK Packet from Netcat")
