sut, an IPv6 in IPv4 Userlspace Tunnel (RFC 4213)


## DEPENDENCIES

* https://github.com/msantos/procket

* https://github.com/msantos/pkt

* https://github.com/msantos/tunctl


## SETUP

* Sign up for an IPv6 tunnel with Hurricane Electric

    http://tunnelbroker.net/

* Start the IPv6 tunnel:

    * Serverv4 = HE IPv4 tunnel end

    * Clientv4 = Your local IP address

    * Clientv6 = The IPv6 address assigned by HE to your end of the tunnel


            sut:start([{serverv4, "216.66.22.2"}, {clientv4, "192.168.1.72"}, {clientv6, "2001:3:3:3::2"}]).

    * Set up MTU and routing (as root)

            ifconfig sut-ipv6 mtu 1480
            ip route add ::/0 dev sut-ipv6

    * Test the tunnel!

            ping6 ipv6.google.com


## TODO

* Support other checks required by RFC

* Support inbound/outbound IPv6 firewalling
