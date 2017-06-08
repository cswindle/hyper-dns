# hyper-dns
NetworkConnector to allow using a custom DNS server with SRV records in Hyper.

Below shows a quick example of how this library can be used (you will need to have SRV records setup for the domain to query):

```
extern crate hyper_dns;
extern crate hyper;

use std::net::ToSocketAddrs;

fn main() {

    let dns_addr: std::net::SocketAddr = ("127.0.0.1", 8600).to_socket_addrs().unwrap().next().unwrap();

    let client = hyper::client::Client::with_connector(
        hyper_dns::DnsConnector::new(dns_addr, hyper::net::HttpConnector));

    client.get("http://test.service.consul/").send();
}
```
