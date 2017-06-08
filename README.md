# hyper-dns

[![Crates.io - hyper-dns](https://img.shields.io/crates/v/hyper-dns.svg)](https://crates.io/crates/hyper-dns) [![Build Status](https://travis-ci.org/cswindle/hyper-dns.svg?branch=master)](https://travis-ci.org/cswindle/hyper-dns) [![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

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
