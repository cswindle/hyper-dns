
extern crate futures;
extern crate hyper;
extern crate rand;
extern crate tokio_core;
extern crate trust_dns;

use trust_dns::client::ClientHandle;
use rand::Rng;

/// A connector that wraps another connector and provides custom DNS resolution.
#[derive(Debug, Clone)]
pub struct DnsConnector<C: hyper::net::NetworkConnector> {
    connector: C,
    dns_addr: std::net::SocketAddr,
}

impl <C: hyper::net::NetworkConnector> DnsConnector<C> {
    pub fn new(dns_addr: std::net::SocketAddr, connector: C) -> DnsConnector<C> {

        DnsConnector {
            connector: connector,
            dns_addr: dns_addr,
        }
    }
}

impl <C: hyper::net::NetworkConnector<Stream=S>, S: hyper::net::NetworkStream + Send> hyper::net::NetworkConnector for DnsConnector<C> {

    type Stream = S;

    /// Performs DNS SRV resolution, then calls into the inner connector with the results.
    /// Note that currently this does not take into account the following in the SRV record:
    /// * weight
    /// * priority
    /// It just takes a random entry in the DNS answers that are returned.
    fn connect(&self, host: &str, _port: u16, scheme: &str) -> hyper::Result<S> {

        let mut io = tokio_core::reactor::Core::new().expect("Failed to create event loop for DNS query");
        let (stream, sender) = trust_dns::udp::UdpClientStream::new(self.dns_addr, io.handle());
        let mut dns_client = trust_dns::client::ClientFuture::new(stream, sender, io.handle(), None);

        let name = trust_dns::rr::Name::parse(host, None).unwrap();

        match io.run(dns_client.query(name,
                                      trust_dns::rr::DNSClass::IN,
                                      trust_dns::rr::RecordType::SRV)) {
            Ok(res) => {
                let answers = res.get_answers();

                if answers.is_empty() {
                    return Err(std::io::Error::new(std::io::ErrorKind::Other, "No valid DNS answers").into())
                }

                let mut rng = rand::thread_rng();
                let answer = rng.choose(answers).expect("Sort out what to return here");

                let srv = match *answer.get_rdata() {
                    trust_dns::rr::RData::SRV(ref srv) => srv,
                    _ => return Err(std::io::Error::new(std::io::ErrorKind::Other, "Unexpected DNS response").into()),
                };

                self.connector.connect(&srv.get_target().to_string(), srv.get_port(), scheme)
            },
            _ => Err(std::io::Error::new(std::io::ErrorKind::Other, "Failed to query DNS server").into()),
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
