
extern crate futures;
extern crate hyper;
extern crate rand;
extern crate tokio_core;
extern crate trust_dns;

use trust_dns::client::ClientHandle;
use rand::Rng;
use hyper::net::{NetworkConnector, NetworkStream};

#[derive(Debug, Clone)]
pub enum RecordType {
    A,
    SRV,
    AUTO,
}

/// A connector that wraps another connector and provides custom DNS resolution.
#[derive(Debug, Clone)]
pub struct DnsConnector<C: NetworkConnector> {
    connector: C,
    dns_addr: std::net::SocketAddr,
    record_type: RecordType,
}

impl<C: NetworkConnector> DnsConnector<C> {
    pub fn new(dns_addr: std::net::SocketAddr, connector: C) -> DnsConnector<C> {
        Self::new_with_resolve_type(dns_addr, connector, RecordType::AUTO)
    }

    pub fn new_with_resolve_type(dns_addr: std::net::SocketAddr,
                                 connector: C,
                                 record_type: RecordType)
                                 -> DnsConnector<C> {
        DnsConnector {
            connector: connector,
            dns_addr: dns_addr,
            record_type: record_type,
        }
    }
}

impl<C: NetworkConnector<Stream = S>, S: NetworkStream + Send> NetworkConnector
    for DnsConnector<C> {
    type Stream = S;

    /// Performs DNS SRV resolution, then calls into the inner connector with the results.
    /// Note that currently this does not take into account the following in the SRV record:
    /// * weight
    /// * priority
    /// It just takes a random entry in the DNS answers that are returned.
    fn connect(&self, host: &str, port: u16, scheme: &str) -> hyper::Result<S> {

        let mut io = tokio_core::reactor::Core::new()
            .expect("Failed to create event loop for DNS query");
        let (stream, sender) = trust_dns::udp::UdpClientStream::new(self.dns_addr, io.handle());
        let mut dns_client =
            trust_dns::client::ClientFuture::new(stream, sender, io.handle(), None);

        // Check if this is a domain name or not before trying to use DNS resolution.
        let (host, port) = match host.parse() {
            Err(_) => {

                // Add a `.` to the end of the host so that we can query the domain records.
                let name = trust_dns::rr::Name::parse(&format!("{}.", host), None).unwrap();

                let trust_record_type = match self.record_type {
                    RecordType::A => trust_dns::rr::RecordType::A,
                    RecordType::SRV => trust_dns::rr::RecordType::SRV,
                    RecordType::AUTO => {
                        // If the port is a standard HTTP port (80, or 443), then assume
                        // one was not provided and perform SRV lookup, otherwise lookup
                        // A records.
                        if (port == 80) || (port == 443) {
                            trust_dns::rr::RecordType::SRV
                        } else {
                            trust_dns::rr::RecordType::A
                        }
                    }
                };

                match io.run(dns_client.query(name.clone(),
                                              trust_dns::rr::DNSClass::IN,
                                              trust_record_type)) {
                    Ok(res) => {
                        let answers = res.get_answers();

                        if answers.is_empty() {
                            return Err(std::io::Error::new(std::io::ErrorKind::Other,
                                                           "No valid DNS answers")
                                               .into());
                        }

                        let mut rng = rand::thread_rng();

                        // First find the SRV records if they were requested
                        let (target, a_records, new_port) = if let trust_dns::rr::RecordType::SRV =
                            trust_record_type {
                            let answer = rng.choose(answers).expect("Sort out what to return here");

                            let srv = match *answer.get_rdata() {
                                trust_dns::rr::RData::SRV(ref srv) => srv,
                                _ => {
                                    return Err(std::io::Error::new(std::io::ErrorKind::Other,
                                                                   "Unexpected DNS response")
                                                       .into())
                                }
                            };

                            (srv.get_target(), res.get_additionals(), srv.get_port())
                        } else {
                            // For A record requests it is the domain name that
                            // we want to use.
                            (&name, answers, port)
                        };

                        let entry = a_records.iter().find(|record| record.get_name() == target);

                        if let Some(entry) = entry {
                            let addr = match *entry.get_rdata() {
                                trust_dns::rr::RData::A(ref addr) => addr,
                                _ => {
                                    return Err(std::io::Error::new(std::io::ErrorKind::Other,
                                                                   "Did not receive a valid record")
                                                       .into())
                                }
                            };

                            (addr.to_string(), new_port)
                        } else {
                            return Err(std::io::Error::new(std::io::ErrorKind::Other,
                                                           "Did not receive a valid record")
                                               .into());
                        }

                    }
                    _ => {
                        return Err(std::io::Error::new(std::io::ErrorKind::Other,
                                                       "Failed to query DNS server")
                                           .into())
                    }
                }
            }
            Ok(std::net::Ipv4Addr { .. }) => (host.to_string(), port),
        };

        self.connector.connect(&host, port, scheme)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {}
}
