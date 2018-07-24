//! DNS resolver for Hyper

#[macro_use]
extern crate log;
extern crate hyper;
extern crate rand;
extern crate tokio_core;
extern crate trust_dns;

use trust_dns::client::ClientHandle;
use rand::Rng;
use hyper::net::{NetworkConnector, NetworkStream};
use std::time::Duration;

/// Docs
#[derive(Debug, Clone)]
pub enum RecordType {
    /// A
    A,
    /// SRV
    SRV,
    /// AUTO
    AUTO,
}

/// A connector that wraps another connector and provides custom DNS resolution.
#[derive(Debug, Clone)]
pub struct DnsConnector<C: NetworkConnector> {
    connector: C,
    dns_addr: std::net::SocketAddr,
    record_type: RecordType,
}

/// Docs
impl<C: NetworkConnector> DnsConnector<C> {
    /// Docs
    pub fn new(dns_addr: std::net::SocketAddr, connector: C) -> DnsConnector<C> {
        Self::new_with_resolve_type(dns_addr, connector, RecordType::AUTO)
    }

    /// Docs
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
        let (stream, sender) = trust_dns::tcp::TcpClientStream::new(self.dns_addr, &io.handle());

        // We would expect a DNS request to be responded to quickly, but add a timeout
        // to ensure that we don't wait for ever if the DNS server does not respond.
        let timeout = Duration::from_millis(30000);
        let mut dns_client =
            trust_dns::client::ClientFuture::with_timeout(
                stream,
                sender,
                &io.handle(),
                timeout,
                None);

        // Check if this is a domain name or not before trying to use DNS resolution.
        let (host, port) = match host.parse() {
            Err(_) => {

                debug!("Trying to resolve {}://{}", scheme, &host);

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
                            debug!("Using A record lookup for: {}", &host);
                            trust_dns::rr::RecordType::A
                        }
                    }
                };

                debug!("Sending DNS request");

                match io.run(dns_client.query(name.clone(),
                                              trust_dns::rr::DNSClass::IN,
                                              trust_record_type)) {
                    Ok(res) => {
                        let answers = res.answers();

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

                            let srv = match *answer.rdata() {
                                trust_dns::rr::RData::SRV(ref srv) => srv,
                                _ => {
                                    return Err(std::io::Error::new(std::io::ErrorKind::Other,
                                                                   "Unexpected DNS response")
                                                       .into())
                                }
                            };

                            (srv.target(), res.additionals(), srv.port())
                        } else {
                            // For A record requests it is the domain name that
                            // we want to use.
                            (&name, answers, port)
                        };

                        let entry = a_records.iter().find(|record| record.name() == target);

                        if let Some(entry) = entry {
                            let addr = match *entry.rdata() {
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

        debug!("Resolved request to {}://{}:{}", scheme, &host, port);

        self.connector.connect(&host, port, scheme)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {}
}
