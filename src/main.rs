use bytes::BufMut;
use color_eyre::Result;
use tokio::net::UdpSocket;

trait Serialize {
    fn serialize(&self, dst: &mut dyn BufMut);
}

#[derive(Debug, Default)]
struct DnsHeader {
    id: u16,
    flags: u16,
    num_questions: u16,
    num_answers: u16,
    num_authorities: u16,
    num_additionals: u16,
}

impl Serialize for DnsHeader {
    fn serialize(&self, dst: &mut dyn BufMut) {
        dst.put_u16(self.id);
        dst.put_u16(self.flags);
        dst.put_u16(self.num_questions);
        dst.put_u16(self.num_answers);
        dst.put_u16(self.num_authorities);
        dst.put_u16(self.num_additionals);
    }
}

#[derive(Debug)]
struct DnsQuestion<'a> {
    name: Domain<'a>,
    ty: Type,
    class: Class,
}

impl Serialize for DnsQuestion<'_> {
    fn serialize(&self, dst: &mut dyn BufMut) {
        self.name.serialize(dst);
        dst.put_u16(self.ty as u16);
        dst.put_u16(self.class as u16);
    }
}

#[derive(Debug)]
struct Domain<'a>(&'a [u8]);

impl Serialize for Domain<'_> {
    fn serialize(&self, dst: &mut dyn BufMut) {
        for part in self.0.split(|c| c == &b'.') {
            let len = part.len().try_into().unwrap();
            dst.put_u8(len);
            dst.put_slice(part);
        }
        dst.put_u8(0);
    }
}

/// See <https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.2>.
#[repr(u16)]
#[derive(Copy, Clone, Debug)]
enum Type {
    A = 0x1,
}

/// See <https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.4>.
#[repr(u16)]
#[derive(Copy, Clone, Debug)]
enum Class {
    /// The internet.
    In = 0x1,
}

struct DnsQuery<'a> {
    header: DnsHeader,
    question: DnsQuestion<'a>,
}

impl<'a> DnsQuery<'a> {
    pub fn new(id: u16, domain: &'a [u8], ty: Type) -> DnsQuery<'a> {
        const RECURSION_DESIRED: u16 = 1 << 8;

        DnsQuery {
            header: DnsHeader {
                id,
                flags: RECURSION_DESIRED,
                num_questions: 1,
                ..Default::default()
            },
            question: DnsQuestion {
                name: Domain(domain),
                ty,
                class: Class::In,
            },
        }
    }
}

impl Serialize for DnsQuery<'_> {
    fn serialize(&self, dst: &mut dyn BufMut) {
        self.header.serialize(dst);
        self.question.serialize(dst);
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    color_eyre::install().unwrap();
    run().await
}

async fn run() -> Result<()> {
    let socket = UdpSocket::bind(("0.0.0.0", 0)).await?;
    socket.connect(("8.8.8.8", 53)).await?;

    let query = DnsQuery::new(fastrand::u16(..), b"example.com", Type::A);

    {
        let mut buf = vec![];
        query.serialize(&mut buf);
        socket.send(&buf).await?;
    }

    {
        let mut buf = vec![0; 1024];
        let n = socket.recv(&mut buf).await?;
        println!("got {n} bytes");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! test_serialize {
        ($name:ident, $serialize:expr, $expected:expr $(,)?) => {
            #[test]
            fn $name() {
                let mut bytes = vec![];
                $serialize.serialize(&mut bytes);
                assert_eq!(bytes, $expected);
            }
        };
    }

    test_serialize!(
        test_dns_header,
        DnsHeader {
            id: 0x1314,
            flags: 1,
            num_questions: 2,
            num_answers: 3,
            num_authorities: 4,
            num_additionals: 5,
        },
        b"\x13\x14\x00\x01\x00\x02\x00\x03\x00\x04\x00\x05",
    );

    test_serialize!(
        test_dns_question,
        DnsQuestion {
            name: Domain(b"foo"),
            ty: Type::A,
            class: Class::In,
        },
        b"\x03foo\x00\x00\x01\x00\x01"
    );

    test_serialize!(
        test_domain,
        Domain(b"google.com.br"),
        b"\x06google\x03com\x02br\x00",
    );

    test_serialize!(
        test_dns_query,
        DnsQuery {
            header: DnsHeader {
                id: 0xABCD,
                flags: 1 << 8,
                num_questions: 1,
                num_answers: 0,
                num_authorities: 0,
                num_additionals: 0
            },
            question: DnsQuestion {
                name: Domain(b"example.com"),
                ty: Type::A,
                class: Class::In
            }
        },
        b"\xAB\xCD\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01",
    );

    test_serialize!(
        test_dns_query_new,
        DnsQuery::new(0xABCD, b"example.com", Type::A),
        // Same as above.
        b"\xAB\xCD\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01",
    );
}
