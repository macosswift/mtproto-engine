use super::buffer::InputBuffer;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Socks5Target {
    Ipv4([u8; 4], u16),
    Ipv6([u8; 16], u16),
    Domain(String, u16),
}

#[derive(Clone, PartialEq, Eq)]
pub struct Socks5Auth {
    pub username: String,
    pub password: String,
}

impl core::fmt::Debug for Socks5Auth {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Socks5Auth(..)")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Socks5Error {
    #[error("proxy replied with an invalid version {0}")]
    InvalidVersion(u8),
    #[error("proxy requires an unsupported authentication method {0:#04x}")]
    UnsupportedMethod(u8),
    #[error("proxy rejected the credentials")]
    AuthenticationFailed,
    #[error("proxy failed to connect: reply code {0}")]
    ConnectFailed(u8),
    #[error("invalid address type {0}")]
    InvalidAddressType(u8),
    #[error("credentials are too long")]
    CredentialsTooLong,
    #[error("domain name is too long")]
    DomainTooLong,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Socks5Progress {
    NeedMore,
    Send(Vec<u8>),
    Connected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Greeting,
    Authenticating,
    Connecting,
    Done,
}

#[derive(Debug)]
pub struct Socks5Handshake {
    target: Socks5Target,
    auth: Option<Socks5Auth>,
    state: State,
}

impl Socks5Handshake {
    pub fn new(target: Socks5Target, auth: Option<Socks5Auth>) -> Result<(Self, Vec<u8>), Socks5Error> {
        if let Some(auth) = &auth
            && (auth.username.len() > 255 || auth.password.len() > 255)
        {
            return Err(Socks5Error::CredentialsTooLong);
        }
        if let Socks5Target::Domain(domain, _) = &target
            && domain.len() > 255
        {
            return Err(Socks5Error::DomainTooLong);
        }
        let greeting = if auth.is_some() { vec![5, 2, 0, 2] } else { vec![5, 1, 0] };
        Ok((Self { target, auth, state: State::Greeting }, greeting))
    }

    pub fn is_done(&self) -> bool {
        self.state == State::Done
    }

    fn connect_request(&self) -> Vec<u8> {
        let mut request = vec![5, 1, 0];
        let port = match &self.target {
            Socks5Target::Ipv4(address, port) => {
                request.push(1);
                request.extend_from_slice(address);
                *port
            }
            Socks5Target::Ipv6(address, port) => {
                request.push(4);
                request.extend_from_slice(address);
                *port
            }
            Socks5Target::Domain(domain, port) => {
                request.push(3);
                request.push(domain.len() as u8);
                request.extend_from_slice(domain.as_bytes());
                *port
            }
        };
        request.extend_from_slice(&port.to_be_bytes());
        request
    }

    pub fn feed(&mut self, input: &mut InputBuffer) -> Result<Socks5Progress, Socks5Error> {
        let data = input.as_slice();
        match self.state {
            State::Greeting => {
                if data.len() < 2 {
                    return Ok(Socks5Progress::NeedMore);
                }
                if data[0] != 5 {
                    return Err(Socks5Error::InvalidVersion(data[0]));
                }
                let method = data[1];
                input.consume(2);
                match method {
                    0 => {
                        self.state = State::Connecting;
                        Ok(Socks5Progress::Send(self.connect_request()))
                    }
                    2 => {
                        let Some(auth) = &self.auth else {
                            return Err(Socks5Error::UnsupportedMethod(method));
                        };
                        let mut request = vec![1, auth.username.len() as u8];
                        request.extend_from_slice(auth.username.as_bytes());
                        request.push(auth.password.len() as u8);
                        request.extend_from_slice(auth.password.as_bytes());
                        self.state = State::Authenticating;
                        Ok(Socks5Progress::Send(request))
                    }
                    other => Err(Socks5Error::UnsupportedMethod(other)),
                }
            }
            State::Authenticating => {
                if data.len() < 2 {
                    return Ok(Socks5Progress::NeedMore);
                }
                let (version, status) = (data[0], data[1]);
                input.consume(2);
                if version != 0x01 {
                    return Err(Socks5Error::InvalidVersion(version));
                }
                if status != 0 {
                    return Err(Socks5Error::AuthenticationFailed);
                }
                self.state = State::Connecting;
                Ok(Socks5Progress::Send(self.connect_request()))
            }
            State::Connecting => {
                if data.len() < 5 {
                    return Ok(Socks5Progress::NeedMore);
                }
                if data[0] != 5 {
                    return Err(Socks5Error::InvalidVersion(data[0]));
                }
                if data[1] != 0 {
                    return Err(Socks5Error::ConnectFailed(data[1]));
                }
                let address_len = match data[3] {
                    1 => 4,
                    4 => 16,
                    3 => 1 + data[4] as usize,
                    other => return Err(Socks5Error::InvalidAddressType(other)),
                };
                let total = 4 + address_len + 2;
                if data.len() < total {
                    return Ok(Socks5Progress::NeedMore);
                }
                input.consume(total);
                self.state = State::Done;
                Ok(Socks5Progress::Connected)
            }
            State::Done => Ok(Socks5Progress::Connected),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed_all(handshake: &mut Socks5Handshake, bytes: &[u8]) -> Result<Socks5Progress, Socks5Error> {
        let mut input = InputBuffer::new();
        input.extend(bytes);
        let progress = handshake.feed(&mut input)?;
        assert!(input.is_empty());
        Ok(progress)
    }

    #[test]
    fn no_auth_ipv4() {
        let (mut handshake, greeting) =
            Socks5Handshake::new(Socks5Target::Ipv4([149, 154, 167, 51], 443), None).unwrap();
        assert_eq!(greeting, vec![5, 1, 0]);
        assert_eq!(
            feed_all(&mut handshake, &[5, 0]).unwrap(),
            Socks5Progress::Send(vec![5, 1, 0, 1, 149, 154, 167, 51, 1, 187])
        );
        assert_eq!(feed_all(&mut handshake, &[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap(), Socks5Progress::Connected);
        assert!(handshake.is_done());
    }

    #[test]
    fn password_auth_ipv6_and_domain_reply() {
        let auth = Socks5Auth { username: "user".into(), password: "pw".into() };
        let (mut handshake, greeting) = Socks5Handshake::new(Socks5Target::Ipv6([0x20; 16], 80), Some(auth)).unwrap();
        assert_eq!(greeting, vec![5, 2, 0, 2]);
        assert_eq!(
            feed_all(&mut handshake, &[5, 2]).unwrap(),
            Socks5Progress::Send(vec![1, 4, b'u', b's', b'e', b'r', 2, b'p', b'w'])
        );
        match feed_all(&mut handshake, &[1, 0]).unwrap() {
            Socks5Progress::Send(request) => {
                assert_eq!(&request[..4], &[5, 1, 0, 4]);
                assert_eq!(request.len(), 4 + 16 + 2);
            }
            other => panic!("{other:?}"),
        }
        let mut input = InputBuffer::new();
        input.extend(&[5, 0, 0, 3, 3]);
        assert_eq!(handshake.feed(&mut input).unwrap(), Socks5Progress::NeedMore);
        input.extend(b"abc\x00\x50");
        assert_eq!(handshake.feed(&mut input).unwrap(), Socks5Progress::Connected);
    }

    #[test]
    fn failures() {
        let (mut handshake, _) = Socks5Handshake::new(Socks5Target::Domain("example.com".into(), 443), None).unwrap();
        assert_eq!(feed_all(&mut handshake, &[4, 0]), Err(Socks5Error::InvalidVersion(4)));
        let (mut handshake, _) = Socks5Handshake::new(Socks5Target::Domain("example.com".into(), 443), None).unwrap();
        assert_eq!(feed_all(&mut handshake, &[5, 2]), Err(Socks5Error::UnsupportedMethod(2)));
        let (mut handshake, _) = Socks5Handshake::new(Socks5Target::Ipv4([1, 2, 3, 4], 1), None).unwrap();
        feed_all(&mut handshake, &[5, 0]).unwrap();
        assert_eq!(feed_all(&mut handshake, &[5, 5, 0, 1, 0]), Err(Socks5Error::ConnectFailed(5)));
        let auth = Socks5Auth { username: "u".into(), password: "p".into() };
        let (mut handshake, _) = Socks5Handshake::new(Socks5Target::Ipv4([1, 2, 3, 4], 1), Some(auth)).unwrap();
        feed_all(&mut handshake, &[5, 2]).unwrap();
        assert_eq!(feed_all(&mut handshake, &[1, 1]), Err(Socks5Error::AuthenticationFailed));
        assert!(Socks5Handshake::new(Socks5Target::Domain("a".repeat(300), 1), None).is_err());
    }
}
