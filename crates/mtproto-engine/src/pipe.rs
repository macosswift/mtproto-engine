use std::io::{self, ErrorKind, Read, Write};
use std::net::SocketAddr;

use mio::net::TcpStream;
use mio::{Interest, Registry, Token};

use crate::host_stream::HostPipe;

/// What a connection reads and writes: its own socket, or a stream the host opened for it.
pub(crate) enum Pipe {
    Socket(TcpStream),
    Host(HostPipe),
}

impl Pipe {
    pub(crate) fn connect(registry: &Registry, token: Token, address: SocketAddr) -> io::Result<Self> {
        let mut socket = TcpStream::connect(address)?;
        registry.register(&mut socket, token, Interest::READABLE | Interest::WRITABLE)?;
        Ok(Pipe::Socket(socket))
    }

    pub(crate) fn is_host(&self) -> bool {
        matches!(self, Pipe::Host(_))
    }

    /// Ok(true) once the connection is up, Ok(false) while it is still being made.
    pub(crate) fn finish_connect(&mut self) -> io::Result<bool> {
        match self {
            Pipe::Socket(socket) => {
                if let Some(error) = socket.take_error()? {
                    return Err(error);
                }
                match socket.peer_addr() {
                    Ok(_) => {
                        let _ = socket.set_nodelay(true);
                        Ok(true)
                    }
                    Err(error) if error.kind() == ErrorKind::NotConnected => Ok(false),
                    Err(error) => Err(error),
                }
            }
            Pipe::Host(pipe) => pipe.is_connected(),
        }
    }

    pub(crate) fn is_cellular(&self) -> bool {
        match self {
            Pipe::Socket(socket) => socket
                .local_addr()
                .ok()
                .and_then(|address| crate::interface::interface_name_for(address.ip()))
                .is_some_and(|name| crate::interface::is_cellular_interface(&name)),
            Pipe::Host(_) => false,
        }
    }

    /// Asks for writable events or stops them; a host stream reports writability whenever it took
    /// back a write it had refused.
    pub(crate) fn set_writable_interest(
        &mut self,
        registry: &Registry,
        token: Token,
        writable: bool,
    ) -> io::Result<()> {
        match self {
            Pipe::Socket(socket) => {
                let interest = if writable { Interest::READABLE | Interest::WRITABLE } else { Interest::READABLE };
                registry.reregister(socket, token, interest)
            }
            Pipe::Host(_) => Ok(()),
        }
    }

    pub(crate) fn close(&mut self, registry: &Registry) {
        match self {
            Pipe::Socket(socket) => {
                let _ = registry.deregister(socket);
                let _ = socket.shutdown(std::net::Shutdown::Both);
            }
            Pipe::Host(pipe) => pipe.close(),
        }
    }

    /// Bytes written that have not left yet: in the kernel's send queue, or not confirmed by the host.
    pub(crate) fn send_queue(&self) -> Option<usize> {
        match self {
            Pipe::Socket(socket) => crate::connection::kernel_send_queue(socket),
            Pipe::Host(pipe) => Some(pipe.unconfirmed()),
        }
    }
}

impl Read for Pipe {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match self {
            Pipe::Socket(socket) => socket.read(buffer),
            Pipe::Host(pipe) => pipe.read(buffer),
        }
    }
}

impl Write for Pipe {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match self {
            Pipe::Socket(socket) => socket.write(bytes),
            Pipe::Host(pipe) => pipe.write(bytes),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Pipe::Socket(socket) => socket.flush(),
            Pipe::Host(pipe) => pipe.flush(),
        }
    }
}
