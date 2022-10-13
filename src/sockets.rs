use std::os::unix::prelude::RawFd;

use nix::{
    errno::Errno,
    sys::socket::{recv, send, socketpair, AddressFamily, MsgFlags, SockFlag, SockType},
    unistd::close,
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Error while creating socket pair: {0}")]
    Create(Errno),
    #[error("Error while closing socket: {0}")]
    Close(Errno),
    #[error("Error while sending data: {0}")]
    Send(Errno),
    #[error("Error while receiving data: {0}")]
    Receive(Errno),
}

pub fn create_socketpair() -> Result<(RawFd, RawFd), Error> {
    socketpair(
        AddressFamily::Unix,
        SockType::SeqPacket,
        None,
        SockFlag::SOCK_CLOEXEC,
    )
    .map_err(Error::Create)
}

pub fn close_socket(socket: RawFd) -> Result<(), Error> {
    close(socket).map_err(Error::Close)
}

pub trait SocketSend<T> {
    fn send(&self, data: T) -> Result<(), Error>;
}

pub trait SocketReceive<T> {
    fn receive(&self) -> Result<T, Error>;
}

impl SocketSend<bool> for RawFd {
    fn send(&self, data: bool) -> Result<(), Error> {
        let data: [u8; 1] = [data.into()];
        let _ = send(*self, &data, MsgFlags::empty()).map_err(Error::Send)?;
        Ok(())
    }
}

impl SocketReceive<bool> for RawFd {
    fn receive(&self) -> Result<bool, Error> {
        let mut data: [u8; 1] = [0];
        let _ = recv(*self, &mut data, MsgFlags::empty()).map_err(Error::Receive)?;
        Ok(data[0] == 1)
    }
}

impl<const S: usize> SocketSend<[u8; S]> for RawFd {
    fn send(&self, data: [u8; S]) -> Result<(), Error> {
        let _ = send(*self, &data, MsgFlags::empty()).map_err(Error::Send)?;
        Ok(())
    }
}

impl<const S: usize> SocketReceive<[u8; S]> for RawFd {
    fn receive(&self) -> Result<[u8; S], Error> {
        let mut data: [u8; S] = [0; S];
        let _ = recv(*self, &mut data, MsgFlags::empty()).map_err(Error::Receive)?;
        Ok(data)
    }
}
