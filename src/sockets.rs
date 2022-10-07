use std::os::unix::prelude::RawFd;

use nix::sys::socket::{recv, send, socketpair, AddressFamily, MsgFlags, SockFlag, SockType};

use crate::container::Error;

pub fn create_socketpair() -> Result<(RawFd, RawFd), Error> {
    socketpair(
        AddressFamily::Unix,
        SockType::SeqPacket,
        None,
        SockFlag::SOCK_CLOEXEC,
    )
    .map_err(Error::SocketPairCreation)
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
        let _ = send(*self, &data, MsgFlags::empty()).map_err(Error::SocketSend)?;
        Ok(())
    }
}

impl SocketReceive<bool> for RawFd {
    fn receive(&self) -> Result<bool, Error> {
        let mut data: [u8; 1] = [0];
        let _ = recv(*self, &mut data, MsgFlags::empty()).map_err(Error::SocketReceive)?;
        Ok(data[0] == 1)
    }
}
