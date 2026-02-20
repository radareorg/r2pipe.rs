use std::sync::mpsc::{RecvError, SendError, TryRecvError};
use std::{io, str};
use thiserror::Error;

/// Custom `Error` for r2pipe.rs.
#[derive(Error, Debug)]
pub enum Error {
    /// An I/O error occurred.
    #[error("I/O error")]
    Io(#[from] io::Error),

    /// No open radare2 session, perhaps path was not specified.
    #[error("No open session")]
    NoSession,

    /// Response had invalid/missing JSON.
    #[error("Empty response from JSON")]
    EmptyResponse,

    /// Incorrect number of arguments, or incorrect format.
    #[error("Argument mismatch")]
    ArgumentMismatch,

    /// An error occurred inside of serde.
    #[error("Serde deserialization error")]
    SerdeError(#[from] serde_json::Error),

    /// Error during UTF-8 decoding.
    #[error("UTF-8 decoding error")]
    Utf8(#[from] str::Utf8Error),

    /// Error receiving data from channel.
    #[error("Receive channel data error")]
    ChannelReceiveError(#[from] RecvError),

    /// Error trying to receive data from channel.
    #[error("Trying receive channel data error")]
    ChannelTryReceiveError(#[from] TryRecvError),

    /// Error sending data through channel.
    #[error("Send channel data error")]
    ChannelSendError(#[from] SendError<String>),

    /// Error loading radare2 shared library.
    #[error("Shared library error: {0}")]
    SharedLibraryError(#[from] libloading::Error),
}
