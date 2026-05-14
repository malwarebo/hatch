#![deny(clippy::all)]

use std::io;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub mod messages;
pub mod paths;

pub use messages::*;
pub use paths::DaemonPaths;

pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum IpcError {
    #[error("io: {0}")]
    Io(#[from] io::Error),

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    #[error("frame too large: {0} bytes > {1}")]
    FrameTooLarge(usize, usize),

    #[error("connection closed before frame complete")]
    ShortRead,
}

pub struct Codec;

impl Codec {
    pub async fn write_message<W, M>(writer: &mut W, msg: &M) -> Result<(), IpcError>
    where
        W: AsyncWriteExt + Unpin,
        M: Serialize,
    {
        let bytes = serde_json::to_vec(msg)?;
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(IpcError::FrameTooLarge(bytes.len(), MAX_FRAME_BYTES));
        }
        let len = u32::try_from(bytes.len()).expect("checked above");
        writer.write_all(&len.to_be_bytes()).await?;
        writer.write_all(&bytes).await?;
        writer.flush().await?;
        Ok(())
    }

    pub async fn read_message<R, M>(reader: &mut R) -> Result<M, IpcError>
    where
        R: AsyncReadExt + Unpin,
        M: for<'de> Deserialize<'de>,
    {
        let mut len_buf = [0u8; 4];
        reader
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| match e.kind() {
                io::ErrorKind::UnexpectedEof => IpcError::ShortRead,
                _ => IpcError::Io(e),
            })?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > MAX_FRAME_BYTES {
            return Err(IpcError::FrameTooLarge(len, MAX_FRAME_BYTES));
        }
        let mut buf = vec![0u8; len];
        reader
            .read_exact(&mut buf)
            .await
            .map_err(|e| match e.kind() {
                io::ErrorKind::UnexpectedEof => IpcError::ShortRead,
                _ => IpcError::Io(e),
            })?;
        Ok(serde_json::from_slice(&buf)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn round_trip_status() {
        let (mut a, mut b) = duplex(8192);
        let sent = ClientRequest::DaemonStatus;
        Codec::write_message(&mut a, &sent).await.unwrap();
        let got: ClientRequest = Codec::read_message(&mut b).await.unwrap();
        assert!(matches!(got, ClientRequest::DaemonStatus));
    }

    #[tokio::test]
    async fn round_trip_response() {
        let (mut a, mut b) = duplex(8192);
        let sent = DaemonResponse::DaemonStatus {
            uptime_seconds: 42,
            running_servers: 3,
            version: "0.1.0".into(),
        };
        Codec::write_message(&mut a, &sent).await.unwrap();
        let got: DaemonResponse = Codec::read_message(&mut b).await.unwrap();
        match got {
            DaemonResponse::DaemonStatus {
                uptime_seconds,
                running_servers,
                version,
            } => {
                assert_eq!(uptime_seconds, 42);
                assert_eq!(running_servers, 3);
                assert_eq!(version, "0.1.0");
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[tokio::test]
    async fn rejects_huge_frame() {
        let (mut a, mut b) = duplex(8);
        let huge = (MAX_FRAME_BYTES as u32) + 1;
        a.write_all(&huge.to_be_bytes()).await.unwrap();
        a.flush().await.unwrap();
        let err = Codec::read_message::<_, ClientRequest>(&mut b)
            .await
            .unwrap_err();
        assert!(matches!(err, IpcError::FrameTooLarge(_, _)));
    }
}
