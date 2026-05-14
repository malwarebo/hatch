use std::io;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("oversize frame: {0} bytes")]
    Oversize(usize),
    #[error("bad header: {0}")]
    BadHeader(String),
    #[error("peer closed")]
    Eof,
}

pub const DEFAULT_MAX_FRAME: usize = 32 * 1024 * 1024;

pub async fn read_frame<R>(reader: &mut BufReader<R>, max: usize) -> Result<Vec<u8>, FrameError>
where
    R: AsyncReadExt + Unpin,
{
    let mut first_line = String::new();
    let n = reader.read_line(&mut first_line).await?;
    if n == 0 {
        return Err(FrameError::Eof);
    }
    let trimmed = first_line.trim_end_matches(['\r', '\n']);
    if let Some(rest) = trimmed.strip_prefix("Content-Length:") {
        return read_lsp_frame(reader, rest.trim(), max).await;
    }
    if trimmed.is_empty() {
        return Box::pin(read_frame(reader, max)).await;
    }
    let bytes = trimmed.as_bytes().to_vec();
    if bytes.len() > max {
        return Err(FrameError::Oversize(bytes.len()));
    }
    Ok(bytes)
}

async fn read_lsp_frame<R>(
    reader: &mut BufReader<R>,
    len_str: &str,
    max: usize,
) -> Result<Vec<u8>, FrameError>
where
    R: AsyncReadExt + Unpin,
{
    let len: usize = len_str
        .parse()
        .map_err(|e: std::num::ParseIntError| FrameError::BadHeader(e.to_string()))?;
    if len > max {
        return Err(FrameError::Oversize(len));
    }
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            return Err(FrameError::Eof);
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    Ok(buf)
}

pub async fn write_frame_newline<W>(writer: &mut W, body: &[u8]) -> Result<(), FrameError>
where
    W: AsyncWriteExt + Unpin,
{
    writer.write_all(body).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn newline_frame_round_trip() {
        let (mut a, b) = duplex(8192);
        a.write_all(b"{\"x\":1}\n").await.unwrap();
        let mut r = BufReader::new(b);
        let f = read_frame(&mut r, 1024).await.unwrap();
        assert_eq!(f, b"{\"x\":1}");
    }

    #[tokio::test]
    async fn lsp_frame_round_trip() {
        let (mut a, b) = duplex(8192);
        a.write_all(b"Content-Length: 7\r\n\r\n{\"x\":1}")
            .await
            .unwrap();
        let mut r = BufReader::new(b);
        let f = read_frame(&mut r, 1024).await.unwrap();
        assert_eq!(f, b"{\"x\":1}");
    }

    #[tokio::test]
    async fn rejects_oversize() {
        let (mut a, b) = duplex(8192);
        a.write_all(b"Content-Length: 100\r\n\r\n").await.unwrap();
        let mut r = BufReader::new(b);
        let err = read_frame(&mut r, 32).await.unwrap_err();
        matches!(err, FrameError::Oversize(_));
    }
}
