use std::collections::HashMap;

use color_eyre::eyre::Result;
use tokio::io::{AsyncBufRead, AsyncBufReadExt};

/// Un bloque AMI (Response o Event) representado como mapa de headers.
/// El protocolo es texto plano: "Header: Value\r\n", bloque terminado en línea vacía.
pub type AmiMessage = HashMap<String, String>;

/// Asterisk envía una línea de banner ("Asterisk Call Manager/x.y.z\r\n") apenas se
/// conecta, antes de cualquier bloque de headers.
pub async fn read_banner<R: AsyncBufRead + Unpin>(reader: &mut R) -> Result<String> {
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

/// Lee un bloque de headers terminado en línea vacía. `Ok(None)` si la conexión
/// se cerró (EOF) antes de recibir ningún dato para un bloque nuevo.
pub async fn read_message<R: AsyncBufRead + Unpin>(reader: &mut R) -> Result<Option<AmiMessage>> {
    let mut message = AmiMessage::new();
    let mut got_any_line = false;

    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            return Ok(if got_any_line { Some(message) } else { None });
        }

        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            if got_any_line {
                return Ok(Some(message));
            }
            continue;
        }

        got_any_line = true;
        if let Some((key, value)) = trimmed.split_once(':') {
            message.insert(key.trim().to_string(), value.trim().to_string());
        }
    }
}

pub fn encode_action(fields: &[(&str, &str)]) -> String {
    let mut out = String::new();
    for (key, value) in fields {
        out.push_str(key);
        out.push_str(": ");
        out.push_str(value);
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use tokio::io::BufReader;

    #[tokio::test]
    async fn reads_banner_line() {
        let mut reader = BufReader::new(Cursor::new(b"Asterisk Call Manager/9.0.0\r\n".to_vec()));
        let banner = read_banner(&mut reader).await.unwrap();
        assert_eq!(banner, "Asterisk Call Manager/9.0.0");
    }

    #[tokio::test]
    async fn reads_single_response_block() {
        let raw =
            b"Response: Success\r\nActionID: login-1\r\nMessage: Authentication accepted\r\n\r\n"
                .to_vec();
        let mut reader = BufReader::new(Cursor::new(raw));
        let message = read_message(&mut reader).await.unwrap().unwrap();

        assert_eq!(message.get("Response").map(String::as_str), Some("Success"));
        assert_eq!(message.get("ActionID").map(String::as_str), Some("login-1"));
        assert_eq!(
            message.get("Message").map(String::as_str),
            Some("Authentication accepted")
        );
    }

    #[tokio::test]
    async fn reads_two_consecutive_blocks() {
        let raw =
            b"Response: Success\r\nActionID: a\r\n\r\nResponse: Success\r\nActionID: b\r\n\r\n"
                .to_vec();
        let mut reader = BufReader::new(Cursor::new(raw));

        let first = read_message(&mut reader).await.unwrap().unwrap();
        assert_eq!(first.get("ActionID").map(String::as_str), Some("a"));

        let second = read_message(&mut reader).await.unwrap().unwrap();
        assert_eq!(second.get("ActionID").map(String::as_str), Some("b"));
    }

    #[tokio::test]
    async fn returns_none_on_clean_eof() {
        let mut reader = BufReader::new(Cursor::new(Vec::<u8>::new()));
        let message = read_message(&mut reader).await.unwrap();
        assert!(message.is_none());
    }

    #[test]
    fn encodes_action_with_trailing_blank_line() {
        let encoded = encode_action(&[("Action", "Login"), ("Username", "admin")]);
        assert_eq!(encoded, "Action: Login\r\nUsername: admin\r\n\r\n");
    }
}
