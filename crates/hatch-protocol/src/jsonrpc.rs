use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum Id {
    Num(i64),
    Str(String),
    Null,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub jsonrpc: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<Id>,
    pub method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub jsonrpc: String,
    pub id: Id,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl Response {
    pub fn ok(id: Id, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn err(id: Id, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id,
            result: None,
            error: Some(RpcError {
                code,
                message: message.into(),
                data: None,
            }),
        }
    }
}

pub fn parse_message(bytes: &[u8]) -> Result<ParsedMessage, serde_json::Error> {
    let owned = bytes.to_vec();
    if let Ok(req) = serde_json::from_slice::<Request>(&owned) {
        if !req.jsonrpc.is_empty() {
            return Ok(ParsedMessage::Request(req));
        }
    }
    let resp: Response = serde_json::from_slice(&owned)?;
    Ok(ParsedMessage::Response(resp))
}

#[derive(Debug, Clone)]
pub enum ParsedMessage {
    Request(Request),
    Response(Response),
}

impl ParsedMessage {
    pub fn is_tool_call(&self) -> bool {
        matches!(self, ParsedMessage::Request(r) if r.method == "tools/call")
    }

    pub fn tool_call_name(&self) -> Option<&str> {
        match self {
            ParsedMessage::Request(r) if r.method == "tools/call" => r
                .params
                .as_ref()
                .and_then(|p| p.get("name"))
                .and_then(|v| v.as_str()),
            _ => None,
        }
    }

    pub fn tool_call_args(&self) -> Value {
        match self {
            ParsedMessage::Request(r) if r.method == "tools/call" => r
                .params
                .as_ref()
                .and_then(|p| p.get("arguments"))
                .cloned()
                .unwrap_or(Value::Null),
            _ => Value::Null,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_tools_call() {
        let raw = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "create_issue",
                "arguments": {"repo": "user/repo", "title": "hi"}
            }
        }))
        .unwrap();
        let msg = parse_message(&raw).unwrap();
        assert!(msg.is_tool_call());
        assert_eq!(msg.tool_call_name(), Some("create_issue"));
        assert_eq!(msg.tool_call_args()["repo"], "user/repo");
    }

    #[test]
    fn parses_response_with_string_id() {
        let raw = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": "abc",
            "result": {"ok": true}
        }))
        .unwrap();
        let msg = parse_message(&raw).unwrap();
        match msg {
            ParsedMessage::Response(r) => assert_eq!(r.id, Id::Str("abc".into())),
            _ => panic!("expected response"),
        }
    }
}
