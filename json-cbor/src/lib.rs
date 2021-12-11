use minicbor::{
    decode::{self, Tokenizer},
    encode::{self, write::EndOfSlice, Encode, Encoder},
};
use serde_json::{Map, Value};

pub fn decode_cbor(buf: &[u8]) -> Result<Value, decode::Error> {
    let mut tokens = Tokenizer::new(buf);
    decode_cbor_inner(&mut tokens)
}

fn decode_cbor_inner(tokenizer: &mut Tokenizer) -> Result<Value, decode::Error> {
    Ok(match tokenizer.token()? {
        decode::Token::Bool(b) => Value::from(b),
        decode::Token::U8(n) => Value::from(n),
        decode::Token::U16(n) => Value::from(n),
        decode::Token::U32(n) => Value::from(n),
        decode::Token::U64(n) => Value::from(n),
        decode::Token::I8(n) => Value::from(n),
        decode::Token::I16(n) => Value::from(n),
        decode::Token::I32(n) => Value::from(n),
        decode::Token::I64(n) => Value::from(n),
        decode::Token::F16(n) => Value::from(n),
        decode::Token::F32(n) => Value::from(n),
        decode::Token::F64(n) => Value::from(n),
        decode::Token::Bytes(b) => {
            let mut buf = String::from("#");
            base64::encode_config_buf(b, base64::STANDARD, &mut buf);
            Value::String(buf)
        }
        decode::Token::String(s) => Value::from(s),
        decode::Token::Array(n) => {
            let mut result = Vec::new();
            for _ in 0..n {
                result.push(decode_cbor_inner(tokenizer)?);
            }
            Value::from(result)
        }
        decode::Token::Map(m) => {
            let mut result = Map::new();
            for _ in 0..m {
                if let Some(s) = decode_cbor_inner(tokenizer)?.as_str() {
                    result.insert(s.to_owned(), decode_cbor_inner(tokenizer)?);
                }
            }
            Value::from(result)
        }
        decode::Token::Tag(_t) => return Err(decode::Error::Message("Tag not yet supported")),
        decode::Token::Simple(_s) => {
            return Err(decode::Error::Message("Simple not yet supported"))
        }
        decode::Token::Break => return Err(decode::Error::Message("unexpected break")),
        decode::Token::Null => Value::Null,
        decode::Token::Undefined => Value::Null,
        decode::Token::BeginBytes => {
            let mut bytes = Vec::new();
            loop {
                let token = tokenizer.token()?;
                if token == decode::Token::Break {
                    break;
                }
                if let decode::Token::Bytes(b) = token {
                    bytes.extend_from_slice(b);
                }
            }
            let mut buf = String::from("#");
            base64::encode_config_buf(bytes, base64::STANDARD, &mut buf);
            Value::String(buf)
        }
        decode::Token::BeginString => {
            let mut buf = String::new();
            loop {
                let token = tokenizer.token()?;
                if token == decode::Token::Break {
                    break;
                }
                if let decode::Token::String(s) = token {
                    buf.push_str(s);
                }
            }
            Value::String(buf)
        }
        decode::Token::BeginArray => {
            let mut buf = Vec::new();
            loop {
                let mut look_ahead = tokenizer.clone();
                let token = look_ahead.token()?;
                if token == decode::Token::Break {
                    tokenizer.token()?;
                    break;
                } else {
                    buf.push(decode_cbor_inner(tokenizer)?)
                }
            }
            Value::Array(buf)
        }
        decode::Token::BeginMap => {
            let mut buf = Map::new();
            loop {
                let mut look_ahead = tokenizer.clone();
                let token = look_ahead.token()?;
                if token == decode::Token::Break {
                    tokenizer.token()?;
                    break;
                } else if let Some(s) = decode_cbor_inner(tokenizer)?.as_str() {
                    buf.insert(s.to_owned(), decode_cbor_inner(tokenizer)?);
                }
            }
            Value::Object(buf)
        }
    })
}
pub fn encode_cbor(value: &Value, buf: &mut [u8]) -> Result<usize, encode::Error<EndOfSlice>> {
    let begin = buf as *const [u8] as *const () as usize;
    let mut e = Encoder::new(buf);
    encode_cbor_inner(value, &mut e)?;
    let end = e.into_inner() as *const [u8] as *const () as usize;
    Ok(end - begin)
}
fn encode_cbor_inner<W: encode::Write>(
    value: &Value,
    e: &mut Encoder<W>,
) -> Result<(), encode::Error<W::Error>> {
    match value {
        Value::Null => {
            e.null()?;
        }
        Value::Bool(b) => {
            e.bool(*b)?;
        }
        Value::Number(n) => {
            if let Some(n) = n.as_f64() {
                e.f64(n)?;
            } else if let Some(n) = n.as_i64() {
                e.i64(n)?;
            } else {
                e.u64(n.as_u64().unwrap())?;
            }
        }
        Value::String(s) => {
            if s.starts_with('#') {
                match base64::decode(s.split_once('#').unwrap().1) {
                    Ok(bytes) => e.bytes(&bytes)?,
                    Err(_) => e.str(s)?,
                };
            } else {
                e.str(s)?;
            }
        }
        Value::Array(a) => {
            e.array(a.len() as u64)?;
            for element in a {
                encode_cbor_inner(element, e)?;
            }
        }
        Value::Object(o) => {
            e.map(o.len() as u64)?;
            for (k, v) in o {
                k.encode(e)?;
                encode_cbor_inner(v, e)?;
            }
        }
    };
    Ok(())
}

#[test]
fn test_json_cbor() -> Result<(), decode::Error> {
    let value = serde_json::json!({
       "name": "Pha",
       "map": {
           "k1": "v1",
           "k2": {
               "k1": "v1",
               "k2": "v2"
           },
           "k3": ["a", "b", "c"],
       },
       "b": "#RHVubg=="
    });

    let mut buf = [0u8; 100];
    let written = encode_cbor(&value, &mut buf).unwrap();

    let svalue: Value = decode_cbor(&buf[..written]).unwrap();
    assert_eq!(value, svalue);

    let mut t = Tokenizer::new(&buf[..written]);
    assert_eq!(t.token()?, decode::Token::Map(3));
    assert_eq!(t.token()?, decode::Token::String("b"));
    assert_eq!(t.token()?, decode::Token::Bytes(b"Dunn"));
    Ok(())
}

#[test]
fn test_indef_type() -> Result<(), encode::Error<EndOfSlice>> {
    let mut buf = [0u8; 1000];
    let begin = &buf as *const _ as *const () as usize;
    let mut encoder = Encoder::new(&mut buf[..]);

    encoder
        .begin_map()?
        .str("hello")?
        .begin_str()?
        .str("ww")?
        .str("w")?
        .str("333")?
        .end()?
        .str("aa")?
        .begin_array()?
        .str("aa")?
        .str("cc")?
        .str("bb")?
        .end()?
        .end()?
        .str("a")?;
    let end = encoder.into_inner() as *const _ as *const () as usize;

    let len = end - begin;
    let result = decode_cbor(&buf[..len]).unwrap();
    let expected = serde_json::json!({
        "hello": "www333",
        "aa": ["aa", "cc", "bb"]
    });
    assert_eq!(result, expected);
    Ok(())
}
