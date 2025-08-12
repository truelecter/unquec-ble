use std::any::Any;

// Re-export QuecTtlvCommandModel from commands module for backward compatibility
pub use crate::commands::TtlvCommandModel;

/// Type-safe TTLV value representation
#[derive(Debug, Clone)]
pub enum TTLVValue {
    None,
    Boolean(bool),
    String(String),
    Integer(i64),
    Float(f64),
    Binary(Vec<u8>),
    Struct(Vec<TTLVData>),
}

impl TTLVValue {
    /// Create TTLVValue from type_id and optional data
    pub fn from_type_id(type_id: i32, data: Option<Box<dyn Any + Send + Sync>>) -> Self {
        match type_id {
            0 | 1 => Self::Boolean(type_id == 1),
            2 => {
                if let Some(data) = data {
                    if let Some(s) = data.downcast_ref::<String>() {
                        Self::String(s.clone())
                    } else if let Some(i) = data.downcast_ref::<i64>() {
                        Self::Integer(*i)
                    } else if let Some(f) = data.downcast_ref::<f64>() {
                        Self::Float(*f)
                    } else {
                        Self::None
                    }
                } else {
                    Self::None
                }
            }
            3 | 5 => {
                if let Some(data) = data {
                    if let Some(bytes) = data.downcast_ref::<Vec<u8>>() {
                        Self::Binary(bytes.clone())
                    } else {
                        Self::None
                    }
                } else {
                    Self::None
                }
            }
            4 => {
                if let Some(data) = data {
                    if let Some(list) = data.downcast_ref::<Vec<TTLVData>>() {
                        Self::Struct(list.clone())
                    } else {
                        Self::None
                    }
                } else {
                    Self::None
                }
            }
            _ => Self::None,
        }
    }

    /// Get the type_id that corresponds to this value
    pub fn type_id(&self) -> i32 {
        match self {
            Self::None => -1,
            Self::Boolean(true) => 1,
            Self::Boolean(false) => 0,
            Self::String(_) => 2,
            Self::Integer(_) => 2,
            Self::Float(_) => 2,
            Self::Binary(_) => 3,
            Self::Struct(_) => 4,
        }
    }
}

/// Data structures for TTLV encoding
#[derive(Debug, Clone)]
pub struct TTLVData {
    pub id: i32,
    pub type_id: i32,
    pub ttlv: bool,
    pub value: TTLVValue,
}

impl TTLVData {
    pub fn new(id: i32, type_id: i32, ttlv: bool) -> Self {
        Self {
            id,
            type_id,
            ttlv,
            value: TTLVValue::None,
        }
    }

    /// Builder pattern methods for creating TTLVData with specific values
    pub fn with_boolean(mut self, value: bool) -> Self {
        self.value = TTLVValue::Boolean(value);
        self.type_id = if value { 1 } else { 0 };
        self
    }

    pub fn with_string(mut self, value: String) -> Self {
        self.value = TTLVValue::String(value);
        self.type_id = 2;
        self
    }

    pub fn with_integer(mut self, value: i64) -> Self {
        self.value = TTLVValue::Integer(value);
        self.type_id = 2;
        self
    }

    pub fn with_float(mut self, value: f64) -> Self {
        self.value = TTLVValue::Float(value);
        self.type_id = 2;
        self
    }

    pub fn with_binary(mut self, value: Vec<u8>) -> Self {
        self.value = TTLVValue::Binary(value);
        self.type_id = 3;
        self
    }

    pub fn with_struct(mut self, value: Vec<TTLVData>) -> Self {
        self.value = TTLVValue::Struct(value);
        self.type_id = 4;
        self
    }

    /// Legacy method for backward compatibility
    pub fn get_data(&self) -> Option<&Box<dyn Any + Send + Sync>> {
        None // No longer needed with type-safe enum
    }

    /// Get value as specific type
    pub fn as_boolean(&self) -> Option<bool> {
        match &self.value {
            TTLVValue::Boolean(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_string(&self) -> Option<&String> {
        match &self.value {
            TTLVValue::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_integer(&self) -> Option<i64> {
        match &self.value {
            TTLVValue::Integer(i) => Some(*i),
            _ => None,
        }
    }

    pub fn as_float(&self) -> Option<f64> {
        match &self.value {
            TTLVValue::Float(f) => Some(*f),
            _ => None,
        }
    }

    pub fn as_binary(&self) -> Option<&Vec<u8>> {
        match &self.value {
            TTLVValue::Binary(b) => Some(b),
            _ => None,
        }
    }

    pub fn as_struct(&self) -> Option<&Vec<TTLVData>> {
        match &self.value {
            TTLVValue::Struct(s) => Some(s),
            _ => None,
        }
    }
}

// QuecTtlvCommandModel moved to commands module

#[derive(Clone, Debug)]
pub struct TtlvTransparentModel {
    pub cmd: u16,
    pub packet_id: Option<i32>,
    pub payloads: Vec<u8>,
}

impl TtlvTransparentModel {
    pub fn new(cmd: u16) -> Self {
        Self {
            cmd,
            packet_id: None,
            payloads: Vec::new(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct EncodeResult {
    cmd_key: u32,
    cmd_data: Vec<u8>,
    cmd: u16,
    packet_id: u16,
}

impl EncodeResult {
    pub fn new() -> Self {
        Self {
            cmd_key: 0,
            cmd_data: Vec::new(),
            cmd: 0,
            packet_id: 0,
        }
    }

    pub fn set_cmd_key(&mut self, cmd_key: u32) {
        self.cmd_key = cmd_key;
    }

    pub fn set_cmd_data(&mut self, cmd_data: Vec<u8>) {
        self.cmd_data = cmd_data;
    }

    pub fn set_cmd(&mut self, cmd: u16) {
        self.cmd = cmd;
    }

    pub fn set_packet_id(&mut self, packet_id: u16) {
        self.packet_id = packet_id;
    }

    pub fn get_cmd_key(&self) -> u32 {
        self.cmd_key
    }

    pub fn get_cmd_data(&self) -> &Vec<u8> {
        &self.cmd_data
    }

    pub fn get_cmd(&self) -> u16 {
        self.cmd
    }

    pub fn get_packet_id(&self) -> u16 {
        self.packet_id
    }
}

#[derive(Clone, Debug)]
pub struct DoubleNeedValue {
    pub value: i64,
    pub count: usize,
}

impl DoubleNeedValue {
    pub fn new() -> Self {
        Self { value: 0, count: 0 }
    }

    pub fn set_value(&mut self, value: i64) {
        self.value = value;
    }

    pub fn set_count(&mut self, count: usize) {
        self.count = count;
    }

    pub fn get_value(&self) -> i64 {
        self.value
    }

    pub fn get_count(&self) -> usize {
        self.count
    }
}

/// Data style constants
pub mod data_style {
    pub const ARRAY: &str = "Array";
    pub const BYTE: &str = "Byte";
    pub const STRING: &str = "String";
    pub const LONG: &str = "Long";
    pub const DOUBLE: &str = "Double";
}

/// Error configuration constants
pub mod error_config {
    pub const PARAMS_DATA_ERROR: &str = "PARAMS_DATA_ERROR";
    pub const PARAMS_ERROR: &str = "PARAMS_ERROR";
}
