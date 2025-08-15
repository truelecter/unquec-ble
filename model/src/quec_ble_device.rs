use std::io::{BufRead, Cursor, Read};
use byteorder::{BigEndian, ReadBytesExt};

pub struct QuecBLEDevice {
    pub id: String,
    pub name: String,
    pub version: u16,
    pub product_key: String,
    pub device_key: String,
    pub mac: String,
    pub device_status: u8,
    pub tag: String,
    pub is_cl_dk: bool,
    pub is_wifi_config: bool,
    pub is_bind: bool,
    pub is_enable_bind: bool,
    pub capabilities_bitmask: u16,
    pub endpoint_type: u8,
    pub is_old_device: bool,
}

#[derive(Debug)]
pub enum QuecBLEDeviceDecodeError {
    DataTooShort,
    InvalidHeader(u16),
    DecodeFailed(String),
    InsufficientFieldData(String, u8)
}

impl From<std::io::Error> for QuecBLEDeviceDecodeError {
    fn from(error: std::io::Error) -> Self {
        match error.kind() {
            std::io::ErrorKind::UnexpectedEof => QuecBLEDeviceDecodeError::DataTooShort,
            _ => QuecBLEDeviceDecodeError::DecodeFailed(error.to_string()),
        }
    }
}

impl QuecBLEDevice {
    // Try to decode the manufacturer data into a QuecBLEDevice
    // This function expects the manufacturer data of the device with id 0x55_51 (QU)
    pub fn decode_data(manufacturer_data: &Vec<u8>) -> Result<Self, QuecBLEDeviceDecodeError> {
        // Broadcast data length insufficient. This appears 
        if manufacturer_data.len() < 19 {
            return Err(QuecBLEDeviceDecodeError::DataTooShort); 
        }

        let mut ret: QuecBLEDevice;

        let mut cursor = Cursor::new(manufacturer_data);

        let header = cursor.read_u16::<BigEndian>()?;

        if header != 0x69_67 {
            return Err(QuecBLEDeviceDecodeError::InvalidHeader(header));
        }

        let version = cursor.read_u16::<BigEndian>()?;

        let pk = String::from_utf8_lossy(&read_field(&mut cursor)?).to_string();
        let mut dk = bytes_to_hex_string(&read_field(&mut cursor)?);

        let status = cursor.read_u8()?;
        let flags = match cursor.read_u16::<BigEndian>() {
            Ok(flags) => flags,
            Err(_) => 0,
        };

        if (flags >> 8) & 0x1 == 0x1 {
            dk = dk[..dk.len() - 1].to_string();
        }

        if (flags >> 12) & 0x1 == 0x1 {
            dk = dk.to_uppercase();
        }

        return Ok(QuecBLEDevice {
            id: String::new(),
            name: String::new(),
            mac: String::new(),
            tag: "QUEC".to_string(),

            version: version,
            product_key: pk,
            device_key: dk,
            device_status: status,
            capabilities_bitmask: flags,
            is_cl_dk: check_bit_value(flags, 0),
            is_wifi_config: check_bit_value(flags, 1),
            is_bind: check_bit_value(flags, 2),
            is_enable_bind: check_bit_value(flags, 3),
            endpoint_type: ((flags >> 4) & 0x0F) as u8,
            is_old_device: check_bit_value(flags, 8),
        });
    }

}

fn check_bit_value(value: u16, bit: u8) -> bool {
    ((value >> bit) & 0x01) == 0x01
}

fn bytes_to_hex_string(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<String>>()
        .join("")
}

fn read_field(cursor: &mut Cursor<&Vec<u8>>) -> Result<Vec<u8>, std::io::Error> {
    let len = cursor.read_u8()?;

    let mut data = vec![0 as u8; len as usize];
    cursor.read_exact(&mut data)?;

    Ok(data)
}
