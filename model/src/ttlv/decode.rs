use crate::commands::TtlvCommandModel;
use crate::ttlv::model::{TTLVData, TTLVValue, TtlvTransparentModel};

/// Result of decoding TTLV data
#[derive(Debug)]
pub enum DecodeResult {
    Success(TtlvCommandModel),
    Transparent(TtlvTransparentModel),
    Incomplete, // Need more data
    Error(String),
}

/// TTLV decoding utility class
/// Note: Single channel can use singleton, multiple channels should use constructor method instantiation
pub struct DecodeTools {
    stbuf: Vec<u8>,
    receive_data: Vec<u8>,
}

impl DecodeTools {
    pub fn new() -> Self {
        Self {
            stbuf: vec![0xaa, 0xaa],
            receive_data: Vec::new(),
        }
    }

    /// Process incoming data packets and return results
    pub fn packet_slice(&mut self, data: &[u8]) -> Vec<DecodeResult> {
        let bytes = data.to_vec();
        self.receive_data.extend_from_slice(&bytes);
        self.receive_data = self.splice_buffer(&self.receive_data);

        let mut results = Vec::new();

        while !self.receive_data.is_empty() {
            if self.receive_data.len() < 9 {
                println!("Received data is too short");
                results.push(DecodeResult::Incomplete);
                return results;
            }

            if let Some(start_index) = self.find_subsequence(&self.receive_data, &self.stbuf) {
                if start_index < self.receive_data.len() {
                    // Find data field length (checksum to data field length)
                    let payload_len = if start_index + 3 < self.receive_data.len() {
                        let use_byte = [
                            self.receive_data[start_index + 2],
                            self.receive_data[start_index + 3],
                        ];
                        self.read_byte_array_short(&use_byte) as usize
                    } else {
                        0
                    };

                    println!(
                        "receive_data=[{:?}], start_index={}, payload_len={}",
                        self.receive_data.iter().map(|b| format!("0x{:02x}", b)).collect::<Vec<String>>().join(", "), start_index, payload_len
                    );

                    if self.receive_data.len() < start_index + payload_len + 4 {
                        println!(
                            "The data length is insufficient, continue to receive data, receiveData-len={}",
                            self.receive_data.len()
                        );
                        self.receive_data = self.receive_data[start_index..].to_vec();
                        results.push(DecodeResult::Incomplete);
                        return results;
                    }

                    let n_buf_copy =
                        self.receive_data[start_index..start_index + payload_len + 4].to_vec();
                    self.receive_data = self.receive_data[start_index + payload_len + 4..].to_vec();

                    match self.crc_security(&n_buf_copy) {
                        Ok(result) => results.push(result),
                        Err(e) => results.push(DecodeResult::Error(e)),
                    }
                }
            } else {
                // Didn't find packet header, check if last byte is 0xAA
                if !self.receive_data.is_empty() {
                    if self.receive_data.last() == Some(&0xaa) {
                        // Last byte might be first byte of packet header, clear previous data
                        self.receive_data = vec![0xaa];
                        results.push(DecodeResult::Incomplete);
                        return results;
                    } else {
                        // Invalid data
                        self.receive_data.clear();
                        results.push(DecodeResult::Error(
                            "Invalid data - no packet header found".to_string(),
                        ));
                        return results;
                    }
                } else {
                    // Empty data
                    self.receive_data.clear();
                    results.push(DecodeResult::Incomplete);
                    return results;
                }
            }
        }

        results
    }

    /// Check CRC and parse data, returning Result instead of using callbacks
    fn crc_security(&self, data: &[u8]) -> Result<DecodeResult, String> {
        if data.len() < 5 {
            return Err("Data too short".to_string());
        }

        let crc_buf = &data[5..];
        let n_xor = self.sum_calculation(crc_buf);
        let old_xor = data[4];

        if n_xor == old_xor {
            let packet_id = if data.len() >= 7 {
                let use_byte = [data[5], data[6]];
                self.read_byte_array_short(&use_byte)
            } else {
                0
            };

            let cmd = if data.len() >= 9 {
                let use_byte = [data[7], data[8]];
                self.read_byte_array_short(&use_byte)
            } else {
                0
            };

            if cmd == 0 || cmd == 0xffff {
                println!("=cmd 非法=");
                return Err("cmd 非法".to_string());
            }

            if cmd == 0x0024 {
                Ok(DecodeResult::Transparent(
                    self.parse_transparent_payload(data),
                ))
            } else {
                Ok(DecodeResult::Success(self.parse_payload(data)))
            }
        } else {
            println!("crc error=");
            Err("crc error".to_string())
        }
    }

    /// Parse payload into QuecTtlvCommandModel
    pub fn parse_payload(&self, data: &[u8]) -> TtlvCommandModel {
        let mut obj = TtlvCommandModel::new(0, 0);

        let packet_id = if data.len() >= 7 {
            let use_byte = [data[5], data[6]];
            self.read_byte_array_short(&use_byte)
        } else {
            0
        };

        let cmd = if data.len() >= 9 {
            let use_byte = [data[7], data[8]];
            self.read_byte_array_short(&use_byte)
        } else {
            0
        };

        obj.packet_id = packet_id;
        obj.cmd = cmd;

        // Payload container
        let mut payload_data = Vec::new();
        let payload_raw = if data.len() > 9 { &data[9..] } else { &[] };

        let payload = payload_raw.to_vec();

        if !payload.is_empty() {
            let mut offset = 0;
            while offset < payload.len() {
                if offset + 1 >= payload.len() {
                    break;
                }

                let use_short = [payload[offset], payload[offset + 1]];
                let ttlv_head = self.read_byte_array_short(&use_short);
                offset += 2;

                let ttlv_id = (ttlv_head >> 3) & 0x1fff;
                let ttlv_type = ttlv_head & 0x07;

                let mut ttlv_data = None;

                if ttlv_type == 3 || ttlv_type == 5 {
                    // Binary data
                    if let Some(p_obj) = self.parse_binary(&payload, offset) {
                        offset = p_obj.offset;
                        let mut data = TTLVData::new(ttlv_id, ttlv_type as i32, true);
                        data.value = TTLVValue::Binary(p_obj.data);
                        ttlv_data = Some(data);
                    } else {
                        offset += 2;
                        continue;
                    }
                } else if ttlv_type == 0 || ttlv_type == 1 {
                    // Boolean
                    let mut data = TTLVData::new(ttlv_id, ttlv_type as i32, true);
                    data.value = TTLVValue::Boolean(ttlv_type == 1);
                    ttlv_data = Some(data);
                } else if ttlv_type == 2 {
                    // Enum and numeric
                    if let Some(parse_num_data) = self.parse_enum_value(&payload, offset) {
                        offset = parse_num_data.offset;
                        let mut data = TTLVData::new(ttlv_id, ttlv_type as i32, true);
                        data.value = parse_num_data.value;
                        ttlv_data = Some(data);
                    }
                } else if ttlv_type == 4 {
                    // Struct
                    if let Some(parse_struct_data) = self.parse_struct(&payload, offset) {
                        offset = parse_struct_data.offset;
                        let mut data = TTLVData::new(ttlv_id, ttlv_type as i32, true);
                        data.value = TTLVValue::Struct(parse_struct_data.data);
                        ttlv_data = Some(data);
                    }
                }

                if let Some(data) = ttlv_data {
                    payload_data.push(data);
                }
            }
            obj.payloads = payload_data;
        }

        obj
    }

    /// Parse transparent payload
    pub fn parse_transparent_payload(&self, data: &[u8]) -> TtlvTransparentModel {
        let mut model = TtlvTransparentModel::new(0);

        let packet_id = if data.len() >= 7 {
            let use_byte = [data[5], data[6]];
            self.read_byte_array_short(&use_byte)
        } else {
            0
        };

        let cmd = if data.len() >= 9 {
            let use_byte = [data[7], data[8]];
            self.read_byte_array_short(&use_byte)
        } else {
            0
        };

        model.packet_id = Some(packet_id);
        model.cmd = cmd as u16;

        // Payload container
        let payload_raw = if data.len() > 9 { &data[9..] } else { &[] };

        model.payloads = payload_raw.to_vec();
        model
    }

    /// Parse struct data
    pub fn parse_struct(&self, payload: &[u8], offset: usize) -> Option<ParseStructData> {
        if offset + 1 >= payload.len() {
            return None;
        }

        let use_short = [payload[offset], payload[offset + 1]];
        let ele_num = self.read_byte_array_short(&use_short);
        let mut offset = offset + 2;

        let mut stc_elements = Vec::new();

        if ele_num > 0 {
            let mut remaining = ele_num;
            while remaining > 0 {
                if offset + 1 >= payload.len() {
                    break;
                }

                let use_short2 = [payload[offset], payload[offset + 1]];
                let ttlv_head = self.read_byte_array_short(&use_short2);
                offset += 2;

                let ttlv_id = (ttlv_head >> 3) & 0x1fff;
                let ttlv_type = ttlv_head & 0x07;

                if ttlv_type == 3 || ttlv_type == 5 {
                    // Binary data
                    if let Some(p_obj) = self.parse_binary(payload, offset) {
                        offset = p_obj.offset;
                        let mut data = TTLVData::new(ttlv_id, ttlv_type as i32, true);
                        data.value = TTLVValue::Binary(p_obj.data);
                        stc_elements.push(data);
                    } else {
                        offset += 2;
                        remaining -= 1;
                        continue;
                    }
                } else if ttlv_type == 0 || ttlv_type == 1 {
                    // Boolean
                    let mut data = TTLVData::new(ttlv_id, ttlv_type as i32, true);
                    data.value = TTLVValue::Boolean(ttlv_type == 1);
                    stc_elements.push(data);
                } else if ttlv_type == 2 {
                    // Enum and numeric
                    if let Some(parse_num_data) = self.parse_enum_value(payload, offset) {
                        offset = parse_num_data.offset;
                        let mut data = TTLVData::new(ttlv_id, ttlv_type as i32, true);
                        data.value = parse_num_data.value;
                        stc_elements.push(data);
                    }
                } else if ttlv_type == 4 {
                    // Struct
                    if let Some(parse_struct_data) = self.parse_struct(payload, offset) {
                        offset = parse_struct_data.offset;
                        let mut data = TTLVData::new(ttlv_id, ttlv_type as i32, true);
                        data.value = TTLVValue::Struct(parse_struct_data.data);
                        stc_elements.push(data);
                    }
                }

                remaining -= 1;
            }
        }

        Some(ParseStructData {
            offset,
            data: stc_elements,
        })
    }

    /// Parse binary data
    pub fn parse_binary(&self, payload: &[u8], offset: usize) -> Option<ParseBinaryData> {
        if offset + 1 >= payload.len() {
            return None;
        }

        let use_short = [payload[offset], payload[offset + 1]];
        let ttlv_len = self.read_byte_array_short(&use_short) as usize;
        let mut offset = offset + 2;

        if ttlv_len > 0 && offset + ttlv_len <= payload.len() {
            let bytes = payload[offset..offset + ttlv_len].to_vec();
            offset += ttlv_len;

            Some(ParseBinaryData {
                data: bytes,
                offset,
            })
        } else {
            None
        }
    }

    /// Parse enum value
    pub fn parse_enum_value(&self, payload: &[u8], offset: usize) -> Option<ParseNumData> {
        if offset >= payload.len() {
            return None;
        }

        let lenbuf = payload[offset];
        let mut offset = offset + 1;

        let negative = (lenbuf & 0xff) >> 7;
        let amp = (lenbuf >> 3) & 0x0f;
        let tmp_len = (lenbuf & 0x07) + 1;

        // println!("lenbuf={}, negative={}, amp={}, tmp_len={}", lenbuf, negative, amp, tmp_len);

        if offset + tmp_len as usize > payload.len() {
            return None;
        }

        let buf = payload[offset..offset + tmp_len as usize].to_vec();
        offset += tmp_len as usize;

        let enum_value = self.read_byte_array_long(&buf);

        let final_value = if negative > 0 {
            -(enum_value as i64)
        } else {
            enum_value as i64
        };

        if amp > 0 {
            // Double value
            let calc1 = final_value as f64;
            let calc2 = 10.0_f64.powi(amp as i32);
            let result = calc1 / calc2;

            Some(ParseNumData {
                value: TTLVValue::Float(result),
                offset,
            })
        } else {
            // Long value
            Some(ParseNumData {
                value: TTLVValue::Integer(final_value),
                offset,
            })
        }
    }

    /// Remove 0x55 after 0xAA from received data, then split packets
    pub fn splice_buffer(&self, bytes: &[u8]) -> Vec<u8> {
        const B_55: u8 = 0x55;
        const B_AA: u8 = 0xAA;

        let mut arr = bytes.to_vec();
        let mut i = 0;

        while i < arr.len() - 1 {
            let current = arr[i];
            let next = arr[i + 1];

            if current == B_AA && next == B_55 {
                println!("remove 55");
                arr.remove(i + 1);
            } else {
                i += 1;
            }
        }

        arr
    }

    /// Calculate checksum
    pub fn sum_calculation(&self, data: &[u8]) -> u8 {
        let mut xor = 0u8;
        for (i, &byte) in data.iter().enumerate() {
            if i == 0 {
                xor = byte;
            } else {
                xor = xor.wrapping_add(byte);
            }
        }
        xor
    }

    /// Find subsequence in data
    fn find_subsequence(&self, data: &[u8], pattern: &[u8]) -> Option<usize> {
        if pattern.len() > data.len() {
            return None;
        }

        for i in 0..=data.len() - pattern.len() {
            if data[i..i + pattern.len()] == pattern[..] {
                return Some(i);
            }
        }
        None
    }

    /// Read short from byte array
    fn read_byte_array_short(&self, data: &[u8]) -> i32 {
        if data.len() < 2 {
            return 0;
        }

        let result = ((data[0] as i32) << 8) | (data[1] as i32);
        result
    }

    /// Read long from byte array
    fn read_byte_array_long(&self, data: &[u8]) -> i64 {
        let mut padded_data = vec![0u8; 8];
        let start = 8 - data.len();
        for (i, &byte) in data.iter().enumerate() {
            padded_data[start + i] = byte;
        }

        let mut result = 0i64;
        for (i, &byte) in padded_data.iter().enumerate() {
            result |= (byte as i64) << ((7 - i) * 8);
        }
        result
    }

    /// Read int from byte array
    fn read_byte_array_int(&self, data: &[u8]) -> i32 {
        if data.len() < 4 {
            return 0;
        }

        let result = ((data[0] as i32) << 24)
            | ((data[1] as i32) << 16)
            | ((data[2] as i32) << 8)
            | (data[3] as i32);
        result
    }
}

/// Parse binary data result
pub struct ParseBinaryData {
    pub data: Vec<u8>,
    pub offset: usize,
}

/// Parse numeric data result
pub struct ParseNumData {
    pub value: TTLVValue,
    pub offset: usize,
}

/// Parse struct data result
pub struct ParseStructData {
    pub data: Vec<TTLVData>,
    pub offset: usize,
}

/// Example usage of DecodeTools with new functional approach
pub fn example_decode_usage(example_data: Vec<u8>) {
    // Create a decode tools instance
    let mut decode_tools = DecodeTools::new();

    // // Example encoded data (this would normally come from BLE)
    // let example_data = vec![
    //     0xAA, 0xAA, 0x00, 0x0B, 0x12, 0x03, 0xE8, 0x70, 0x32, 0x10, 0x01, 0x00, 0x02,
    // ];

    // let example_data = vec![
    //     0xaa, 0xaa, 0x0, 0x52, 0xd7, 0x3, 0xe8, 0x70, 0x10, 0x0, 0xb, 0x0, 0x9, 0x58, 0x61, 0x74, 0x61, 0x32, 0x39, 0x30, 0x2e, 0x32, 0x0, 0x13, 0x0, 0xb, 0x46, 0x65, 0x65, 0x64, 0x62, 0x61, 0x63, 0x63, 0x32, 0x39, 0x30, 0x0, 0x5a, 0x0, 0x78, 0x0, 0x6b, 0x0, 0x25, 0x6d, 0x71, 0x74, 0x74, 0x73, 0x3a, 0x2f, 0x2f, 0x69, 0x6f, 0x74, 0x2d, 0x73, 0x6f, 0x75, 0x74, 0x68, 0x2e, 0x61, 0x63, 0x63, 0x65, 0x6c, 0x65, 0x72, 0x6f, 0x6e, 0x69, 0x78, 0x2e, 0x69, 0x6f, 0x3a, 0x38, 0x38, 0x38, 0x36, 0x0, 0x62, 0x0, 0xff,
    // ];

    // let example_data = vec![
    //     0xaa, 0xaa, 0x0, 0x52, 0xd7, 0x3, 0xe8, 0x70, 0x10, 0x0, 0xb, 0x0, 0x9, 0x58, 0x61, 0x74, 0x61, 0x32, 0x39, 0x30, 0x2e, 0x32, 0x0, 0x13, 0x0, 0xb, 0x46, 0x65, 0x65, 0x64, 0x62, 0x61, 0x63, 0x63, 0x32, 0x39, 0x30, 0x0, 0x5a, 0x0, 0x78, 0x0, 0x6b, 0x0, 0x25, 0x6d, 0x71, 0x74, 0x74, 0x73, 0x3a, 0x2f, 0x2f, 0x69, 0x6f, 0x74, 0x2d, 0x73, 0x6f, 0x75, 0x74, 0x68, 0x2e, 0x61, 0x63, 0x63, 0x65, 0x6c, 0x65, 0x72, 0x6f, 0x6e, 0x69, 0x78, 0x2e, 0x69, 0x6f, 0x3a, 0x38, 0x38, 0x38, 0x36, 0x0, 0x62, 0x0, 0xff
    // ];

    // let example_data = vec![
    //     0xaa, 0xaa, 0x0, 0x39, 0x3f, 0x3, 0xe8, 0x70, 0x11, 0x0, 0x21, 0x0, 0x2a, 0x0, 0x1e, 0x0, 0x3b, 0x0, 0x6, 0x70,
    //     0x31, 0x31, 0x71, 0x58, 0x6f, 0x0, 0x43, 0x0, 0xc, 0x37, 0x34, 0x30, 0x37, 0x37, 0x65, 0x36, 0x37, 0x36, 0x63, 0x33,
    //     0x30, 0x0, 0x4b, 0x0, 0x10, 0x37, 0x46, 0x36, 0x39, 0x31, 0x41, 0x46, 0x31, 0x37, 0x30, 0x43, 0x37, 0x46, 0x41, 0x31,
    //     0x30
    // ];

    // let example_data = vec![
    //     0xaa, 0xaa, 0x0, 0x7, 0xb5, 0x0, 0x0, 0x70, 0x14, 0x0, 0x31
    // ];

    // let example_data = vec![
    //     0xaa, 0xaa, 0x0, 0x5, 0x6c, 0x3, 0xe8, 0x70, 0x11
    // ];

    // let example_data = vec![
    //     0xaa, 0xaa, 0x00, 0xca, 0x71, 0x03, 0xe8, 0x70, 0x13, 0x01, 0x9c, 0x00, 0x10, 0x00, 0x03, 0x00, 0x09, 0x58, 0x61, 
    //     0x74, 0x61, 0x32, 0x39, 0x30, 0x2e, 0x32, 0x00, 0x03, 0x00, 0x07, 0x63, 0x61, 0x6c, 0x79, 0x6e, 0x6b, 0x61, 0x00, 
    //     0x03, 0x00, 0x0c, 0x54, 0x50, 0x2d, 0x4c, 0x69, 0x6e, 0x6b, 0x5f, 0x41, 0x34, 0x33, 0x34, 0x00, 0x03, 0x00, 0x0c, 
    //     0x54, 0x50, 0x2d, 0x4c, 0x69, 0x6e, 0x6b, 0x5f, 0x32, 0x37, 0x34, 0x36, 0x00, 0x03, 0x00, 0x0d, 0x4d, 0x65, 0x67, 
    //     0x61, 0x57, 0x49, 0x46, 0x49, 0x5f, 0x32, 0x47, 0x48, 0x7a, 0x00, 0x03, 0x00, 0x00, 0x00, 0x03, 0x00, 0x08, 0x4e, 
    //     0x45, 0x57, 0x5f, 0x57, 0x49, 0x46, 0x49, 0x00, 0x03, 0x00, 0x0b, 0x58, 0x69, 0x61, 0x6f, 0x6d, 0x69, 0x5f, 0x39, 
    //     0x41, 0x34, 0x31, 0x00, 0x03, 0x00, 0x0e, 0x58, 0x69, 0x61, 0x6f, 0x6d, 0x69, 0x20, 0x31, 0x31, 0x20, 0x4c, 0x69, 
    //     0x74, 0x65, 0x00, 0x03, 0x00, 0x03, 0x4b, 0x4e, 0x53, 0x00, 0x03, 0x00, 0x00, 0x00, 0x03, 0x00, 0x0c, 0x54, 0x50, 
    //     0x2d, 0x4c, 0x49, 0x4e, 0x4b, 0x5f, 0x41, 0x38, 0x32, 0x38, 0x00, 0x03, 0x00, 0x00, 0x00, 0x03, 0x00, 0x08, 0x54, 
    //     0x65, 0x6e, 0x64, 0x61, 0x5f, 0x35, 0x37, 0x00, 0x03, 0x00, 0x08, 0x56, 0x65, 0x72, 0x4e, 0x65, 0x74, 0x5f, 0x32, 
    //     0x00, 0x03, 0x00, 0x0c, 0x54, 0x50, 0x2d, 0x4c, 0x49, 0x4e, 0x4b, 0x5f, 0x43, 0x41, 0x34, 0x38
    // ];

    // let example_data = vec![
    //     0xaa, 0xaa, 0x00, 0x09, 0x7d, 0x03, 0xe8, 0x70, 0x17, 0x00, 0x0a, 0x00, 0x01
    // ];
    
    // let example_data = vec![
    //     0xaa, 0xaa, 0x00, 0x49, 0x0f, 0x00, 0x01, 0x00, 0xb4, 0x00, 0x63, 0x00, 0x40, 
    //     0x54, 0x65, 0x61, 0x33, 0x63, 0x71, 0x2b, 0x53, 0x2b, 0x71, 0x48, 0x41, 0x53, 
    //     0x63, 0x45, 0x4a, 0x69, 0x49, 0x5a, 0x36, 0x66, 0x74, 0x39, 0x72, 0x32, 0x55, 
    //     0x65, 0x47, 0x64, 0x37, 0x34, 0x57, 0x79, 0x2f, 0x4b, 0x65, 0x58, 0x32, 0x4c, 
    //     0x6b, 0x66, 0x67, 0x33, 0x2f, 0x46, 0x51, 0x50, 0x75, 0x72, 0x53, 0x63, 0x42, 
    //     0x54, 0x75, 0x4f, 0x53, 0x46, 0x4a, 0x4d, 0x4a, 0x62, 0x59, 0x43, 0x70,
    // ];

    // Process data and get results
    let results = decode_tools.packet_slice(&example_data);

    fn traverse_payload(payload: &TTLVData, indent: usize) {
        let indent_str = "  ".repeat(indent);
        println!(
            "{}Payload: ID=0x{:04X}, Type={}, TTLV={}",
            indent_str,
            payload.id,
            payload.type_id,
            payload.ttlv,
        );

        // Pattern match on the value
        match &payload.value {
            TTLVValue::Boolean(b) => println!("{}  Boolean: {}", indent_str, b),
            TTLVValue::String(s) => println!("{}  String: {}", indent_str, s),
            TTLVValue::Integer(i) => println!("{}  Integer: {}", indent_str, i),
            TTLVValue::Float(f) => println!("{}  Float: {}", indent_str, f),
            TTLVValue::Binary(b) => println!("{}  Binary: {:?}, as string: {}", indent_str, b, String::from_utf8_lossy(b)),
            TTLVValue::Struct(s) => {
                println!("{}  Struct with {} items", indent_str, s.len());
                for (j, item) in s.iter().enumerate() {
                    println!("{}  Item {}: ID=0x{:04X}, Type={}, TTLV={}", indent_str, j, item.id, item.type_id, item.ttlv);
                    traverse_payload(item, indent + 1);
                }
            }
            TTLVValue::None => println!("    None"),
        }
    }

    // Handle results
    for result in results {
        match result {
            DecodeResult::Success(cmd) => {
                println!("Decoded command: 0x{:04X}", cmd.cmd);
                println!("Packet ID: {}", cmd.packet_id);
                println!("Payload count: {}", cmd.payloads.len());

                for (i, payload) in cmd.payloads.iter().enumerate() {
                    traverse_payload(payload, 0);
                }
            }
            DecodeResult::Transparent(trans) => {
                println!("Transparent command: 0x{:04X}", trans.cmd);
                println!("Transparent payload: {:?}", trans.payloads);
            }
            DecodeResult::Incomplete => {
                println!("Need more data to complete packet");
            }
            DecodeResult::Error(e) => {
                eprintln!("Decode error: {}", e);
            }
        }
    }
}

/// Example of processing multiple packets
pub fn example_multiple_packets() {
    let mut decoder = DecodeTools::new();

    // Simulate receiving data in chunks
    let chunk1 = vec![0xAA, 0xAA, 0x00, 0x0B, 0x12, 0x03, 0xE8, 0x70, 0x32];
    let chunk2 = vec![0x10, 0x01, 0x00, 0x02];

    // Process first chunk
    let results1 = decoder.packet_slice(&chunk1);
    for result in results1 {
        match result {
            DecodeResult::Incomplete => println!("First chunk incomplete, waiting for more data"),
            DecodeResult::Error(e) => println!("Error in first chunk: {}", e),
            _ => println!("Unexpected result in first chunk"),
        }
    }

    // Process second chunk
    let results2 = decoder.packet_slice(&chunk2);
    for result in results2 {
        match result {
            DecodeResult::Success(cmd) => {
                println!("Successfully decoded command: 0x{:04X}", cmd.cmd)
            }
            DecodeResult::Error(e) => println!("Error in second chunk: {}", e),
            _ => println!("Other result in second chunk"),
        }
    }
}
