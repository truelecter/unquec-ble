use crate::commands::TtlvCommandModel;
use crate::ttlv::model::{
    DoubleNeedValue, EncodeResult, TTLVData, TTLVValue, TtlvTransparentModel,
};

/// TTLV encoding utility class
pub struct EncodeTools {
    packet_id: u16,
}

impl EncodeTools {
    pub fn new() -> Self {
        Self { packet_id: 0 }
    }

    pub fn get_packet_id(&self) -> u16 {
        self.packet_id
    }

    /// Start encoding TTLV command model
    pub fn start_encode(&mut self, model: &TtlvCommandModel) -> EncodeResult {
        self.start_encode_with_packet_id(model, false)
    }

    /// Encode to TTLV format
    /// @param model QuecTtlvCommandModel
    /// @param is_use_packet_id Whether to use QuecTtlvCommandModel's PacketId
    /// @return EncodeResult
    pub fn start_encode_with_packet_id(
        &mut self,
        model: &TtlvCommandModel,
        is_use_packet_id: bool,
    ) -> EncodeResult {
        let payloads = &model.payloads;
        let cmd = model.cmd as u16;
        let mut result = EncodeResult::new();
        let payload_raw;

        if cmd == 0x0011 {
            payload_raw = self.encode_read_payload_to_buffer(payloads);
        } else {
            payload_raw = self.encode_payload_to_buffer(payloads);
        }

        let payload = payload_raw; // No encryption in Rust version
        let length = 9 + payload.len();
        let mut cmd_data = vec![0u8; length];
        cmd_data[0] = 0xaa;
        cmd_data[1] = 0xaa;
        let length2 = 5 + payload.len();
        // Data field length
        cmd_data[2] = ((length2 >> 8) & 0xff) as u8;
        cmd_data[3] = (length2 & 0xff) as u8;
        let packet_id = if is_use_packet_id {
            (model.packet_id & 0xFFFF) as u16
        } else {
            self.get_serial_num()
        };
        cmd_data[5] = ((packet_id >> 8) & 0xff) as u8;
        cmd_data[6] = (packet_id & 0xff) as u8;
        cmd_data[7] = ((cmd >> 8) & 0xff) as u8;
        cmd_data[8] = (cmd & 0xff) as u8;

        if payload.len() > 0 {
            for (i, &byte) in payload.iter().enumerate() {
                cmd_data[9 + i] = byte;
            }
        }

        let valid_array = &cmd_data[5..];
        cmd_data[4] = self.sum_calculation(valid_array);
        let data = self.garble_buffer(&cmd_data);
        let ckey = (cmd as u32) << 16 | packet_id as u32;

        result.set_cmd_key(ckey);
        result.set_cmd_data(data);
        result.set_cmd(cmd);
        result.set_packet_id(packet_id);
        result
    }

    pub fn start_encode_transparent(&mut self, model: &TtlvTransparentModel) -> EncodeResult {
        let payload_raw = &model.payloads;
        let payload = payload_raw.clone(); // No encryption in Rust version

        let package_id = model.packet_id;
        let cmd = model.cmd;

        let length = 9 + payload.len();
        let mut cmd_data = vec![0u8; length];
        cmd_data[0] = 0xaa;
        cmd_data[1] = 0xaa;
        let length2 = 5 + payload.len();
        // Data field length
        cmd_data[2] = ((length2 >> 8) & 0xff) as u8;
        cmd_data[3] = (length2 & 0xff) as u8;
        let packet_id = if let Some(id) = package_id {
            (id & 0xFFFF) as u16
        } else {
            self.get_serial_num()
        };
        cmd_data[5] = ((packet_id >> 8) & 0xff) as u8;
        cmd_data[6] = (packet_id & 0xff) as u8;
        cmd_data[7] = ((cmd >> 8) & 0xff) as u8;
        cmd_data[8] = (cmd & 0xff) as u8;

        if payload.len() > 0 {
            cmd_data[9..9 + payload.len()].copy_from_slice(&payload);
        }

        let valid_array = &cmd_data[5..];
        cmd_data[4] = self.sum_calculation(valid_array);
        let data = self.garble_buffer(&cmd_data);
        let c_key = (cmd as u32) << 16 | packet_id as u32;

        let mut result = EncodeResult::new();
        result.set_cmd_key(c_key);
        result.set_cmd_data(data);
        result.set_cmd(cmd);
        result.set_packet_id(packet_id);
        result
    }

    /// Prevent conflicts with packet header, this method checks the encapsulated instruction
    /// and inserts 0x55 for data like 0xAA55, 0xAAAA except the packet header
    pub fn garble_buffer(&self, data: &[u8]) -> Vec<u8> {
        let mut count = 2;
        let mut bytes = data.to_vec();
        let mut arr = bytes.clone();
        const B_55: u8 = 0x55;
        const B_AA: u8 = 0xAA;

        while count < arr.len() - 1 {
            let current = arr[count];
            let next = arr[count + 1];

            if (current == B_AA && next == B_55) || (current == B_AA && next == B_AA) {
                println!("add 55");
                arr.insert(count + 1, B_55);
                count += 1;
            }
            count += 1;
        }
        arr
    }

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

    pub fn get_serial_num(&mut self) -> u16 {
        self.packet_id += 1;
        if self.packet_id < 1000 || self.packet_id >= 0xffff {
            self.packet_id = 1000;
        }
        self.packet_id
    }

    pub fn encode_read_payload_to_buffer(&self, payloads: &[TTLVData]) -> Vec<u8> {
        let mut buf = Vec::new();
        for obj in payloads {
            let byte_by_short = self.get_byte_by_short(obj.id);
            buf.extend_from_slice(&byte_by_short);
        }
        buf
    }

    pub fn encode_payload_to_buffer(&self, payloads: &[TTLVData]) -> Vec<u8> {
        let mut buf = Vec::new();
        for obj in payloads {
            if !obj.ttlv {
                let byte_by_short = self.get_byte_by_short(obj.id);
                buf.extend_from_slice(&byte_by_short);
            } else {
                // 13 data identifier + data type 3 + length + value
                let ttlv_id = obj.id as u16;
                let ttlv_type = obj.type_id as u16;
                let ttlv_header = ((ttlv_id << 3) & 0xFFF8) + (ttlv_type & 0x07);
                let header_buf_sec = self.get_byte_by_short(ttlv_header as i32);
                buf.extend_from_slice(&header_buf_sec);

                match &obj.value {
                    TTLVValue::Binary(_) | TTLVValue::None => {
                        // Binary data or None - encode as binary
                        let bytes = self.encode_binary(obj);
                        buf.extend_from_slice(&bytes);
                    }
                    TTLVValue::Boolean(_) => {
                        // Boolean - no additional data needed
                    }
                    TTLVValue::String(_) | TTLVValue::Integer(_) | TTLVValue::Float(_) => {
                        // Enum values
                        let bytes = self.encode_enum_value(obj);
                        buf.extend_from_slice(&bytes);
                    }
                    TTLVValue::Struct(_) => {
                        // Struct
                        buf.extend(self.encode_struct_payload(obj));
                    }
                }
            }
        }
        buf
    }

    fn encode_struct_payload(&self, obj: &TTLVData) -> Vec<u8> {
        let mut buf = Vec::new();
        let payloads = match &obj.value {
            TTLVValue::Struct(list) => list,
            _ => &Vec::new(),
        };

        let ttlv_id = obj.id as u16;
        let ttlv_type = obj.type_id as u16;
        let ttlv_header = ((ttlv_id << 3) & 0xFFF8) + (ttlv_type & 0x07);
        let header_buf_sec = self.get_byte_by_short(ttlv_header as i32);
        buf.extend_from_slice(&header_buf_sec);

        // Add struct protocol Length element count 2B
        let byte_by_short = self.get_byte_by_short(payloads.len() as i32);
        buf.extend_from_slice(&byte_by_short);

        for obj_sec in payloads {
            if !obj_sec.ttlv {
                // Skip non-TTLV data
            } else {
                // 13 data identifier + data type 3 + length + value
                let ttlv_id_sec = obj_sec.id as u16;
                let ttlv_type_sec = obj_sec.type_id as u16;
                let ttlv_header_sec = ((ttlv_id_sec << 3) & 0xFFF8) + (ttlv_type_sec & 0x07);
                let header_buf_sec_sec = self.get_byte_by_short(ttlv_header_sec as i32);
                buf.extend_from_slice(&header_buf_sec_sec);

                match &obj_sec.value {
                    TTLVValue::Binary(_) => {
                        // Binary
                        let bytes = self.encode_binary(obj_sec);
                        buf.extend_from_slice(&bytes);
                    }
                    TTLVValue::Boolean(_) => {
                        // Boolean - no additional data needed
                    }
                    TTLVValue::String(_) | TTLVValue::Integer(_) | TTLVValue::Float(_) => {
                        // Encapsulated enum
                        let bytes = self.encode_enum_value(obj_sec);
                        buf.extend_from_slice(&bytes);
                    }
                    TTLVValue::Struct(_) => {
                        buf.extend(self.encode_struct_payload(obj_sec));
                    }
                    TTLVValue::None => {
                        // Skip None values
                    }
                }
            }
        }
        buf
    }

    fn get_byte_by_short(&self, value: i32) -> Vec<u8> {
        let mut result = Vec::new();
        result.push(((value >> 8) & 0xff) as u8);
        result.push((value & 0xff) as u8);
        result
    }

    fn get_byte_by_long(&self, value: i64) -> Vec<u8> {
        let mut result = Vec::new();
        for i in 0..8 {
            result.push(((value >> (i * 8)) & 0xff) as u8);
        }
        result.reverse();
        result
    }

    fn encode_binary(&self, obj: &TTLVData) -> Vec<u8> {
        match &obj.value {
            TTLVValue::Binary(bytes) => {
                let byte_by_short = self.get_byte_by_short(bytes.len() as i32);
                let mut result = Vec::new();
                result.extend_from_slice(&byte_by_short);
                result.extend_from_slice(bytes);
                result
            }
            _ => {
                // For None or other types, return empty
                Vec::new()
            }
        }
    }

    fn encode_enum_value(&self, obj: &TTLVData) -> Vec<u8> {
        match &obj.value {
            TTLVValue::String(s) => {
                if s.contains('.') {
                    self.get_double_result(s)
                } else {
                    self.get_long_result(s)
                }
            }
            TTLVValue::Integer(i) => self.get_long_result(&i.to_string()),
            TTLVValue::Float(f) => self.get_double_result(&f.to_string()),
            _ => Vec::new(),
        }
    }

    fn get_long_result(&self, data: &str) -> Vec<u8> {
        let value = data.parse::<i64>().unwrap();
        let mut one_byte = vec![0u8; 1];

        let (sign, abs_value) = if value < 0 {
            one_byte[0] = 0x01 << 7;
            (true, -value)
        } else {
            one_byte[0] = 0;
            (false, value)
        };

        let mut parm_buf = if abs_value != 0 {
            self.long_to_byte_array_big_endian(abs_value)
        } else {
            vec![0x00]
        };

        one_byte[0] |= (parm_buf.len() - 1) as u8;
        let mut result = Vec::new();
        result.extend_from_slice(&one_byte);
        result.extend_from_slice(&parm_buf);
        result
    }

    fn get_double_result(&self, data: &str) -> Vec<u8> {
        let value = data.parse::<f64>().unwrap();
        let mut one_byte = vec![0u8; 1];

        let (sign, abs_value) = if value < 0.0 {
            one_byte[0] = 0x01 << 7;
            (true, -value)
        } else {
            one_byte[0] = 0;
            (false, value)
        };

        let double_need_value = self.extract_double(abs_value);
        let mut parm_buf = self.long_to_byte_array_big_endian(double_need_value.value);
        let count = double_need_value.count;
        one_byte[0] |= (count << 3) as u8;
        one_byte[0] |= (parm_buf.len() - 1) as u8;

        let mut result = Vec::new();
        result.extend_from_slice(&one_byte);
        result.extend_from_slice(&parm_buf);
        result
    }

    fn u64_buffer(&self, value: i64) -> Vec<u8> {
        let byte_by_long = self.get_byte_by_long(value);
        byte_by_long
    }

    /// Convert long to byte array, big endian
    fn long_to_byte_array_big_endian(&self, l: i64) -> Vec<u8> {
        let mut valid_byte_list = Vec::new();
        if l == 0 {
            valid_byte_list.push(0);
            return valid_byte_list;
        }

        let mut array = vec![0u8; 8];
        for i in 0..array.len() {
            let idx = array.len() - 1 - i;
            array[idx] = ((l >> (i * 8)) & 0xFF) as u8;
        }

        let mut is_valid_data = false;
        for &b in &array {
            if is_valid_data {
                valid_byte_list.push(b);
            } else {
                if (b & 0xFF) > 0 {
                    is_valid_data = true;
                    valid_byte_list.push(b);
                }
            }
        }
        valid_byte_list
    }

    fn extract_double(&self, value: f64) -> DoubleNeedValue {
        let mut result = DoubleNeedValue::new();

        let str = format!("{:.15}", value);
        let str = str.replace(",", ".");
        let parts: Vec<&str> = str.split('.').collect();

        if parts.len() == 1 {
            let last = parts[0];
            let need_value = last.parse::<i64>().unwrap();
            result.set_value(need_value);
            result.set_count(0);
        } else {
            let value2 = parts[1];
            let num_value = value2.parse::<i64>().unwrap();
            if num_value <= 0 {
                panic!("PARAMS_ERROR");
            }
            let t = value2.trim_end_matches('0');
            let last = format!("{}{}", parts[0], t);
            let need_value = last.parse::<i64>().unwrap();
            result.set_value(need_value);
            result.set_count(t.len());
        }
        result
    }
}

/// Example usage of TTLV encoding utility
pub fn example_usage() {
    // Create a command model (equivalent to Java: QuecTtlvCommandModel commandModel = new QuecTtlvCommandModel();)
    let mut command_model = TtlvCommandModel::new(0x7032, 0);

    // Create payloads (equivalent to Java: List<TTLVData> payLoads = new ArrayList<TTLVData>();)
    let mut payloads = Vec::new();

    // Example 1: Add a simple TTLV data (non-TTLV)
    let simple_data = TTLVData::new(0x1001, 0, false);
    payloads.push(simple_data);

    // Example 2: Add a boolean TTLV data using builder pattern
    let bool_data = TTLVData::new(0x1002, 0, true).with_boolean(true);
    payloads.push(bool_data);

    // Example 3: Add a string enum TTLV data using builder pattern
    let string_data = TTLVData::new(0x1003, 2, true).with_string("Hello World".to_string());
    payloads.push(string_data);

    // Example 4: Add a numeric enum TTLV data using builder pattern
    let numeric_data = TTLVData::new(0x1004, 2, true).with_integer(42);
    payloads.push(numeric_data);

    // Example 5: Add a double enum TTLV data using builder pattern
    let double_data = TTLVData::new(0x1005, 2, true).with_float(3.14159);
    payloads.push(double_data);

    // Example 6: Add binary TTLV data using builder pattern
    let binary_data = TTLVData::new(0x1006, 3, true).with_binary(vec![0x01, 0x02, 0x03, 0x04]);
    payloads.push(binary_data);

    // Example 7: Add a struct TTLV data (nested structure) using builder pattern
    let mut nested_payloads = Vec::new();

    // Add nested data to struct
    let nested_string = TTLVData::new(0x2001, 2, true).with_string("Nested String".to_string());
    nested_payloads.push(nested_string);

    let nested_number = TTLVData::new(0x2002, 2, true).with_integer(123);
    nested_payloads.push(nested_number);

    let struct_data = TTLVData::new(0x1007, 4, true).with_struct(nested_payloads);
    payloads.push(struct_data);

    // Set the payloads to the command model
    command_model.payloads = payloads;

    // Create encoder and encode the command
    let mut encoder = EncodeTools::new();
    let result = encoder.start_encode(&command_model);

    // Print the results
    println!("Command Key: 0x{:08X}", result.get_cmd_key());
    println!("Command: 0x{:04X}", result.get_cmd());
    println!("Packet ID: {}", result.get_packet_id());
    println!("Encoded Data: {:?}", result.get_cmd_data());
}

/// Example of transparent model usage
pub fn example_transparent_usage() {
    // Create a transparent model
    let mut transparent_model = TtlvTransparentModel::new(0x8001);
    transparent_model.payloads = vec![0x01, 0x02, 0x03, 0x04, 0x05];

    // Create encoder and encode the transparent model
    let mut encoder = EncodeTools::new();
    let result = encoder.start_encode_transparent(&transparent_model);

    // Print the results
    println!("Transparent Command Key: 0x{:08X}", result.get_cmd_key());
    println!("Transparent Command: 0x{:04X}", result.get_cmd());
    println!("Transparent Packet ID: {}", result.get_packet_id());
    println!("Transparent Encoded Data: {:?}", result.get_cmd_data());
}

/// Example of read command (cmd = 0x0011)
pub fn example_read_command() {
    // Create a read command model
    let mut read_model = TtlvCommandModel::new(0x0011, 0);

    // Add read payloads (just IDs, no data)
    let mut read_payloads = Vec::new();
    read_payloads.push(TTLVData::new(0x1001, 0, false));
    read_payloads.push(TTLVData::new(0x1002, 0, false));
    read_payloads.push(TTLVData::new(0x1003, 0, false));

    read_model.payloads = read_payloads;

    // Create encoder and encode the read command
    let mut encoder = EncodeTools::new();
    let result = encoder.start_encode(&read_model);

    // Print the results
    println!("Read Command Key: 0x{:08X}", result.get_cmd_key());
    println!("Read Command: 0x{:04X}", result.get_cmd());
    println!("Read Packet ID: {}", result.get_packet_id());
    println!("Read Encoded Data: {:?}", result.get_cmd_data());
}
