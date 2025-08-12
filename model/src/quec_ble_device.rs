pub struct QuecBLEDevice {
    pub id: String,
    pub name: String,
    pub version: String,
    pub product_key: String,
    pub device_key: String,
    pub mac: String,
    pub device_status: i32,
    pub tag: String,
    pub is_cl_dk: bool,
    pub is_wifi_config: bool,
    pub is_bind: bool,
    pub is_enable_bind: bool,
    pub capabilities_bitmask: i32,
    pub endpoint_type: i32,
    pub is_old_device: bool,
    pub data: Vec<u8>,
}

impl QuecBLEDevice {
    pub fn decode_data(manufacturer_data: &Vec<u8>) -> Result<Self, String> {
        // Broadcast data length insufficient, return empty result
        if manufacturer_data.len() < 19 {
            return Err("Data too short".to_string());
        }

        let mut ret: QuecBLEDevice;

        let data = &manufacturer_data[2..];

        println!("Data to parse {:?}", data);

        match std::panic::catch_unwind(|| {
            let version = Self::combine_bytes_to_short(data[0], data[1]);
            let pk_length = data[2] as usize;
            let pk = String::from_utf8_lossy(&data[3..3 + pk_length]).to_string();
            let dk_length = data[3 + pk_length] as usize;
            let dk_start = 4 + pk_length;
            let dk_end = dk_start + dk_length;
            let mut dk = Self::bytes_to_hex_string(&data[dk_start..dk_end]);

            let status = data[4 + pk_length + dk_length] as i32;
            let flags = if data.len() >= 6 + pk_length + dk_length {
                Self::combine_bytes_to_short(
                    data[6 + pk_length + dk_length],
                    data[5 + pk_length + dk_length],
                )
            } else {
                0
            };

            // bit8=1 means dk was padded with a "0" before encoding,
            // receiver should trim the final "0" after decoding
            if Self::check_byte_value(flags, 8) && dk.ends_with('0') {
                dk = dk[..dk.len() - 1].to_string();
            }

            // bit12=1 means the obtained DK is all uppercase
            if Self::check_byte_value(flags, 12) {
                dk = dk.to_uppercase();
            }

            QuecBLEDevice {
                id: String::new(),   // Will be set later
                name: String::new(), // Will be set later
                version: version.to_string(),
                product_key: pk,
                device_key: dk,
                mac: String::new(), // Will be set later
                device_status: status,
                tag: "QUEC".to_string(),
                is_cl_dk: false,       // Will be set based on flags
                is_wifi_config: false, // Will be set based on flags
                is_bind: false,        // Will be set based on flags
                is_enable_bind: false, // Will be set based on flags
                capabilities_bitmask: flags,
                endpoint_type: 0,     // Will be set based on flags
                is_old_device: false, // Will be set based on flags
                data: data.to_vec(),
            }
        }) {
            Ok(device) => {
                ret = device;
                // Set additional fields based on flags
                ret.is_cl_dk = Self::check_byte_value(ret.capabilities_bitmask, 0);
                ret.is_wifi_config = Self::check_byte_value(ret.capabilities_bitmask, 1);
                ret.is_bind = Self::check_byte_value(ret.capabilities_bitmask, 2);
                ret.is_enable_bind = Self::check_byte_value(ret.capabilities_bitmask, 3);
                ret.endpoint_type = (ret.capabilities_bitmask >> 4) & 0x0F;
                ret.is_old_device = Self::check_byte_value(ret.capabilities_bitmask, 8);

                Ok(ret)
            }
            Err(_) => Err(format!(
                "Decode failed for data: {}",
                Self::bytes_to_hex_string(data)
            )),
        }
    }

    fn combine_bytes_to_short(high: u8, low: u8) -> i32 {
        ((high as i32) << 8) | ((low as i32) & 0xFF)
    }

    fn check_byte_value(value: i32, bit: i32) -> bool {
        ((value >> bit) & 0x01) == 0x01
    }

    fn bytes_to_hex_string(bytes: &[u8]) -> String {
        bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<String>>()
            .join("")
    }
}
