use unquec_model::{
    commands::{Cmd, IotCmd, TtlvCommandModel},
    quec_ble_device::QuecBLEDevice,
    ttlv::{
        decode::{DecodeResult, DecodeTools},
        encode::EncodeTools,
        model::{TTLVData, TTLVValue},
    },
};

use base64::{Engine as _, engine::general_purpose::STANDARD as b64};
 

fn main() {
    let mut encoder = EncodeTools::new();
    
    let mut something = TtlvCommandModel::new(0x00B4, 1);
    something.add_payload(TTLVData::new(0x000C, 3, true).with_binary(b64.encode([b'a';48]).as_bytes().to_vec()));
    
    let result = encoder.start_encode(&something);
    let result = result.get_cmd_data();

    println!("result: {}", result.iter().map(|b| format!("\\x{:02x}", b)).collect::<Vec<String>>().join(""));

    // unquec_model::ttlv::encode::example_encode_usage(example_data);
}

