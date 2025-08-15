use bluer::{
    AdapterEvent, Address, Device, DiscoveryFilter, DiscoveryTransport, Result,
    gatt::{
        WriteOp,
        remote::{Characteristic, CharacteristicWriteRequest},
    },
};
use futures::{StreamExt, pin_mut};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::time::sleep;
use uuid::Uuid;

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



fn try_get_quec_device(
    name: &Option<String>,
    address: &Address,
    manufacturer_data: &HashMap<u16, Vec<u8>>,
) -> Option<QuecBLEDevice> {
    match manufacturer_data.get(&0x55_51 /* QU */) {
        Some(d) => {
            if !(d.len() >= 19 && d[0] == b'E' && d[1] == b'C') {
                return None;
            };

            match QuecBLEDevice::decode_data(&d) {
                Ok(mut quec_device) => {
                    if name.is_some() {
                        quec_device.name = name.clone().unwrap();
                    }

                    quec_device.mac = address.to_string();

                    return Some(quec_device);
                }

                Err(err) => {
                    println!("Error decoding manufacturer data: {:?}", &err);
                    return None;
                }
            }
        }
        _ => {
            return None;
        }
    };
}

async fn connect_to_device(device: &Device) -> Result<()> {
    if !device.is_connected().await? {
        println!("    Connecting...");
        let mut retries = 2;
        loop {
            match device.connect().await {
                Ok(()) => break,
                Err(err) if retries > 0 => {
                    println!("    Connect error: {}", &err);
                    retries -= 1;
                }
                Err(err) => return Err(err),
            }
        }
        println!("    Connected");
    } else {
        println!("    Already connected");
    }

    return Ok(());
}

const SERVICE_UUID: Uuid = Uuid::from_u128(0x00000180_a000_1000_8000_00805f9b34fb);
const CHARACTERISTIC_UUID: Uuid = Uuid::from_u128(0x00009c40_0000_1000_8000_00805f9b34fb);

const CHARACTERISTIC_UUID_2: Uuid = Uuid::from_u128(0x00002902_0000_1000_8000_00805f9b34fb);

async fn find_our_characteristic(device: &Device) -> Result<Option<Characteristic>> {
    let addr = device.address();
    let uuids = device.uuids().await?.unwrap_or_default();
    println!("Discovered device {} with service UUIDs {:?}", addr, &uuids);
    println!("    Enumerating services...");

    let mut retries = 2;
    let mut services = Vec::new();

    loop {
        match device.services().await {
            Ok(s) => {
                services.extend(s);
                break;
            }
            Err(err) if retries > 0 => {
                println!("    Services error: {}", &err);
                sleep(Duration::from_secs(1)).await;
                retries -= 1;
            }
            Err(err) => return Err(err),
        }
    }

    for service in services {
        let uuid = service.uuid().await?;
        println!("    Service UUID: {}", &uuid);

        for char in service.characteristics().await? {
            let uuid = char.uuid().await?;
            println!("    Characteristic UUID: {}", &uuid);
            println!(
                "    Characteristic data: {:?}",
                char.all_properties().await?
            );

            if uuid == CHARACTERISTIC_UUID {
                println!("    Found our characteristic!");
                return Ok(Some(char));
            }
        }
    }

    println!("    Not found!");

    Ok(None)
}

async fn write_to_characteristic(characteristic: &Characteristic, data: &[u8]) -> Result<()> {
    let mut retries = 2;

    loop {
        match characteristic
            .write_ext(
                data,
                &CharacteristicWriteRequest {
                    offset: 0,
                    op_type: WriteOp::Request,
                    prepare_authorize: false,
                    _non_exhaustive: (),
                },
            )
            .await
        {
            Ok(()) => return Ok(()),
            Err(err) if retries > 0 => {
                println!("Write failed: {}", &err);
                sleep(Duration::from_secs(1)).await;
                retries -= 1;
            }
            Err(err) => return Err(err),
        }
    }
}

async fn writre_random_command(
    our_characteristic: &Characteristic,
    encode_tools: &mut EncodeTools,
) -> Result<()> {
    println!("Trying writing random command...");

    let command_model = TtlvCommandModel::new(Cmd::Random.as_i32(), 0);

    write_to_characteristic(
        &our_characteristic,
        encode_tools.start_encode(&command_model).get_cmd_data(),
    )
    .await
}

async fn write_login_command(
    our_characteristic: &Characteristic,
    encode_tools: &mut EncodeTools,
    random_value: String,
    binding_key: String,
) -> Result<()> {
    println!("Trying writing login command...");

    let bk = bytes_to_hex_str(b64.decode(binding_key).unwrap().as_slice());
    println!("  bk: {:?}", bk);

    let params = bk + ";" + &random_value;

    let value = digest(&params);

    println!("  params: {:?}", params);
    println!("  value: {:?}", value);

    let mut login_model = TtlvCommandModel::new(Cmd::Login.as_i32(), 1001);
    login_model.add_payload(TTLVData::new(2, 3, true).with_binary(value.as_bytes().to_vec()));

    write_to_characteristic(
        &our_characteristic,
        encode_tools
            .start_encode_with_packet_id(&login_model, true)
            .get_cmd_data(),
    )
    .await
}

async fn write_pure_login_command(
    our_characteristic: &Characteristic,
    encode_tools: &mut EncodeTools,
) -> Result<()> {
    println!("Trying writing pure login command...");

    let mut login_model = TtlvCommandModel::new(Cmd::BLEAccountAuthentication.as_i32(), 1001);

    login_model.add_payload(TTLVData::new(1, 2, true).with_integer(1));

    write_to_characteristic(
        &our_characteristic,
        encode_tools
            .start_encode_with_packet_id(&login_model, true)
            .get_cmd_data(),
    )
    .await
}

async fn write_wifi_pair_command(
    our_characteristic: &Characteristic,
    encode_tools: &mut EncodeTools,
) -> Result<()> {
    println!("Trying writing wifi pair command...");

    let mut wifi_pair_model = TtlvCommandModel::new(Cmd::WifiPair.as_i32(), 1001);

    wifi_pair_model
        .add_payload(TTLVData::new(1, 3, true).with_binary("Xata290.2".as_bytes().to_vec()));
    wifi_pair_model
        .add_payload(TTLVData::new(2, 3, true).with_binary("Feedbacc290".as_bytes().to_vec()));
    wifi_pair_model.add_payload(TTLVData::new(11, 2, true).with_integer(30));
    wifi_pair_model.add_payload(TTLVData::new(12, 2, true).with_integer(380));
    wifi_pair_model.add_payload(
        TTLVData::new(13, 3, true).with_binary("mqtt://local-mqtt.test:1337".as_bytes().to_vec()),
    );

    write_to_characteristic(
        &our_characteristic,
        encode_tools.start_encode(&wifi_pair_model).get_cmd_data(),
    )
    .await
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> bluer::Result<()> {
    // pretty_env_logger::init();

    simple_logger::SimpleLogger::new()
        .with_level(log::LevelFilter::Debug)
        .with_colors(true)
        .init()
        .unwrap();

    let session = bluer::Session::new().await?;
    let adapter = session.default_adapter().await?;

    // adapter.set_powered(false).await?;
    // println!("Powered off");
    // sleep(Duration::from_secs(2)).await;

    // adapter.set_powered(true).await?;
    // println!("Powered on");

    let mut our_device: Option<Device> = None;
    let mut our_quec_device: Option<QuecBLEDevice> = None;

    {
        println!(
            "Discovering on Bluetooth adapter {} with address {}\n",
            adapter.name(),
            adapter.address().await?
        );

        adapter
            .set_discovery_filter(DiscoveryFilter {
                transport: DiscoveryTransport::Le,
                ..Default::default()
            })
            .await?;

        let discover = adapter.discover_devices().await?;

        pin_mut!(discover);

        while let Some(evt) = discover.next().await {
            match evt {
                AdapterEvent::DeviceAdded(addr) => {
                    let device = adapter.device(addr)?;

                    let name = device.name().await?;

                    let manufacturer_data = match device.manufacturer_data().await? {
                        Some(data) => data,
                        None => {
                            continue;
                        }
                    };

                    let quec_device = match try_get_quec_device(&name, &addr, &manufacturer_data) {
                        Some(d) => d,
                        None => {
                            continue;
                        }
                    };

                    println!("Found device with \"{:?}\" with address {:?}:", name, addr);
                    println!("  device key: {:?}", quec_device.device_key);
                    println!("  product key: {:?}", quec_device.product_key);

                    device.set_blocked(false).await?;
                    device.set_trusted(true).await?;

                    our_device = Some(device);
                    our_quec_device = Some(quec_device);

                    break;
                    // if our_characteristic.flags().await?.read {
                    //     let value = our_characteristic.read().await?;
                    //     println!("    Read value back: {:x?}", &value);
                    //     sleep(Duration::from_secs(1)).await;
                    // }

                    // match device.disconnect().await {
                    //     Ok(()) => println!("Device disconnected"),
                    //     Err(err) => println!("Device disconnection failed: {}", &err),
                    // }

                    // break;
                }
                // AdapterEvent::DeviceRemoved(addr) => {
                //     println!("Device removed {addr}");
                // }
                _ => (),
            }
        }

        println!("Stopping discovery");
    }

    let device = our_device.unwrap();

    match connect_to_device(&device).await {
        Ok(()) => println!("Device connected"),
        Err(err) => {
            println!("Device connection failed: {}", &err);
            return Err(err);
        }
    }

    let our_characteristic = match find_our_characteristic(&device).await {
        Ok(Some(char)) => char,
        Ok(None) => {
            println!("    Not found!");
            return Err(bluer::Error {
                kind: bluer::ErrorKind::NotFound,
                message: "Characteristic not found".to_string(),
            });
        }
        Err(err) => {
            println!("    Device failed: {}", &err);
            let _ = adapter.remove_device(device.address()).await;
            return Err(err);
        }
    };

    device.set_trusted(true).await?;

    sleep(Duration::from_secs(1)).await;

    // our_characteristic.write_ext(encode_tools.start_encode(&command_model).get_cmd_data(), &CharacteristicWriteRequest {
    //     offset: 0,
    //     op_type: WriteOp::Request,
    //     prepare_authorize: false,
    //     _non_exhaustive: (),
    // }).await?;

    println!("Trying notify...");

    // Create shared container that both tasks can access
    let shared_container = Arc::new(Mutex::new(LoginInfoContainer::new()));
    let shared_container_clone = Arc::clone(&shared_container);

    let notify = our_characteristic.notify().await.unwrap();

    let our_characteristic_clone = our_characteristic.clone();

    // Spawn the notify task
    let notify_task = tokio::spawn(async move {
        pin_mut!(notify);

        let mut decode_tools = DecodeTools::new();
        let mut encode_tools = EncodeTools::new();

        let mut binding_key: String = "3EB24BC7957DB49D".to_string();

        loop {
            match notify.next().await {
                Some(value) => {
                    println!("    Notification value: {:x?}", &value);

                    let results = decode_tools.packet_slice(&value);
                    for result in results {
                        match result {
                            DecodeResult::Success(model) => {
                                println!("Decoded command: 0x{:04X}", model.cmd);
                                println!("Packet ID: {}", model.packet_id);
                                println!("Payload count: {}", model.payloads.len());

                                match Cmd::from_i32(model.cmd) {
                                    Some(Cmd::RandomResp) => {
                                        println!("Random response");

                                        let random_ttlv = &model
                                            .payloads
                                            .iter()
                                            .find(|payload| payload.id == 1)
                                            .unwrap()
                                            .value;

                                        match random_ttlv {
                                            TTLVValue::Binary(data) => {
                                                let random_value =
                                                    String::from_utf8_lossy(data.as_slice())
                                                        .to_string();
                                                println!("Random value: {}", random_value);
                                                // write_pure_login_command(&our_characteristic_clone, &mut encode_tools).await;

                                                let binding_key_clone = binding_key.clone();
                                                write_login_command(
                                                    &our_characteristic_clone,
                                                    &mut encode_tools,
                                                    random_value,
                                                    binding_key_clone,
                                                )
                                                .await;
                                            }
                                            _ => (),
                                        }
                                    }

                                    Some(Cmd::LoginResp) => {
                                        println!("Login response");

                                        let login_ttlv = &model
                                            .payloads
                                            .iter()
                                            .find(|payload| payload.id == 3)
                                            .unwrap()
                                            .value;

                                        match login_ttlv {
                                            TTLVValue::Binary(data) => {
                                                let login_value =
                                                    String::from_utf8_lossy(data.as_slice())
                                                        .to_string();
                                                println!("Login value: {}", login_value);
                                            }
                                            _ => (),
                                        }
                                    }

                                    Some(Cmd::BLEAccountAuthenticationResp) => {
                                        println!("BLEAccountAuthentication response");
                                    }

                                    Some(Cmd::WifiPairResp) => {
                                        println!("Wifi pair response");

                                        let binding_ttlv =
                                            model.payloads.iter().find(|payload| payload.id == 9);

                                        match binding_ttlv {
                                            Some(ttlv) => match &ttlv.value {
                                                TTLVValue::Binary(data) => {
                                                    let binding_key_value =
                                                        String::from_utf8_lossy(data.as_slice())
                                                            .to_string();
                                                    println!(
                                                        "Binding key value: {}",
                                                        binding_key_value
                                                    );
                                                    binding_key = binding_key_value;

                                                    // writre_random_command(
                                                    //     &our_characteristic_clone,
                                                    //     &mut encode_tools,
                                                    // )
                                                    // .await;
                                                }
                                                _ => {
                                                    println!("Binding key format messed up.");
                                                }
                                            },
                                            _ => {
                                                println!(
                                                    "Binding key not found. Device seems to be not in pairing mode."
                                                );
                                            }
                                        }
                                    }

                                    _ => (),
                                }

                                for (i, payload) in model.payloads.iter().enumerate() {
                                    println!(
                                        "  Payload {}: ID=0x{:04X}, Type={}, TTLV={}",
                                        i, payload.id, payload.type_id, payload.ttlv
                                    );

                                    match &payload.value {
                                        TTLVValue::Binary(data) => {
                                            let code = String::from_utf8_lossy(data);

                                            // Update shared container
                                            if let Ok(mut container) = shared_container_clone.lock()
                                            {
                                                container.set_random(code.to_string());
                                            }

                                            println!("    Value: {:?} as string: {}", data, code);
                                        }
                                        TTLVValue::Integer(data) => {
                                            println!("    Integer value: {}", data);
                                        }
                                        _ => (),
                                    }
                                }
                            }
                            DecodeResult::Transparent(model) => {
                                println!("Transparent command: 0x{:04X}", model.cmd);
                            }
                            DecodeResult::Incomplete => {
                                println!("Incomplete data");
                            }
                            DecodeResult::Error(err) => {
                                println!("Error: {}", err);
                            }
                        }
                    }
                }
                None => {
                    println!("    Notification session was terminated");
                    break;
                }
            }
        }
    });

    // Spawn the write task
    let write_task = tokio::spawn(async move {
        sleep(Duration::from_secs(1)).await;

        let mut encode_tools = EncodeTools::new();

        if our_characteristic.flags().await?.write {
            // let command_model = TtlvCommandModel::new(Cmd::Random.as_i32(), 0);

            // println!("Trying write random command...");

            // write_to_characteristic(
            //     &our_characteristic,
            //     encode_tools.start_encode(&command_model).get_cmd_data(),
            // )
            // .await?;

            // writre_random_command(&our_characteristic.clone(), &mut encode_tools).await?;
            write_wifi_pair_command(&our_characteristic.clone(), &mut encode_tools).await?;
            // write_pure_login_command(&our_characteristic, &mut encode_tools).await?;

            sleep(Duration::from_secs(1)).await;

            // println!("Trying writing device info command...");
            // let model2 = TtlvCommandModel::new(IotCmd::ReadDeviceInfo.as_i32(), 1001);
            // write_to_characteristic(
            //     &our_characteristic,
            //     encode_tools.start_encode(&model2).get_cmd_data(),
            // )
            // .await?;

            // println!("Trying writing account authentication command...");

            // let random_value = {
            //     if let Ok(container) = shared_container.lock() {
            //         container.get_random()
            //     } else {
            //         String::new()
            //     }
            // };

            // let mut login_model = TtlvCommandModel::new(Cmd::BLEAccountAuthentication.as_i32(), 1001);
            // login_model.add_payload(TTLVData::new(1, 2, true).with_integer(1));
            // login_model.add_payload(TTLVData::new(3, 3, true).with_binary(random_value.as_bytes().to_vec()));

            // write_to_characteristic(
            //     &our_characteristic,
            //     encode_tools.start_encode(&login_model).get_cmd_data(),
            // )
            // .await?;
        }

        Ok::<(), bluer::Error>(())
    });

    // Wait for both tasks to complete
    let (notify_result, write_result) =
        tokio::join!(notify_task, write_task);

    // Handle any errors from the tasks
    if let Err(e) = notify_result {
        println!("Notify task error: {:?}", e);
    }

    if let Err(e) = write_result {
        println!("Write task error: {:?}", e);
        // The write task returns Result<(), bluer::Error>, so we need to handle the JoinError
        // and then extract the bluer::Error if it exists
        return Err(bluer::Error {
            kind: bluer::ErrorKind::Failed,
            message: format!("Write task failed: {:?}", e),
        });
    }

    device.disconnect().await?;

    // sleep(Duration::from_secs(10)).await;

    return Ok(());
}

#[derive(Default)]
struct LoginInfoContainer {
    random: Arc<Mutex<String>>,
}

impl LoginInfoContainer {
    fn new() -> Self {
        let shared_data = Arc::new(Mutex::new(String::from("")));
        LoginInfoContainer {
            random: shared_data,
        }
    }

    fn set_random(&mut self, random: String) {
        let mut lock = self.random.lock().unwrap();
        *lock = random;
    }

    fn get_random(&self) -> String {
        let lock = self.random.lock().unwrap();
        lock.clone()
    }
}

fn bytes_to_hex_str(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>()
}

use sha2::{Digest, Sha256};

fn digest(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    byte2hex(&result)
}

fn byte2hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
