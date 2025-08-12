use crate::ttlv::model::TTLVData;

/// Command model for TTLV protocol
#[derive(Debug, Clone)]
pub struct TtlvCommandModel {
    pub cmd: i32,
    pub packet_id: i32,
    pub payloads: Vec<TTLVData>,
}

impl TtlvCommandModel {
    pub fn new(cmd: i32, packet_id: i32) -> Self {
        Self {
            cmd,
            packet_id,
            payloads: Vec::new(),
        }
    }

    pub fn set_cmd(&mut self, cmd: i32) {
        self.cmd = cmd;
    }

    pub fn set_packet_id(&mut self, packet_id: i32) {
        self.packet_id = packet_id;
    }

    pub fn add_payload(&mut self, payload: TTLVData) {
        self.payloads.push(payload);
    }

    pub fn get_cmd(&self) -> i32 {
        self.cmd
    }

    pub fn get_packet_id(&self) -> i32 {
        self.packet_id
    }

    pub fn get_payloads(&self) -> &Vec<TTLVData> {
        &self.payloads
    }
}

/// Base command constants
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Cmd {
    // UDP broadcast commands
    UdpBroadcast = 0x7030,
    UdpBroadcastResp = 0x7031,

    // TCP heartbeat commands
    TcpHeartBeat = 0x7037,
    TcpHeartBeatResp = 0x7038,

    // Random and authentication commands
    Random = 0x7032,
    RandomResp = 0x7033,
    Login = 0x7034,
    LoginResp = 0x7035,

    BLEAccountAuthentication = 0x7016, //0x7017
    BLEAccountAuthenticationResp = 0x7017, //0x7012

    // TLS (Thing Model) commands
    TlsRead = 0x0011,
    TlsReadRes = 0x0012,
    TlsWrite = 0x0013,
    TlsDeviceReport = 0x0014,
    TlsWriteRes = 0x7036,
    
    // Wifi pair commands
    WifiPair = 0x7010,
    WifiPairResp = 0x7011,

    // Wifi scan commands
    WifiScan = 0x7012,
    WifiScanResp = 0x7013,
}

impl Cmd {
    /// Convert enum to i32
    pub fn as_i32(self) -> i32 {
        self as i32
    }

    /// Convert i32 to enum (returns None if invalid)
    pub fn from_i32(value: i32) -> Option<Self> {
        match value {
            0x7030 => Some(Self::UdpBroadcast),
            0x7031 => Some(Self::UdpBroadcastResp),
            0x7037 => Some(Self::TcpHeartBeat),
            0x7038 => Some(Self::TcpHeartBeatResp),
            0x7032 => Some(Self::Random),
            0x7033 => Some(Self::RandomResp),
            0x7034 => Some(Self::Login),
            0x7035 => Some(Self::LoginResp),
            0x0011 => Some(Self::TlsRead),
            0x0012 => Some(Self::TlsReadRes),
            0x0013 => Some(Self::TlsWrite),
            0x0014 => Some(Self::TlsDeviceReport),
            0x7036 => Some(Self::TlsWriteRes),
            0x7016 => Some(Self::BLEAccountAuthentication),
            0x7017 => Some(Self::BLEAccountAuthenticationResp),

            0x7010 => Some(Self::WifiPair),
            0x7011 => Some(Self::WifiPairResp),
            0x7012 => Some(Self::WifiScan),
            0x7013 => Some(Self::WifiScanResp),
            _ => None,
        }
    }
}

/// IoT-specific command constants
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IotCmd {
    // Device status commands
    ReadDeviceStatus = 0x0031,
    ReadDeviceStatusAck = 0x0032,

    // WiFi commands
    ReadDeviceWifiList = 0x7051,
    ReadDeviceWifiListAck = 0x7052,
    ReadDeviceWifiListReport = 0x7053,
    ReadDeviceWifiListReportAck = 0x7054,
    ReadDeviceSwitchWifi = 0x7055,
    ReadDeviceSwitchWifiAck = 0x7056,

    // Device info commands
    ReadDeviceInfo = 0x7040,
    ReadDeviceInfoAck = 0x7041,

    // File control commands
    FileControl = 0x7043,
    FileControlAck = 0x7044,

    // Data report commands
    DeviceDataReport = 0x7065,
    DeviceDataReportAck = 0x7066,

    // Transparent data commands
    SendDeviceTransparent = 0x0023,
    ReceiveDeviceTransparent = 0x0024,

    // Time sync commands
    DeviceTimeSyncReport = 0x7060,
    DeviceTimeSyncReportAck = 0x7061,
    SendDeviceTimeSyncEvent = 0x7062,

    // Unbind commands
    DeviceUnbindReport = 0x7063,
    DeviceUnbindReportAck = 0x7064,

    // Account authentication commands
    SendDeviceAccountAuth = 0x7017,
    SendDeviceAccountAuthAck = 0x7018,
}

impl IotCmd {
    /// Convert enum to i32
    pub fn as_i32(self) -> i32 {
        self as i32
    }

    /// Convert i32 to enum (returns None if invalid)
    pub fn from_i32(value: i32) -> Option<Self> {
        match value {
            0x0031 => Some(Self::ReadDeviceStatus),
            0x0032 => Some(Self::ReadDeviceStatusAck),
            0x7051 => Some(Self::ReadDeviceWifiList),
            0x7052 => Some(Self::ReadDeviceWifiListAck),
            0x7053 => Some(Self::ReadDeviceWifiListReport),
            0x7054 => Some(Self::ReadDeviceWifiListReportAck),
            0x7055 => Some(Self::ReadDeviceSwitchWifi),
            0x7056 => Some(Self::ReadDeviceSwitchWifiAck),
            0x7040 => Some(Self::ReadDeviceInfo),
            0x7041 => Some(Self::ReadDeviceInfoAck),
            0x7043 => Some(Self::FileControl),
            0x7044 => Some(Self::FileControlAck),
            0x7065 => Some(Self::DeviceDataReport),
            0x7066 => Some(Self::DeviceDataReportAck),
            0x0023 => Some(Self::SendDeviceTransparent),
            0x0024 => Some(Self::ReceiveDeviceTransparent),
            0x7060 => Some(Self::DeviceTimeSyncReport),
            0x7061 => Some(Self::DeviceTimeSyncReportAck),
            0x7062 => Some(Self::SendDeviceTimeSyncEvent),
            0x7063 => Some(Self::DeviceUnbindReport),
            0x7064 => Some(Self::DeviceUnbindReportAck),
            0x7017 => Some(Self::SendDeviceAccountAuth),
            0x7018 => Some(Self::SendDeviceAccountAuthAck),
            _ => None,
        }
    }
}

/// Combined command enum that includes both base commands and IoT commands
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Command {
    Base(Cmd),
    Iot(IotCmd),
}

impl Command {
    /// Convert enum to i32
    pub fn as_i32(self) -> i32 {
        match self {
            Self::Base(cmd) => cmd.as_i32(),
            Self::Iot(cmd) => cmd.as_i32(),
        }
    }

    /// Convert i32 to enum (returns None if invalid)
    pub fn from_i32(value: i32) -> Option<Self> {
        // Try base commands first
        if let Some(cmd) = Cmd::from_i32(value) {
            return Some(Self::Base(cmd));
        }
        
        // Try IoT commands
        if let Some(cmd) = IotCmd::from_i32(value) {
            return Some(Self::Iot(cmd));
        }
        
        None
    }

    /// Check if this is a base command
    pub fn is_base(&self) -> bool {
        matches!(self, Self::Base(_))
    }

    /// Check if this is an IoT command
    pub fn is_iot(&self) -> bool {
        matches!(self, Self::Iot(_))
    }
}

impl From<Cmd> for Command {
    fn from(cmd: Cmd) -> Self {
        Self::Base(cmd)
    }
}

impl From<IotCmd> for Command {
    fn from(cmd: IotCmd) -> Self {
        Self::Iot(cmd)
    }
}

impl From<Command> for i32 {
    fn from(cmd: Command) -> Self {
        cmd.as_i32()
    }
}

impl From<Cmd> for i32 {
    fn from(cmd: Cmd) -> Self {
        cmd.as_i32()
    }
}

impl From<IotCmd> for i32 {
    fn from(cmd: IotCmd) -> Self {
        cmd.as_i32()
    }
}

/// Helper functions for working with commands
pub mod command_utils {
    use super::*;

    /// Create a TtlvCommandModel with a base command
    pub fn create_base_command(cmd: Cmd, packet_id: i32) -> TtlvCommandModel {
        TtlvCommandModel::new(cmd.as_i32(), packet_id)
    }

    /// Create a TtlvCommandModel with an IoT command
    pub fn create_iot_command(cmd: IotCmd, packet_id: i32) -> TtlvCommandModel {
        TtlvCommandModel::new(cmd.as_i32(), packet_id)
    }

    /// Create a TtlvCommandModel with a combined command
    pub fn create_command(cmd: Command, packet_id: i32) -> TtlvCommandModel {
        TtlvCommandModel::new(cmd.as_i32(), packet_id)
    }

    /// Check if a command value is a base command
    pub fn is_base_command(value: i32) -> bool {
        Cmd::from_i32(value).is_some()
    }

    /// Check if a command value is an IoT command
    pub fn is_iot_command(value: i32) -> bool {
        IotCmd::from_i32(value).is_some()
    }

    /// Get command name as string
    pub fn get_command_name(value: i32) -> Option<String> {
        if let Some(cmd) = Cmd::from_i32(value) {
            return Some(format!("{:?}", cmd));
        }
        
        if let Some(cmd) = IotCmd::from_i32(value) {
            return Some(format!("{:?}", cmd));
        }
        
        None
    }
}

/// Example usage of the command enums
pub fn example_command_usage() {
    println!("=== Command Enum Examples ===");
    
    // Using base commands
    let tls_read = Cmd::TlsRead;
    println!("TLS Read command: 0x{:04X}", tls_read.as_i32());
    
    let login = Cmd::Login;
    println!("Login command: 0x{:04X}", login.as_i32());
    
    // Using IoT commands
    let wifi_list = IotCmd::ReadDeviceWifiList;
    println!("WiFi List command: 0x{:04X}", wifi_list.as_i32());
    
    let device_status = IotCmd::ReadDeviceStatus;
    println!("Device Status command: 0x{:04X}", device_status.as_i32());
    
    // Using combined Command enum
    let combined_tls = Command::Base(Cmd::TlsRead);
    let combined_wifi = Command::Iot(IotCmd::ReadDeviceWifiList);
    
    println!("Combined TLS: 0x{:04X}", combined_tls.as_i32());
    println!("Combined WiFi: 0x{:04X}", combined_wifi.as_i32());
    
    // Converting from i32 back to enums
    if let Some(cmd) = Cmd::from_i32(0x0011) {
        println!("0x0011 is: {:?}", cmd);
    }
    
    if let Some(cmd) = IotCmd::from_i32(0x7051) {
        println!("0x7051 is: {:?}", cmd);
    }
    
    if let Some(cmd) = Command::from_i32(0x0011) {
        println!("0x0011 as Command: {:?}", cmd);
    }
    
    // Using utility functions
    let model1 = command_utils::create_base_command(Cmd::TlsRead, 123);
    let model2 = command_utils::create_iot_command(IotCmd::ReadDeviceWifiList, 456);
    
    println!("Model 1 command: 0x{:04X}", model1.cmd);
    println!("Model 2 command: 0x{:04X}", model2.cmd);
    
    // Command name lookup
    if let Some(name) = command_utils::get_command_name(0x0011) {
        println!("Command 0x0011 name: {}", name);
    }
    
    if let Some(name) = command_utils::get_command_name(0x7051) {
        println!("Command 0x7051 name: {}", name);
    }
    
    // Type checking
    println!("Is 0x0011 a base command? {}", command_utils::is_base_command(0x0011));
    println!("Is 0x7051 an IoT command? {}", command_utils::is_iot_command(0x7051));
    println!("Is 0x9999 a valid command? {}", command_utils::is_base_command(0x9999) || command_utils::is_iot_command(0x9999));
}

/// Example of creating command models with different command types
pub fn example_command_models() {
    println!("\n=== Command Model Examples ===");
    
    // Create models using different approaches
    let model1 = TtlvCommandModel::new(Cmd::TlsRead.as_i32(), 1);
    let model2 = TtlvCommandModel::new(IotCmd::ReadDeviceWifiList.as_i32(), 2);
    let model3 = command_utils::create_command(Command::Base(Cmd::Login), 3);
    
    println!("Model 1: cmd=0x{:04X}, packet_id={}", model1.cmd, model1.packet_id);
    println!("Model 2: cmd=0x{:04X}, packet_id={}", model2.cmd, model2.packet_id);
    println!("Model 3: cmd=0x{:04X}, packet_id={}", model3.cmd, model3.packet_id);
    
    // Pattern matching on command types
    for (i, model) in [model1, model2, model3].iter().enumerate() {
        match Command::from_i32(model.cmd) {
            Some(Command::Base(cmd)) => {
                println!("Model {}: Base command {:?}", i, cmd);
            }
            Some(Command::Iot(cmd)) => {
                println!("Model {}: IoT command {:?}", i, cmd);
            }
            None => {
                println!("Model {}: Unknown command 0x{:04X}", i, model.cmd);
            }
        }
    }
}
