/*
   Unix SMB3 implementation
   Copyright (C) David Mulder <dmulder@samba.org> 2024

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program. If not, see <https://www.gnu.org/licenses/>.
*/
use crate::error::*;
use bytes::{Buf, BufMut, BytesMut};
use chrono::{LocalResult, TimeZone, Utc};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tracing::error;

#[macro_export]
macro_rules! error_resp_send {
    ($stream:expr, $command:expr, $message_id:expr, $error:expr) => {{
        let resp = SmbPacket {
            header: SMBHeaderSync {
                protocol_id: PROTOCOL_ID,
                structure_size: 0x40,
                credit_charge: 0,
                interpret: StatusChannelSequenceInterpretation::Status(
                    $error.val(),
                ),
                command: $command as u16,
                credits: 1,
                flags: SMB2_FLAGS_SERVER_TO_REDIR,
                next_command: 0,
                message_id: $message_id,
                reserved: 0,
                tree_id: 0,
                session_id: 0,
                signature: 0,
            },
            payload: Payload::ErrorResponse(ErrorResponse {
                structure_size: 9,
                error_context_count: 0,
                reserved: 0,
                byte_count: 0,
                error_data: vec![],
            }),
        };
        let mut bytes = BytesMut::new();
        resp.to_bytes(&mut bytes);
        $stream.write_all(&bytes).await.map_err(|e| {
            error!("{:?}", e);
            NT_STATUS_NETWORK_BUSY
        })?;
    }};
}

macro_rules! read_bytes_from_stream {
    ($stream:expr, $count:expr) => {{
        let mut bytes = vec![0u8; $count];
        $stream.read_exact(&mut bytes).await.map_err(|e| {
            error!("{:?}", e);
            NT_STATUS_NETWORK_BUSY
        })?;
        BytesMut::from(&bytes[..])
    }};
}

#[macro_export]
macro_rules! write_netbios_header_to_bytes {
    ($bytes:expr, $length:expr) => {{
        $bytes.put_u8(0 as u8);
        let length: u32 = $length - 4;
        let bytes = length.to_be_bytes();
        $bytes.put_slice(&bytes[1..]);
    }};
}

pub const NETBIOS_SESSION_MESSAGE: u8 = 0x00;
pub const PROTOCOL_ID: u32 = 0x424D53FE;
pub const SMB2_FLAGS_ASYNC_COMMAND: u32 = 0x00000002;
pub const SMB_3_1_1_DIALECT: u16 = 0x0311;
pub const SMB2_FLAGS_SERVER_TO_REDIR: u32 = 0x00000001;

// SecurityMode
pub const SMB2_NEGOTIATE_SIGNING_ENABLED: u16 = 0x0001;
pub const SMB2_NEGOTIATE_SIGNING_REQUIRED: u16 = 0x0002;

// Capabilities
pub const SMB2_GLOBAL_CAP_DFS: u32 = 0x00000001;
pub const SMB2_GLOBAL_CAP_LEASING: u32 = 0x00000002;
pub const SMB2_GLOBAL_CAP_LARGE_MTU: u32 = 0x00000004;
pub const SMB2_GLOBAL_CAP_MULTI_CHANNEL: u32 = 0x00000008;
pub const SMB2_GLOBAL_CAP_PERSISTENT_HANDLES: u32 = 0x00000010;
pub const SMB2_GLOBAL_CAP_DIRECTORY_LEASING: u32 = 0x00000020;
pub const SMB2_GLOBAL_CAP_ENCRYPTION: u32 = 0x00000040;

// Negotiate Context Type
pub const SMB2_SIGNING_CAPABILITIES: u16 = 0x0008;
pub const SMB2_ENCRYPTION_CAPABILITIES: u16 = 0x0002;

// Signing Algorithm Id
pub const AES_GMAC: u16 = 0x0002;

// Encryption Ciphers
pub const AES_256_GCM: u16 = 0x0004;

#[derive(Debug, PartialEq, Eq)]
pub struct SmbPacket {
    pub header: SMBHeaderSync,
    pub payload: Payload,
}

impl SmbPacket {
    pub async fn from_stream(
        stream: &mut TcpStream,
        req: bool,
    ) -> Result<Self, NtStatus> {
        // Strip off the NetBIOS header, if present
        let mut netbios = [0u8; 1];
        stream.peek(&mut netbios).await.map_err(|e| {
            error!("{:?}", e);
            NT_STATUS_NETWORK_BUSY
        })?;
        if netbios[0] == NETBIOS_SESSION_MESSAGE {
            // Consume the netbios header
            let _ = read_bytes_from_stream!(stream, 4);
        }
        let mut header_bytes = read_bytes_from_stream!(stream, 20);
        let protocol_id = header_bytes.get_u32_le();
        if protocol_id != PROTOCOL_ID {
            println!("{}", protocol_id);
            return Err(NT_STATUS_PROTOCOL_NOT_SUPPORTED);
        }
        let structure_size = header_bytes.get_u16_le();
        if structure_size != 64 {
            return Err(NT_STATUS_INVALID_PARAMETER);
        }
        let credit_charge = header_bytes.get_u16_le();
        let interpret = if req {
            StatusChannelSequenceInterpretation::ChannelSequence(
                header_bytes.get_u16_le(),
                header_bytes.get_u16_le(),
            )
        } else {
            StatusChannelSequenceInterpretation::Status(
                header_bytes.get_u32_le(),
            )
        };
        let command = header_bytes.get_u16_le();
        let credits = header_bytes.get_u16_le();
        let flags = header_bytes.get_u32_le();
        let header = if (flags & SMB2_FLAGS_ASYNC_COMMAND) != 0 {
            error!("Async headers are not yet implemented");
            return Err(NT_STATUS_NOT_SUPPORTED);
        } else {
            let mut header_bytes = read_bytes_from_stream!(stream, 44);
            let next_command = header_bytes.get_u32_le();
            let message_id = header_bytes.get_u64_le();
            let reserved = header_bytes.get_u32_le();
            let tree_id = header_bytes.get_u32_le();
            let session_id = header_bytes.get_u64_le();
            let signature = header_bytes.get_u128_le();
            SMBHeaderSync {
                protocol_id,
                structure_size,
                credit_charge,
                interpret,
                command,
                credits,
                flags,
                next_command,
                message_id,
                reserved,
                tree_id,
                session_id,
                signature,
            }
        };

        let payload = match header.command {
            x if x == SmbCommand::Negotiate as u16 => {
                if req {
                    Payload::NegotiateProtocolRequest(
                        NegotiateProtocolRequest::from_stream(stream).await?,
                    )
                } else {
                    return Err(NT_STATUS_NOT_SUPPORTED);
                }
            }
            command => {
                error!("Command {} not supported yet", command);
                return Err(NT_STATUS_NOT_SUPPORTED);
            }
        };

        Ok(SmbPacket { header, payload })
    }

    pub fn to_bytes(&self, bytes: &mut BytesMut) {
        let mut smb3_bytes = BytesMut::new();
        self.header.to_bytes(&mut smb3_bytes);
        match &self.payload {
            Payload::ErrorResponse(resp) => resp.to_bytes(&mut smb3_bytes),
            Payload::NegotiateProtocolRequest(_req) => {
                panic!("Not implemented yet")
            } //TODO
            Payload::NegotiateProtocolResponse(resp) => {
                resp.to_bytes(&mut smb3_bytes)
            }
        }
        let smb3_length = smb3_bytes.len();
        write_netbios_header_to_bytes!(bytes, (4 + smb3_length) as u32);
        bytes.extend_from_slice(&smb3_bytes);
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Payload {
    ErrorResponse(ErrorResponse),
    NegotiateProtocolRequest(NegotiateProtocolRequest),
    NegotiateProtocolResponse(NegotiateProtocolResponse),
}

#[derive(Debug, PartialEq, Eq)]
pub enum StatusChannelSequenceInterpretation {
    ChannelSequence(u16, u16),
    Status(u32),
}

#[derive(Debug, PartialEq, Eq)]
pub struct SMBHeaderSync {
    pub protocol_id: u32,
    pub structure_size: u16,
    pub credit_charge: u16,
    pub interpret: StatusChannelSequenceInterpretation,
    pub command: u16,
    pub credits: u16,
    pub flags: u32,
    pub next_command: u32,
    pub message_id: u64,
    pub(crate) reserved: u32,
    pub tree_id: u32,
    pub session_id: u64,
    pub signature: u128,
}

impl SMBHeaderSync {
    pub fn new(
        credit_charge: u16,
        interpret: StatusChannelSequenceInterpretation,
        command: SmbCommand,
        credits: u16,
        flags: u32,
        next_command: u32,
        message_id: u64,
        tree_id: u32,
        session_id: u64,
    ) -> Self {
        SMBHeaderSync {
            protocol_id: PROTOCOL_ID,
            structure_size: 0x40,
            credit_charge,
            interpret,
            command: command as u16,
            credits,
            flags,
            next_command,
            message_id,
            reserved: 0,
            tree_id,
            session_id,
            signature: 0, //TODO
        }
    }

    pub fn to_bytes(&self, bytes: &mut BytesMut) {
        bytes.put_u32_le(self.protocol_id);
        bytes.put_u16_le(self.structure_size);
        bytes.put_u16_le(self.credit_charge);
        match self.interpret {
            StatusChannelSequenceInterpretation::ChannelSequence(
                channel_sequence,
                reserved,
            ) => {
                bytes.put_u16_le(channel_sequence);
                bytes.put_u16_le(reserved);
            }
            StatusChannelSequenceInterpretation::Status(status) => {
                bytes.put_u32_le(status);
            }
        }
        bytes.put_u16_le(self.command);
        bytes.put_u16_le(self.credits);
        bytes.put_u32_le(self.flags);
        bytes.put_u32_le(self.next_command);
        bytes.put_u64_le(self.message_id);
        bytes.put_u32_le(self.reserved);
        bytes.put_u32_le(self.tree_id);
        bytes.put_u64_le(self.session_id);
        bytes.put_u128_le(self.signature);
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum SmbCommand {
    Negotiate = 0,
    SessionSetup = 1,
    Logoff = 2,
    TreeConnect = 3,
    TreeDisconnect = 4,
    Create = 5,
    Close = 6,
    Flush = 7,
    Read = 8,
    Write = 9,
    Lock = 10,
    Ioctl = 11,
    Cancel = 12,
    Echo = 13,
    QueryDirectory = 14,
    ChangeNotify = 15,
    QueryInfo = 16,
    SetInfo = 17,
    OplockBreak = 18,
    ServerToClientNotification = 19,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ErrorResponse {
    pub structure_size: u16,
    pub error_context_count: u8,
    pub(crate) reserved: u8,
    pub byte_count: u32,
    pub error_data: Vec<u8>,
}

impl ErrorResponse {
    pub fn to_bytes(&self, bytes: &mut BytesMut) {
        bytes.put_u16_le(self.structure_size);
        bytes.put_u8(self.error_context_count);
        bytes.put_u8(self.reserved);
        bytes.put_u32_le(self.byte_count);
        // 1 bytes padding?
        bytes.put_u8(0);
        for byte in &self.error_data {
            bytes.put_u8(*byte);
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum NegotiateContextData {
    SigningCapabilities(SigningCapabilities),
    EncryptionCapabilities(EncryptionCapabilities),
    Data(Vec<u8>),
}

#[derive(Debug, PartialEq, Eq)]
pub struct SigningCapabilities {
    pub signing_algorithm_count: u16,
    pub signing_algorithms: Vec<u16>,
}

impl SigningCapabilities {
    pub fn to_bytes(&self, bytes: &mut BytesMut) {
        bytes.put_u16_le(self.signing_algorithm_count);
        for signing_algorithm in &self.signing_algorithms {
            bytes.put_u16_le(*signing_algorithm);
        }
    }

    pub async fn from_stream(stream: &mut TcpStream) -> Result<Self, NtStatus> {
        let mut bytes = read_bytes_from_stream!(stream, 2);
        let signing_algorithm_count = bytes.get_u16_le();
        let mut bytes = read_bytes_from_stream!(
            stream,
            (2 * signing_algorithm_count).into()
        );
        let mut signing_algorithms = vec![];
        for _ in 0..signing_algorithm_count {
            let signing_algorithm = bytes.get_u16_le();
            signing_algorithms.push(signing_algorithm);
        }
        Ok(SigningCapabilities {
            signing_algorithm_count,
            signing_algorithms,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct EncryptionCapabilities {
    pub cipher_count: u16,
    pub ciphers: Vec<u16>,
}

impl EncryptionCapabilities {
    pub fn to_bytes(&self, bytes: &mut BytesMut) {
        bytes.put_u16_le(self.cipher_count);
        for cipher in &self.ciphers {
            bytes.put_u16_le(*cipher);
        }
    }

    pub async fn from_stream(stream: &mut TcpStream) -> Result<Self, NtStatus> {
        let mut bytes = read_bytes_from_stream!(stream, 2);
        let cipher_count = bytes.get_u16_le();
        let mut bytes =
            read_bytes_from_stream!(stream, (2 * cipher_count).into());
        let mut ciphers = vec![];
        for _ in 0..cipher_count {
            let cipher = bytes.get_u16_le();
            ciphers.push(cipher);
        }
        Ok(EncryptionCapabilities {
            cipher_count,
            ciphers,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct NegotiateContext {
    pub context_type: u16,
    pub data_length: u16,
    reserved: u32,
    pub data: NegotiateContextData,
}

impl NegotiateContext {
    pub fn to_bytes(&self, bytes: &mut BytesMut) {
        bytes.put_u16_le(self.context_type);
        bytes.put_u16_le(self.data_length);
        bytes.put_u32_le(self.reserved);

        match &self.data {
            NegotiateContextData::SigningCapabilities(data) => {
                data.to_bytes(bytes)
            }
            NegotiateContextData::EncryptionCapabilities(data) => {
                data.to_bytes(bytes)
            }
            NegotiateContextData::Data(data) => {
                for byte in data {
                    bytes.put_u8(*byte);
                }
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct NegotiateProtocolRequest {
    pub structure_size: u16,
    pub dialect_count: u16,
    pub security_mode: u16,
    reserved: u16,
    pub capabilities: u32,
    pub client_guid: u128,
    pub negotiate_context_offset: u32,
    pub negotiate_context_count: u16,
    reserved2: u16,
    pub dialects: Vec<u16>,
    padding: Vec<u8>,
    pub negotiate_context_list: Vec<NegotiateContext>,
}

impl NegotiateProtocolRequest {
    pub async fn from_stream(stream: &mut TcpStream) -> Result<Self, NtStatus> {
        let mut bytes = read_bytes_from_stream!(stream, 36);
        let structure_size = bytes.get_u16_le();
        if structure_size != 36 {
            return Err(NT_STATUS_INVALID_PARAMETER);
        }
        let dialect_count = bytes.get_u16_le();
        let security_mode = bytes.get_u16_le();
        let reserved = bytes.get_u16_le();
        let capabilities = bytes.get_u32_le();
        let client_guid = bytes.get_u128_le();
        let negotiate_context_offset = bytes.get_u32_le();
        let negotiate_context_count = bytes.get_u16_le();
        let reserved2 = bytes.get_u16_le();
        let mut dialects = vec![];
        let mut bytes =
            read_bytes_from_stream!(stream, (dialect_count * 2).into());
        for _ in 0..dialect_count {
            dialects.push(bytes.get_u16_le());
        }
        // Check for padding
        let offset = 64 + 36 + (dialect_count * 2);
        let padding_bytes = if (offset % 8) != 0 {
            8 - (offset % 8)
        } else {
            0
        };
        let mut bytes = read_bytes_from_stream!(stream, padding_bytes as usize);
        let mut padding = vec![];
        for _ in 0..padding_bytes {
            padding.push(bytes.get_u8());
        }
        // Only fetch negotiate contexts if supported
        let mut negotiate_context_list = vec![];
        if dialects.contains(&SMB_3_1_1_DIALECT) {
            for i in 0..negotiate_context_count {
                let mut bytes = read_bytes_from_stream!(stream, 8);
                let context_type = bytes.get_u16_le();
                let data_length = bytes.get_u16_le();
                let reserved = bytes.get_u32_le();
                let data = match context_type {
                    SMB2_SIGNING_CAPABILITIES => {
                        NegotiateContextData::SigningCapabilities(
                            SigningCapabilities::from_stream(stream).await?,
                        )
                    }
                    SMB2_ENCRYPTION_CAPABILITIES => {
                        NegotiateContextData::EncryptionCapabilities(
                            EncryptionCapabilities::from_stream(stream).await?,
                        )
                    }
                    _ => {
                        let mut data = vec![];
                        for _ in 0..data_length {
                            let mut bytes = read_bytes_from_stream!(stream, 1);
                            data.push(bytes.get_u8());
                        }
                        NegotiateContextData::Data(data)
                    }
                };
                if i != negotiate_context_count - 1 {
                    let padding_bytes = if (data_length % 8) != 0 {
                        8 - (data_length % 8)
                    } else {
                        0
                    };
                    let _ =
                        read_bytes_from_stream!(stream, padding_bytes as usize);
                }
                negotiate_context_list.push(NegotiateContext {
                    context_type,
                    data_length,
                    reserved,
                    data,
                });
            }
        }

        Ok(NegotiateProtocolRequest {
            structure_size,
            dialect_count,
            security_mode,
            reserved,
            capabilities,
            client_guid,
            negotiate_context_offset,
            negotiate_context_count,
            reserved2,
            dialects,
            padding,
            negotiate_context_list,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct NegotiateProtocolResponse {
    pub structure_size: u16,
    pub security_mode: u16,
    pub dialect_revision: u16,
    pub negotiate_context_count: u16,
    pub server_guid: u128,
    pub capabilities: u32,
    pub max_transact_size: u32,
    pub max_read_size: u32,
    pub max_write_size: u32,
    pub system_time: u64,
    pub server_start_time: u64,
    pub security_buffer_offset: u16,
    pub security_buffer_length: u16,
    pub negotiate_context_offset: u32,
    pub buffer: Vec<u8>,
    pub(crate) padding: Vec<u8>,
    pub negotiate_context_list: Vec<NegotiateContext>,
}

impl NegotiateProtocolResponse {
    pub fn new(
        server_guid: u128,
        security_blob: Vec<u8>,
    ) -> Result<Self, NtStatus> {
        let windows_epoch = match Utc.with_ymd_and_hms(1601, 1, 1, 0, 0, 0) {
            LocalResult::Single(datetime) => datetime,
            _ => return Err(NT_STATUS_UNSUCCESSFUL),
        };
        let now = Utc::now();
        let duration_since_epoch = now.signed_duration_since(windows_epoch);
        let intervals = (duration_since_epoch.num_seconds() as u64)
            * 10_000_000
            + (duration_since_epoch.num_nanoseconds().unwrap_or(0)
                % 1_000_000_000
                / 100) as u64;

        let negotiate_context_list = vec![
            NegotiateContext {
                context_type: SMB2_SIGNING_CAPABILITIES,
                data_length: 4,
                reserved: 0,
                data: NegotiateContextData::SigningCapabilities(
                    SigningCapabilities {
                        signing_algorithm_count: 1,
                        signing_algorithms: vec![AES_GMAC],
                    },
                ),
            },
            NegotiateContext {
                context_type: SMB2_ENCRYPTION_CAPABILITIES,
                data_length: 4,
                reserved: 0,
                data: NegotiateContextData::EncryptionCapabilities(
                    EncryptionCapabilities {
                        cipher_count: 1,
                        ciphers: vec![AES_256_GCM],
                    },
                ),
            },
        ];

        Ok(NegotiateProtocolResponse {
            structure_size: 65,
            security_mode: SMB2_NEGOTIATE_SIGNING_ENABLED
                | SMB2_NEGOTIATE_SIGNING_REQUIRED,
            dialect_revision: SMB_3_1_1_DIALECT,
            negotiate_context_count: 2,
            server_guid,
            capabilities: 0,
            max_transact_size: 8388608,
            max_read_size: 8388608,
            max_write_size: 8388608,
            system_time: intervals,
            server_start_time: intervals,
            security_buffer_offset: 128,
            security_buffer_length: security_blob.len() as u16,
            negotiate_context_offset: (security_blob.len() + 128) as u32,
            buffer: security_blob,
            padding: vec![],
            negotiate_context_list,
        })
    }

    pub fn to_bytes(&self, bytes: &mut BytesMut) {
        bytes.put_u16_le(self.structure_size);
        bytes.put_u16_le(self.security_mode);
        bytes.put_u16_le(self.dialect_revision);
        bytes.put_u16_le(self.negotiate_context_count);
        bytes.put_u128_le(self.server_guid);
        bytes.put_u32_le(self.capabilities);
        bytes.put_u32_le(self.max_transact_size);
        bytes.put_u32_le(self.max_read_size);
        bytes.put_u32_le(self.max_write_size);
        bytes.put_u64_le(self.system_time);
        bytes.put_u64_le(self.server_start_time);
        bytes.put_u16_le(self.security_buffer_offset);
        bytes.put_u16_le(self.security_buffer_length);
        bytes.put_u32_le(self.negotiate_context_offset);

        // Add the buffer
        for byte in &self.buffer {
            bytes.put_u8(*byte);
        }

        // Add the padding
        for byte in &self.padding {
            bytes.put_u8(*byte);
        }

        // Add the negotiate context list
        for i in 0..self.negotiate_context_count {
            let context = &self.negotiate_context_list[i as usize];
            context.to_bytes(bytes);
            if i != self.negotiate_context_count - 1 {
                let padding_bytes = if (context.data_length % 8) != 0 {
                    8 - (context.data_length % 8)
                } else {
                    0
                };
                for _ in 0..padding_bytes {
                    bytes.put_u8(0);
                }
            }
        }
    }
}
