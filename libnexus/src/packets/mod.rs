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
use bytes::{Buf, BytesMut};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tracing::error;

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

pub const NETBIOS_SESSION_MESSAGE: u8 = 0x00;
pub const PROTOCOL_ID: u32 = 0x424D53FE;
pub const SMB2_FLAGS_ASYNC_COMMAND: u32 = 0x00000002;

#[derive(Debug, PartialEq, Eq)]
pub struct SmbPacket {
    header: SMBHeaderSync,
    payload: Payload,
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
}

#[derive(Debug, PartialEq, Eq)]
pub enum Payload {
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
    reserved: u32,
    pub tree_id: u32,
    pub session_id: u64,
    pub signature: u128,
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
pub struct NegotiateContext {
    pub context_type: u16,
    pub data_length: u16,
    reserved: u32,
    pub data: Vec<u8>,
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
        if dialects.contains(&0x0311) {
            for i in 0..negotiate_context_count {
                let mut bytes = read_bytes_from_stream!(stream, 8);
                let context_type = bytes.get_u16_le();
                let data_length = bytes.get_u16_le();
                let reserved = bytes.get_u32_le();
                let mut data = vec![];
                for _ in 0..data_length {
                    let mut bytes = read_bytes_from_stream!(stream, 1);
                    data.push(bytes.get_u8());
                }
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
    padding: Vec<u8>,
    pub negotiate_context_list: Vec<NegotiateContext>,
}
