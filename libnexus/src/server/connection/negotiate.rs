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
use crate::packets::*;
use crate::server::connection::Connection;
use bytes::BytesMut;
use tokio::io::AsyncWriteExt;
use tracing::error;

impl Connection<'_> {
    pub(crate) async fn negotiate_dialect(&mut self) -> Result<(), NtStatus> {
        let req = SmbPacket::from_stream(self.stream, true).await?;

        match req.payload {
            Payload::NegotiateProtocolRequest(neg_req) => {
                // We only support dialect 0x0311 (or newer, when available)
                if !neg_req.dialects.contains(&SMB_3_1_1_DIALECT) {
                    return Err(NT_STATUS_PROTOCOL_NOT_SUPPORTED);
                }
                // We require signing, so it must at least be enabled by the client
                if (neg_req.security_mode & SMB2_NEGOTIATE_SIGNING_ENABLED) == 0
                {
                    return Err(NT_STATUS_PROTOCOL_NOT_SUPPORTED);
                }
                // We only support AES-GMAC signing
                let signing_capabilities = neg_req
                    .negotiate_context_list
                    .iter()
                    .find_map(|context| match &context.data {
                        NegotiateContextData::SigningCapabilities(caps) => {
                            Some(caps)
                        }
                        _ => None,
                    });
                if let Some(signing_capabilities) = signing_capabilities {
                    if !signing_capabilities
                        .signing_algorithms
                        .contains(&AES_GMAC)
                    {
                        // Client doesn't support AES_GMAC signing
                        return Err(NT_STATUS_PROTOCOL_NOT_SUPPORTED);
                    }
                } else {
                    // Client doesn't support signing
                    return Err(NT_STATUS_PROTOCOL_NOT_SUPPORTED);
                }
                // We require AES-256-GCM Encryption
                let encryption_capabilities = neg_req
                    .negotiate_context_list
                    .iter()
                    .find_map(|context| match &context.data {
                        NegotiateContextData::EncryptionCapabilities(caps) => {
                            Some(caps)
                        }
                        _ => None,
                    });
                if let Some(encryption_capabilities) = encryption_capabilities {
                    if !encryption_capabilities.ciphers.contains(&AES_256_GCM) {
                        // Client doesn't support AES_256_GCM encryption
                        return Err(NT_STATUS_PROTOCOL_NOT_SUPPORTED);
                    }
                } else {
                    // Client doesn't support encryption
                    return Err(NT_STATUS_PROTOCOL_NOT_SUPPORTED);
                }
                let security_blob = self.create_security_blob()?;
                let resp = SmbPacket {
                    header: SMBHeaderSync::new(
                        0,
                        StatusChannelSequenceInterpretation::Status(
                            NT_STATUS_SUCCESS.val(),
                        ),
                        SmbCommand::Negotiate,
                        1,
                        SMB2_FLAGS_SERVER_TO_REDIR,
                        0,
                        req.header.message_id,
                        req.header.tree_id,
                        req.header.session_id,
                    ),
                    payload: Payload::NegotiateProtocolResponse(
                        NegotiateProtocolResponse::new(
                            self.ctx.server_guid,
                            security_blob,
                        )?,
                    ),
                };
                let mut bytes = BytesMut::new();
                resp.to_bytes(&mut bytes);
                self.stream.write_all(&bytes).await.map_err(|e| {
                    error!("{:?}", e);
                    NT_STATUS_NETWORK_BUSY
                })?;
            }
            _ => return Err(NT_STATUS_INVALID_NETWORK_RESPONSE),
        }
        Ok(())
    }
}
