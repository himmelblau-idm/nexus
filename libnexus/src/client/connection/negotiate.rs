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
use crate::client::connection::Connection;
use crate::error::*;
use crate::packets::*;
use bytes::BytesMut;
use tokio::io::AsyncWriteExt;
use tracing::error;

impl Connection {
    pub(crate) async fn negotiate_dialect(&mut self) -> Result<(), NtStatus> {
        let req = SmbPacket {
            header: SMBHeaderSync::new(
                0,
                StatusChannelSequenceInterpretation::Status(
                    NT_STATUS_SUCCESS.val(),
                ),
                SmbCommand::Negotiate,
                1,
                0,
                0,
                0,
                0,
                0,
            ),
            payload: Payload::NegotiateProtocolRequest(
                NegotiateProtocolRequest::new(self.client_guid)?,
            ),
        };
        let mut bytes = BytesMut::new();
        req.to_bytes(&mut bytes);
        self.stream.write_all(&bytes).await.map_err(|e| {
            error!("{:?}", e);
            NT_STATUS_NETWORK_BUSY
        })?;

        let resp = SmbPacket::from_stream(&mut self.stream, true).await?;

        Ok(())
    }
}
