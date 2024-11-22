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
use crate::error::NtStatus;
use tokio::net::TcpStream;
use uuid::Uuid;

mod negotiate;

pub(crate) struct Connection {
    stream: TcpStream,
    client_guid: u128,
    session_id: u64,
}

impl Connection {
    pub(crate) async fn new(stream: TcpStream) -> Result<Self, NtStatus> {
        let mut connection = Connection {
            stream,
            client_guid: Uuid::new_v4().as_u128(),
            session_id: 0, // Initialized to 0. Will be established later.
        };

        connection.negotiate_dialect().await?;

        Ok(connection)
    }
}
