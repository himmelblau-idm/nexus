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
use crate::server::connection::Connection;
use crate::server::Server;
use tokio::net::TcpStream;

pub async fn handle_client(
    stream: &mut TcpStream,
    ctx: Server,
) -> Result<(), NtStatus> {
    let mut connection = Connection::new(stream, ctx);

    connection.negotiate_dialect().await?;
    connection.session_setup().await?;

    Err(NT_STATUS_NOT_IMPLEMENTED)
}
