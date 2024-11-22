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
use std::error::Error;
use tokio::net::TcpStream;

mod connection;
use crate::client::connection::Connection;

pub struct Client {
    connection: Connection,
}

impl Client {
    pub async fn new(
        server_address: &str,
        server_port: u32,
    ) -> Result<Self, Box<dyn Error>> {
        Ok(Client {
            connection: Connection::new(
                TcpStream::connect(format!(
                    "{}:{}",
                    server_address, server_port
                ))
                .await?,
            )
            .await?,
        })
    }
}
