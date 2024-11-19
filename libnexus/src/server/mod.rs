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
use tokio::net::TcpListener;
use tracing::{debug, error};
use uuid::Uuid;

mod handler;
mod session;

pub struct Share {
    pub path: String,
    pub read_only: bool,
}

pub struct Server {
    server_guid: u128,
    shares: Vec<Share>,
    address: String,
    port: u32,
}

impl Server {
    pub fn new(address: &str, port: u32, shares: Vec<Share>) -> Self {
        Server {
            server_guid: Uuid::new_v4().as_u128(),
            shares,
            address: address.to_string(),
            port,
        }
    }

    pub async fn serve(&self) -> Result<(), Box<dyn Error>> {
        let listener =
            TcpListener::bind(format!("{}:{}", self.address, self.port))
                .await?;

        let server_guid = self.server_guid;
        loop {
            // Accept an incoming connection
            match listener.accept().await {
                Ok((mut stream, addr)) => {
                    debug!("Accepted connection from SMB3 client {}", addr);

                    // Spawn a new task for each connection
                    tokio::spawn(async move {
                        if let Err(e) =
                            handler::handle_client(&mut stream, server_guid)
                                .await
                        {
                            error!(
                                "Error handling SMB3 client {}: {}",
                                addr, e
                            );
                        }
                    });
                }
                Err(e) => {
                    error!(
                        "Failed to accept connection from SMB3 client: {}",
                        e
                    );
                }
            }
        }
    }
}
