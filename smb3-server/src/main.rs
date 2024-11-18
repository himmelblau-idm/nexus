/*
   Unix SMB3 implementation
   Copyright (C) David Mulder <dmulder@samba.org> 2024

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
use std::error::Error;
use tokio::net::TcpListener;

mod handler;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Start the TCP listener
    let listener = TcpListener::bind("127.0.0.1:445").await?;

    loop {
        // Accept an incoming connection
        match listener.accept().await {
            Ok((mut stream, addr)) => {
                println!("Accepted connection from {}", addr);

                // Spawn a new task for each connection
                tokio::spawn(async move {
                    if let Err(e) = handler::handle_client(&mut stream).await {
                        eprintln!("Error handling client {}: {}", addr, e);
                    }
                });
            }
            Err(e) => {
                eprintln!("Failed to accept connection: {}", e);
            }
        }
    }
}
