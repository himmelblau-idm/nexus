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
use picky_asn1::wrapper::{
    ExplicitContextTag0, ObjectIdentifierAsn1, Optional,
};
use picky_asn1_der::to_vec;
use picky_krb::gss_api::{
    ApplicationTag0, GssApiNegInit, MechTypeList, NegTokenInit,
};
use tracing::error;

impl Connection<'_> {
    pub(crate) fn create_security_blob(&self) -> Result<Vec<u8>, NtStatus> {
        // SPNEGO - Simple Protected Negotiation
        let oid =
            ObjectIdentifierAsn1("1.3.6.1.5.5.2".try_into().map_err(|e| {
                error!("{:?}", e);
                NT_STATUS_UNSUCCESSFUL
            })?);
        let mech_type_list: MechTypeList = vec![
            // MS KRB5 - Microsoft Kerberos 5
            ObjectIdentifierAsn1("1.2.840.48018.1.2.2".try_into().map_err(
                |e| {
                    error!("{:?}", e);
                    NT_STATUS_UNSUCCESSFUL
                },
            )?),
            // KRB5 - Kerberos 5
            ObjectIdentifierAsn1("1.2.840.113554.1.2.2".try_into().map_err(
                |e| {
                    error!("{:?}", e);
                    NT_STATUS_UNSUCCESSFUL
                },
            )?),
        ]
        .into();
        let blob = ApplicationTag0(GssApiNegInit {
            oid,
            neg_token_init: ExplicitContextTag0(NegTokenInit {
                mech_types: Optional(Some(ExplicitContextTag0(mech_type_list))),
                req_flags: Optional(None),
                mech_token: Optional(None),
                mech_list_mic: Optional(None),
            }),
        });
        to_vec(&blob).map_err(|e| {
            error!("{:?}", e);
            NT_STATUS_UNSUCCESSFUL
        })
    }
}
