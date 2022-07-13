// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2022 irohaede <irohaede@proton.me>

use std::net::IpAddr;

use serde::{Deserialize, Deserializer, Serialize};

use crate::proto::Password;

pub type UserFetchResponse = Response<Vec<UserRaw>>;

pub type UpdateResponse = Response<String>;

#[derive(Deserialize)]
pub struct Response<D> {
    #[serde(rename = "ret")]
    pub status: isize,
    pub data: D,
}

#[derive(Deserialize, PartialEq)]
pub struct UserRaw {
    pub id: usize,
    #[serde(rename = "uuid", deserialize_with = "pwd_hash")]
    pub pwd: Password,
    #[serde(rename = "node_speedlimit")]
    pub speed_limit: f64,
    #[serde(rename = "node_connector")]
    pub ip_limit: usize,
    #[serde(default, rename = "alive_ip", deserialize_with = "ip_online_fallback")]
    pub ip_online: usize,
}

fn ip_online_fallback<'de, D>(der: D) -> Result<usize, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(<Option<usize>>::deserialize(der)?.unwrap_or(0))
}

fn pwd_hash<'de, D>(der: D) -> Result<Password, D::Error>
where
    D: Deserializer<'de>,
{
    use sha2::{Digest, Sha224};

    let raw = <&[u8]>::deserialize(der)?;
    let digest = Sha224::digest(raw);
    Ok(Password { raw: digest.into() })
}

impl UserRaw {
    pub fn ip_limit(&self) -> Option<usize> {
        if self.ip_limit == 0 {
            None
        } else if self.ip_limit < self.ip_online {
            // ip_online is not guaranteed to be less than ip_limit
            Some(0)
        } else {
            Some(self.ip_limit - self.ip_online)
        }
    }

    pub fn speed_limit(&self) -> f64 {
        if self.speed_limit == 0.0 {
            f64::INFINITY
        } else {
            self.speed_limit * 1024.0 * 1024.0
        }
    }
}

#[derive(Serialize)]
pub struct Request<D> {
    pub data: D,
}

#[derive(Serialize)]
pub struct UpdateData {
    pub user_id: usize,
    #[serde(rename = "u")]
    pub rx: u64,
    #[serde(rename = "d")]
    pub tx: u64,
    /// Password to seek back in ServerContext
    #[serde(skip)]
    pub pwd: Password,
}

#[derive(Serialize)]
pub struct IpData {
    pub user_id: usize,
    pub ip: IpAddr,
}
