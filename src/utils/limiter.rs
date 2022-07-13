// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2022 irohaede <irohaede@proton.me>

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use tokio::time::Instant;

pub struct Limiter {
    bucket: Mutex<Bucket>,
    is_unlimited: AtomicBool,
}

impl Limiter {
    pub fn new(speed_limit: f64) -> Limiter {
        let bucket = Bucket {
            updated_at: Instant::now(),
            volumn: 0.0,
            speed_limit,
        };
        Limiter {
            bucket: Mutex::new(bucket),
            is_unlimited: AtomicBool::new(speed_limit == f64::INFINITY),
        }
    }

    pub fn set_speed_limit(&self, speed_limit: f64) {
        if speed_limit == f64::INFINITY {
            self.is_unlimited.swap(true, Ordering::Relaxed);
        } else {
            self.is_unlimited.swap(false, Ordering::Relaxed);
            self.bucket.lock().unwrap().speed_limit = speed_limit;
        }
    }

    pub fn consume(&self, bytes: usize) -> Duration {
        if self.is_unlimited.load(Ordering::Relaxed) {
            return Duration::ZERO;
        }
        let mut bucket = self.bucket.lock().unwrap();
        bucket.refill(Instant::now());
        bucket.consume(bytes)
    }
}

struct Bucket {
    updated_at: Instant,
    volumn: f64,
    speed_limit: f64,
}

impl Bucket {
    const INTERVAL: f64 = 0.2;

    fn consume(&mut self, bytes: usize) -> Duration {
        self.volumn -= bytes as f64;
        if self.volumn > 0.0 {
            Duration::ZERO
        } else {
            let sleep_secs = Self::INTERVAL - (self.volumn / self.speed_limit);
            Duration::from_secs_f64(sleep_secs)
        }
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = (now - self.updated_at).as_secs_f64();
        let refilled = self.speed_limit * elapsed;
        self.volumn = (self.speed_limit * Self::INTERVAL).min(self.volumn + refilled);
        self.updated_at = now;
    }
}
