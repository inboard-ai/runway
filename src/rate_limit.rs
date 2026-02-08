//! Token-bucket rate limiter keyed by IP address.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Instant;

struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

/// A simple in-process token-bucket rate limiter keyed by client IP.
pub struct RateLimiter {
    max_tokens: u32,
    window_secs: u64,
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
}

impl RateLimiter {
    /// Create a new rate limiter.
    ///
    /// * `max_tokens` — maximum requests allowed per window.
    /// * `window_secs` — refill window in seconds.
    pub fn new(max_tokens: u32, window_secs: u64) -> Self {
        Self {
            max_tokens,
            window_secs,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Check whether `ip` is within its rate limit.
    ///
    /// Returns `Ok(remaining)` on success or `Err(retry_after_secs)` when the
    /// bucket is empty.
    pub fn check(&self, ip: IpAddr) -> Result<u32, u64> {
        let mut buckets = self.buckets.lock().unwrap();
        let now = Instant::now();

        let bucket = buckets.entry(ip).or_insert(Bucket {
            tokens: self.max_tokens as f64,
            last_refill: now,
        });

        // Refill tokens based on elapsed time
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        let refill_rate = self.max_tokens as f64 / self.window_secs as f64;
        bucket.tokens = (bucket.tokens + elapsed * refill_rate).min(self.max_tokens as f64);
        bucket.last_refill = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            Ok(bucket.tokens as u32)
        } else {
            // Calculate retry-after: time until at least 1 token is available
            let deficit = 1.0 - bucket.tokens;
            let retry_after = (deficit / refill_rate).ceil() as u64;
            Err(retry_after.max(1))
        }
    }

    /// Remove stale entries that have fully refilled.
    pub fn cleanup(&self) {
        let mut buckets = self.buckets.lock().unwrap();
        let now = Instant::now();
        let window = std::time::Duration::from_secs(self.window_secs * 2);
        buckets.retain(|_, bucket| now.duration_since(bucket.last_refill) < window);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn within_limit() {
        let limiter = RateLimiter::new(3, 60);
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert!(limiter.check(ip).is_ok());
        assert!(limiter.check(ip).is_ok());
        assert!(limiter.check(ip).is_ok());
    }

    #[test]
    fn over_limit() {
        let limiter = RateLimiter::new(2, 60);
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert!(limiter.check(ip).is_ok());
        assert!(limiter.check(ip).is_ok());
        assert!(limiter.check(ip).is_err());
    }

    #[test]
    fn different_ips_independent() {
        let limiter = RateLimiter::new(1, 60);
        let ip1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        assert!(limiter.check(ip1).is_ok());
        assert!(limiter.check(ip2).is_ok());
        assert!(limiter.check(ip1).is_err());
    }

    #[test]
    fn cleanup_removes_stale() {
        let limiter = RateLimiter::new(1, 1);
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let _ = limiter.check(ip);
        // Manually age the entry
        {
            let mut buckets = limiter.buckets.lock().unwrap();
            if let Some(b) = buckets.get_mut(&ip) {
                b.last_refill = Instant::now() - std::time::Duration::from_secs(10);
            }
        }
        limiter.cleanup();
        let buckets = limiter.buckets.lock().unwrap();
        assert!(buckets.is_empty());
    }
}
