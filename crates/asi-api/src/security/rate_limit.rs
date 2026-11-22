use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use asi_common::error::DomainError;

#[derive(Clone)]
pub struct LoginRateLimiter {
    max_attempts: usize,
    window: Duration,
    buckets: Arc<Mutex<HashMap<String, VecDeque<Instant>>>>,
}

impl Default for LoginRateLimiter {
    fn default() -> Self {
        Self::new(10, Duration::from_secs(300))
    }
}

impl LoginRateLimiter {
    #[must_use]
    pub fn new(max_attempts: usize, window: Duration) -> Self {
        Self {
            max_attempts: max_attempts.max(1),
            window,
            buckets: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn check_and_record(&self, key: &str) -> Result<(), DomainError> {
        let now = Instant::now();
        let mut guard = self
            .buckets
            .lock()
            .map_err(|_| DomainError::Internal("rate limiter lock poisoned".to_string()))?;

        let entries = guard.entry(key.to_string()).or_default();
        while let Some(&front) = entries.front() {
            if now.duration_since(front) >= self.window {
                entries.pop_front();
            } else {
                break;
            }
        }

        if entries.len() >= self.max_attempts {
            return Err(DomainError::TooManyRequests(
                "Too many login attempts. Please try again later.".to_string(),
            ));
        }

        entries.push_back(now);
        Ok(())
    }

    pub fn reset(&self, key: &str) {
        if let Ok(mut guard) = self.buckets.lock() {
            guard.remove(key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforces_max_attempts_and_resets() {
        let limiter = LoginRateLimiter::new(2, Duration::from_secs(60));
        assert!(limiter.check_and_record("127.0.0.1:admin").is_ok());
        assert!(limiter.check_and_record("127.0.0.1:admin").is_ok());
        assert!(limiter.check_and_record("127.0.0.1:admin").is_err());

        limiter.reset("127.0.0.1:admin");
        assert!(limiter.check_and_record("127.0.0.1:admin").is_ok());
    }
}
