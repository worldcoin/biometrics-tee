//! Framed request/response exchange with the worker; payloads stay opaque.

// Only the Linux worker drives the channel; elsewhere it is built for its tests.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::{
    io,
    os::unix::net::UnixStream,
    sync::Arc,
    time::{Duration, Instant},
};

use crate::transport;

/// Enclave-owned limits, sized by the caller for its operation.
#[derive(Debug, Clone)]
pub struct ChannelConfig {
    /// Budget for the worker's readiness frame, which follows model initialization.
    pub startup_timeout: Duration,
    /// Budget for one request write plus its response read.
    pub request_timeout: Duration,
    /// Largest readiness frame accepted.
    pub max_ready_bytes: usize,
    /// Largest request the enclave sends.
    pub max_request_bytes: usize,
    /// Largest response the enclave reads, checked before allocating it.
    pub max_response_bytes: usize,
}

impl Default for ChannelConfig {
    fn default() -> Self {
        Self {
            startup_timeout: Duration::from_secs(120),
            request_timeout: Duration::from_secs(10),
            max_ready_bytes: 64,
            max_request_bytes: 8 * 1024 * 1024,
            max_response_bytes: 256 * 1024,
        }
    }
}

impl ChannelConfig {
    /// Checks that every limit is usable on the wire.
    ///
    /// # Errors
    /// Returns [`ChannelError::InvalidConfig`] for zero or oversized limits and timeouts.
    pub fn validate(&self) -> Result<(), ChannelError> {
        if !transport::valid_limit(self.max_ready_bytes)
            || !transport::valid_limit(self.max_request_bytes)
            || !transport::valid_limit(self.max_response_bytes)
            || !transport::valid_timeout(self.startup_timeout)
            || !transport::valid_timeout(self.request_timeout)
        {
            return Err(ChannelError::InvalidConfig);
        }

        Ok(())
    }
}

/// One exclusive synchronous connection. A failure permanently closes it.
#[derive(Debug)]
pub(crate) struct Channel {
    stream: Option<UnixStream>,
    config: ChannelConfig,
    failure: Option<ChannelError>,
}

impl Channel {
    /// Waits for the worker's readiness frame and returns it undecoded.
    pub(crate) fn open(
        mut stream: UnixStream,
        config: ChannelConfig,
    ) -> Result<(Self, Vec<u8>), ChannelError> {
        config.validate()?;
        stream
            .set_nonblocking(false)
            .map_err(ChannelError::transport)?;
        let ready = transport::read_frame(
            &mut stream,
            config.max_ready_bytes,
            Instant::now() + config.startup_timeout,
        )
        .map_err(|error| match ChannelError::transport(error) {
            ChannelError::RequestTimeout => ChannelError::StartupTimeout,
            error => error,
        })?;

        Ok((
            Self {
                stream: Some(stream),
                config,
                failure: None,
            },
            ready,
        ))
    }

    pub(crate) fn failure(&self) -> Option<&ChannelError> {
        self.failure.as_ref()
    }

    /// Sends one request and reads one response under a single deadline.
    /// An oversized request is rejected before sending and leaves the channel usable.
    pub(crate) fn exchange(&mut self, request: &[u8]) -> Result<Vec<u8>, ChannelError> {
        if let Some(error) = &self.failure {
            return Err(error.clone());
        }
        if request.is_empty() || request.len() > self.config.max_request_bytes {
            return Err(ChannelError::InvalidRequest);
        }

        let deadline = Instant::now() + self.config.request_timeout;
        let stream = self
            .stream
            .as_mut()
            .expect("failed channels return before exchange");
        let result = transport::write_frame(stream, request, deadline)
            .and_then(|()| transport::read_frame(stream, self.config.max_response_bytes, deadline))
            .map_err(ChannelError::transport);
        if let Err(error) = &result {
            self.close(error.clone());
        }

        result
    }

    /// Closes the connection for good, keeping the first failure.
    pub(crate) fn close(&mut self, error: ChannelError) {
        self.failure.get_or_insert(error);
        self.stream.take();
    }
}

/// Payload-free errors; only [`ChannelError::InvalidRequest`] leaves the channel usable.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ChannelError {
    /// The socket failed or the worker closed it.
    #[error("worker socket I/O failed: {0}")]
    Transport(Arc<io::Error>),
    /// Limits or timeouts cannot be used.
    #[error("invalid worker channel configuration")]
    InvalidConfig,
    /// The request is empty or over the byte limit; nothing was sent.
    #[error("worker request is empty or exceeds the byte limit")]
    InvalidRequest,
    /// The worker did not answer within the request deadline.
    #[error("worker request timed out")]
    RequestTimeout,
    /// The worker did not send its readiness frame in time.
    #[error("worker startup timed out")]
    StartupTimeout,
    /// The caller rejected a response, so the worker's state is untrusted.
    #[error("worker response violates the protocol")]
    Protocol,
}

impl ChannelError {
    fn transport(error: io::Error) -> Self {
        if matches!(
            error.kind(),
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
        ) {
            Self::RequestTimeout
        } else {
            Self::Transport(Arc::new(error))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};

    use super::*;

    fn config() -> ChannelConfig {
        ChannelConfig {
            startup_timeout: Duration::from_millis(200),
            request_timeout: Duration::from_millis(200),
            max_ready_bytes: 16,
            max_request_bytes: 64,
            max_response_bytes: 64,
        }
    }

    fn frame(payload: &[u8]) -> Vec<u8> {
        let mut bytes = (payload.len() as u32).to_be_bytes().to_vec();
        bytes.extend_from_slice(payload);
        bytes
    }

    /// Reads one framed request from the worker side of the pair.
    fn read_request(worker: &mut UnixStream) -> Vec<u8> {
        let mut length = [0; 4];
        worker.read_exact(&mut length).unwrap();
        let mut body = vec![0; u32::from_be_bytes(length) as usize];
        worker.read_exact(&mut body).unwrap();
        body
    }

    fn opened() -> (Channel, UnixStream) {
        let (enclave, mut worker) = UnixStream::pair().unwrap();
        worker.write_all(&frame(b"ready")).unwrap();
        let (channel, ready) = Channel::open(enclave, config()).unwrap();
        assert_eq!(ready, b"ready");
        (channel, worker)
    }

    #[test]
    fn exchanges_opaque_frames() {
        let (mut channel, mut worker) = opened();
        let echo = std::thread::spawn(move || {
            let request = read_request(&mut worker);
            worker.write_all(&frame(&request)).unwrap();
            worker
        });

        assert_eq!(channel.exchange(b"payload").unwrap(), b"payload");
        drop(echo.join().unwrap());
        assert!(channel.failure().is_none());
    }

    #[test]
    fn invalid_requests_are_rejected_without_closing() {
        let (mut channel, _worker) = opened();

        assert!(matches!(
            channel.exchange(&[]),
            Err(ChannelError::InvalidRequest)
        ));
        assert!(matches!(
            channel.exchange(&[0; 65]),
            Err(ChannelError::InvalidRequest)
        ));
        assert!(channel.failure().is_none());
    }

    #[test]
    fn a_silent_worker_times_out_and_closes_the_channel() {
        let (mut channel, _worker) = opened();

        assert!(matches!(
            channel.exchange(b"payload"),
            Err(ChannelError::RequestTimeout)
        ));
        assert!(matches!(
            channel.exchange(b"payload"),
            Err(ChannelError::RequestTimeout)
        ));
    }

    #[test]
    fn an_oversized_response_is_refused_before_allocation() {
        let (mut channel, mut worker) = opened();
        let reply = std::thread::spawn(move || {
            read_request(&mut worker);
            worker.write_all(&65_u32.to_be_bytes()).unwrap();
            worker
        });

        assert!(matches!(
            channel.exchange(b"payload"),
            Err(ChannelError::Transport(_))
        ));
        drop(reply.join().unwrap());
        assert!(channel.failure().is_some());
    }

    #[test]
    fn a_missing_readiness_frame_is_a_startup_timeout() {
        let (enclave, _worker) = UnixStream::pair().unwrap();

        assert!(matches!(
            Channel::open(enclave, config()),
            Err(ChannelError::StartupTimeout)
        ));
    }

    #[test]
    fn an_oversized_readiness_frame_is_refused() {
        let (enclave, mut worker) = UnixStream::pair().unwrap();
        worker.write_all(&frame(&[0; 17])).unwrap();

        assert!(matches!(
            Channel::open(enclave, config()),
            Err(ChannelError::Transport(_))
        ));
    }

    #[test]
    fn a_closed_channel_keeps_its_first_failure() {
        let (mut channel, _worker) = opened();
        channel.close(ChannelError::Protocol);
        channel.close(ChannelError::RequestTimeout);

        assert!(matches!(
            channel.exchange(b"payload"),
            Err(ChannelError::Protocol)
        ));
    }

    #[test]
    fn zero_limits_and_timeouts_are_invalid() {
        for invalid in [
            ChannelConfig {
                max_ready_bytes: 0,
                ..config()
            },
            ChannelConfig {
                max_request_bytes: 0,
                ..config()
            },
            ChannelConfig {
                max_response_bytes: 0,
                ..config()
            },
            ChannelConfig {
                request_timeout: Duration::ZERO,
                ..config()
            },
            ChannelConfig {
                startup_timeout: Duration::ZERO,
                ..config()
            },
        ] {
            assert!(matches!(
                invalid.validate(),
                Err(ChannelError::InvalidConfig)
            ));
        }
        ChannelConfig::default().validate().unwrap();
    }
}
