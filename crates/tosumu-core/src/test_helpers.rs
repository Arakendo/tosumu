// Test helpers shared across tosumu-core integration tests.
//
// Only compiled under `#[cfg(test)]` — see lib.rs.

use std::io::{self, Read, Seek, SeekFrom, Write};

// ── CrashPhase ───────────────────────────────────────────────────────────────

/// The point in an I/O sequence at which `CrashWriter` should inject a failure.
///
/// Use this to simulate crashes at each durability-relevant phase:
///
/// ```text
/// BeforeWrite   — write(2) never called; simulates process death before any I/O
/// MidWrite      — write returns Ok(n) for n < buf.len() then Err on the next call
/// AfterWrite    — write completes but fsync/flush fails (torn durability)
/// DuringSync    — sync_all() / flush() returns Err
/// DuringTruncate — set_len() returns Err (checkpoint-truncation crash)
/// ```
///
/// For byte-count crashes, set phase = `MidWrite` and `fail_after_bytes = Some(n)`.
#[derive(Clone, Debug)]
pub(crate) enum CrashPhase {
    /// Fail before any bytes are written on the first write call.
    BeforeWrite,
    /// Write `fail_after_bytes` bytes successfully, then fail the next write.
    /// If `fail_after_bytes` is `None`, fails on the very first byte.
    MidWrite { fail_after_bytes: u64 },
    /// All writes succeed; fail on `flush()` / `sync_all()`.
    AfterWrite,
    /// Fail on `set_len()` (simulates crash during WAL truncation).
    DuringTruncate,
}

// ── CrashWriter ──────────────────────────────────────────────────────────────

/// A `Write + Seek` wrapper that injects a `BrokenPipe` error at a controlled
/// point in the I/O sequence, simulating a process crash.
///
/// Wraps any `Write + Seek` (usually a `std::fs::File` or a `Cursor<Vec<u8>>`).
///
/// # Example — crash after 32 bytes
/// ```ignore
/// let f = File::create(&path)?;
/// let mut cw = CrashWriter::new(f, CrashPhase::MidWrite { fail_after_bytes: 32 });
/// // Writes up to 32 bytes normally, then returns BrokenPipe.
/// ```
pub(crate) struct CrashWriter<W: Write + Seek> {
    inner: W,
    phase: CrashPhase,
    bytes_written: u64,
    triggered: bool,
}

impl<W: Write + Seek> CrashWriter<W> {
    pub(crate) fn new(inner: W, phase: CrashPhase) -> Self {
        CrashWriter { inner, phase, bytes_written: 0, triggered: false }
    }

    /// Return the inner writer (only valid after the crash has fired, or for inspection).
    pub(crate) fn into_inner(self) -> W { self.inner }

    fn crash() -> io::Error {
        io::Error::new(io::ErrorKind::BrokenPipe, "CrashWriter: simulated crash")
    }
}

impl<W: Write + Seek> Write for CrashWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.triggered { return Err(Self::crash()); }
        match &self.phase {
            CrashPhase::BeforeWrite => {
                self.triggered = true;
                Err(Self::crash())
            }
            CrashPhase::MidWrite { fail_after_bytes } => {
                let remaining = fail_after_bytes.saturating_sub(self.bytes_written);
                if remaining == 0 {
                    self.triggered = true;
                    return Err(Self::crash());
                }
                let to_write = buf.len().min(remaining as usize);
                let n = self.inner.write(&buf[..to_write])?;
                self.bytes_written += n as u64;
                if self.bytes_written >= *fail_after_bytes {
                    self.triggered = true;
                }
                Ok(n)
            }
            CrashPhase::AfterWrite | CrashPhase::DuringTruncate => {
                // Pass through writes normally; crash only on flush/set_len.
                let n = self.inner.write(buf)?;
                self.bytes_written += n as u64;
                Ok(n)
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.triggered { return Err(Self::crash()); }
        match &self.phase {
            CrashPhase::AfterWrite => {
                self.triggered = true;
                Err(Self::crash())
            }
            _ => self.inner.flush(),
        }
    }
}

impl<W: Write + Seek> Seek for CrashWriter<W> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
}

// ── CrashFile ────────────────────────────────────────────────────────────────

/// Convenience wrapper so test code can call `set_len` and `sync_all` on a CrashWriter<File>.
///
/// For `DuringTruncate`: `set_len()` fires the crash.
/// For `AfterWrite`: `sync_data()` / `sync_all()` fires the crash (via `flush()`).
pub(crate) struct CrashFile {
    inner: CrashWriter<std::fs::File>,
}

impl CrashFile {
    pub(crate) fn new(file: std::fs::File, phase: CrashPhase) -> Self {
        CrashFile { inner: CrashWriter::new(file, phase) }
    }

    pub(crate) fn set_len(&mut self, size: u64) -> io::Result<()> {
        if matches!(self.inner.phase, CrashPhase::DuringTruncate) {
            self.inner.triggered = true;
            return Err(CrashWriter::<std::fs::File>::crash());
        }
        self.inner.inner.set_len(size)
    }

    pub(crate) fn sync_data(&mut self) -> io::Result<()> {
        // Route through flush() so AfterWrite fires correctly.
        self.inner.flush()?;
        if !self.inner.triggered {
            self.inner.inner.sync_data()?;
        }
        Ok(())
    }
}

impl Write for CrashFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> { self.inner.write(buf) }
    fn flush(&mut self) -> io::Result<()> { self.inner.flush() }
}

impl Seek for CrashFile {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> { self.inner.seek(pos) }
}

impl Read for CrashFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> { self.inner.inner.read(buf) }
}
