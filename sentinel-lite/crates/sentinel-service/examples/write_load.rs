//! Test helper for the ransomware-decoy smoke test: an *unsigned* program that
//! writes heavily (rewrites an 8 MB scratch file in %TEMP% in a loop) so the
//! engine has a realistic "heaviest writer" to find and suspend. It touches
//! nothing but its own scratch file, which it deletes on exit.
//!
//!   write_load [seconds]   (default 60)

use std::io::Write;
use std::time::{Duration, Instant};

fn main() -> std::io::Result<()> {
    let secs: u64 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(60);
    let path = std::env::temp_dir().join(format!("sentinel-write-load-{}.bin", std::process::id()));
    let block = vec![0x5Au8; 1 << 20];
    let end = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < end {
        let mut f = std::fs::File::create(&path)?;
        for _ in 0..8 {
            f.write_all(&block)?;
        }
        f.sync_data()?;
        std::thread::sleep(Duration::from_millis(50));
    }
    std::fs::remove_file(&path)
}
