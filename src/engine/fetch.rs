//! The one place `engine::install`/`engine::rollback` reach the network:
//! a single HTTPS GET, response capped at `ureq`'s default 10 MiB limit
//! (`ops-engine` release binaries are a few MiB). No redirect target,
//! header, or response body content is ever trusted without the
//! checksum/signature checks in `verify.rs` — this module only fetches
//! bytes.

#[derive(Debug)]
pub enum Error {
    Request(ureq::Error),
    Read(ureq::Error),
}

pub fn fetch_bytes(url: &str) -> Result<Vec<u8>, Error> {
    let mut response = ureq::get(url).call().map_err(Error::Request)?;
    response.body_mut().read_to_vec().map_err(Error::Read)
}
