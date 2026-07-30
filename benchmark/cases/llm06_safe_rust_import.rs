use reqwest::StatusCode;

#[tool]
fn ping() -> u16 {
    // no dangerous sink here; the reqwest import must not be read as an HTTP call
    200
}
