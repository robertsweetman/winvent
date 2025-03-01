mod config;
mod logging;
mod service;
mod cloudwatch;

use service::service_main;
use std::env::args;
use windows_service::{define_windows_service, service_dispatcher};

define_windows_service!(ffi_service_main, service_main);

fn main() -> Result<(), windows_service::Error> {
    let args: Vec<String> = args().collect();

    if args.len() > 1 && args[1] == "install" {
        service::install_service()?;
    } else {
        service_dispatcher::start(config::SERVICE_NAME, ffi_service_main)?;
    }

    Ok(())
}
