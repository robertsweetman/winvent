use crate::config::{Config, SERVICE_NAME};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use windows::{
    core::PCWSTR,
    Win32::{Foundation::HANDLE, System::EventLog::*},
};

pub struct EventLogger {
    handle: HANDLE,
}

impl EventLogger {
    pub fn log(&self, event_type: u16, message: &str) {
        use std::ffi::CString;
        let c_message = CString::new(message).expect("CString conversion failed");
        unsafe {
            let message_ptr = c_message.as_ptr();
            let _ = ReportEventA(
                self.handle,
                REPORT_EVENT_TYPE(event_type),
                0,
                1,
                None,
                1,
                Some(&[windows::core::PCSTR(message_ptr as *const u8)]),
                None,
            );
        }
    }
    pub fn new(source_name: &str) -> Option<Self> {
        let source_name_wide: Vec<u16> = source_name.encode_utf16().chain(Some(0)).collect();
        let handle =
            unsafe { RegisterEventSourceW(PCWSTR::null(), PCWSTR(source_name_wide.as_ptr())) };
        let handle = match handle {
            Ok(h) => h,
            Err(_) => return None,
        };
        if handle.is_invalid() {
            None
        } else {
            Some(Self { handle })
        }
    }
}

impl Drop for EventLogger {
    fn drop(&mut self) {
        unsafe {
            let _ = DeregisterEventSource(self.handle);
        }
    }
}

pub fn write_to_debug_log(message: &str) {
    let config = Config::load();

    // Only write to debug logs if debug is enabled
    if !config.debug {
        return;
    }

    let debug_path = config.debug_path.unwrap_or_else(|| "C:\\Temp".to_string());
    let log_path = Path::new(&debug_path).join("winvent_debug.log");

    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(log_path)
    // Using full path in C:\Temp
    {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let _ = writeln!(file, "[{}] {}", timestamp.as_secs(), message);
    }
}

pub fn log_event(event_type: u16, message: &str) {
    if let Some(logger) = EventLogger::new(SERVICE_NAME) {
        logger.log(event_type, message);
    }
}
