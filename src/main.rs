use std::{ffi::OsString, time::Duration, fs::OpenOptions, io::Write};
use windows::{
    Win32::System::EventLog::*,
    Win32::Foundation::{ 
        HANDLE, GetLastError
    },
    core::PCWSTR,
};
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
        ServiceAccess, ServiceInfo
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
    service_manager::{ServiceManager, ServiceManagerAccess},
};

// const MONITORED_EVENT_IDS: &[u32] = &[6005, 6006];
const SERVICE_NAME: &str = "WindowsEventLogger";
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;
// const EVENTLOG_BACKWARDS_READ: u32 = 0x00000008;
const EVENTLOG_SEEK_READ: u32 = 0x00000002;
const EVENTLOG_FORWARDS_READ: u32 = 0x00000004; // Needed for forward reading

define_windows_service!(ffi_service_main, service_main);

fn main() -> Result<(), windows_service::Error> {
    if std::env::args().nth(1).map_or(false, |arg| arg == "install") {
        install_service()?;
        println!("Service installed successfully");
    } else {
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
    }
    Ok(())
}

fn install_service() -> windows_service::Result<()> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE
    )?;

    let service_binary_path = std::env::current_exe()
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();

    let service_info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_NAME),
        service_type: SERVICE_TYPE,
        start_type: windows_service::service::ServiceStartType::OnDemand,
        error_control: windows_service::service::ServiceErrorControl::Normal,
        executable_path: std::path::PathBuf::from(service_binary_path),
        launch_arguments: vec![],
        dependencies: vec![],
        account_name: None,
        account_password: None,
    };

    let service = manager.create_service(&service_info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::STOP)?;
    
    // Check service status
    if let Ok(status) = service.query_status() {
        log_event(EVENTLOG_INFORMATION_TYPE.0, 
            &format!("Service installed with state: {:?}", status.current_state));
    }

    if EventLogger::new(SERVICE_NAME).is_some() {
        log_event(EVENTLOG_INFORMATION_TYPE.0, "Event source registered successfully");
    }
    Ok(())
}

struct EventLogger {
    handle: HANDLE
}

impl EventLogger {
    fn log(&self, event_type: u16, message: &str) {
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
    fn new(source_name: &str) -> Option<Self> {
        let source_name_wide: Vec<u16> = source_name.encode_utf16().chain(Some(0)).collect();
        let handle = unsafe { RegisterEventSourceW(PCWSTR::null(), PCWSTR(source_name_wide.as_ptr())) };
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

fn log_event(event_type: u16, message: &str) {
    if let Some(logger) = EventLogger::new(SERVICE_NAME) {
        logger.log(event_type, message);
    }
}

fn service_main(arguments: Vec<OsString>) {
    if let Err(e) = run_service(arguments) {
        let error_msg = format!("Service failed: {}", e);
        log_event(EVENTLOG_ERROR_TYPE.0, &error_msg);
    }
}

fn write_to_debug_log(message: &str) {
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open("C:\\Temp\\service_events.log")  // Using full path in C:\Temp
    {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let _ = writeln!(file, "[{}] {}", timestamp.as_secs(), message);
    }
}

fn run_service(_arguments: Vec<OsString>) -> Result<(), windows_service::Error> {
    let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let running_clone = running.clone();

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop => {
                log_event(EVENTLOG_INFORMATION_TYPE.0, "Stop command received");
                running_clone.store(false, std::sync::atomic::Ordering::SeqCst);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => {
                log_event(EVENTLOG_INFORMATION_TYPE.0, "Interrogate command received");
                ServiceControlHandlerResult::NoError
            }
            _ => {
                log_event(EVENTLOG_INFORMATION_TYPE.0, "Unhandled command received");
                ServiceControlHandlerResult::NotImplemented
            }
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

    // Tell SCM we're starting
    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::StartPending,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::from_secs(1),
        process_id: None,
    })?;

    // Tell SCM we're running
    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    log_event(EVENTLOG_INFORMATION_TYPE.0, "Service started");

    // Initialize last_record so we ignore events that occurred before service start.
    let mut last_record: u32 = {
        if let Ok(handle) = unsafe { OpenEventLogW(PCWSTR::null(), &windows::core::HSTRING::from("Application")) } {
            let mut record_count: u32 = 0;
            let mut oldest: u32 = 0;
            if unsafe { GetNumberOfEventLogRecords(handle, &mut record_count) }.is_ok()
                && unsafe { GetOldestEventLogRecord(handle, &mut oldest) }.is_ok()
            {
                // The newest record is oldest + count - 1.
                let newest = oldest + record_count - 1;
                unsafe { let _ = CloseEventLog(handle); };
                newest
            } else {
                unsafe { let _ = CloseEventLog(handle); };
                0
            }
        } else {
            0
        }
    };

    while running.load(std::sync::atomic::Ordering::SeqCst) {
        if let Ok(handle) = unsafe { OpenEventLogW(PCWSTR::null(), &windows::core::HSTRING::from("Application")) } {
            write_to_debug_log("Opened Application event log for polling");

            let mut record_count: u32 = 0;
            let count_result = unsafe { GetNumberOfEventLogRecords(handle, &mut record_count) };

            if count_result.is_ok() {
                write_to_debug_log(&format!("Number of records in log: {}", record_count));

                let mut oldest: u32 = 0;
                if unsafe { GetOldestEventLogRecord(handle, &mut oldest) }.is_ok() {
                    // Calculate the newest record number.
                    let newest = oldest + record_count - 1;
                    if newest > last_record {
                        // Read new events starting with last_record + 1.
                        let start_record = last_record + 1;
                        let mut bytes_read: u32 = 0;
                        let mut bytes_needed: u32 = 0;
                        let mut buffer = vec![0u8; 0x10000];

                        let read_result = unsafe {
                            ReadEventLogW(
                                handle,
                                READ_EVENT_LOG_READ_FLAGS(EVENTLOG_SEEK_READ | EVENTLOG_FORWARDS_READ),
                                start_record,
                                buffer.as_mut_ptr() as *mut _,
                                buffer.len() as u32,
                                &mut bytes_read,
                                &mut bytes_needed,
                            )
                        };

                        write_to_debug_log(&format!(
                            "Read attempt from record {} completed. Bytes read: {}, Bytes needed: {}",
                            start_record, bytes_read, bytes_needed
                        ));

                        match read_result {
                            Ok(_) => {
                                write_to_debug_log("ReadEventLogW succeeded");
                                if bytes_read > 0 {
                                    // Process the returned event records. For simplicity,
                                    // we assume at least one event is returned.
                                    let event_record = unsafe {
                                        &*(buffer.as_ptr() as *const EVENTLOGRECORD)
                                    };

                                    write_to_debug_log(&format!(
                                        "New event - ID: {}, Length: {}, Record #: {}",
                                        event_record.EventID,
                                        event_record.Length,
                                        event_record.RecordNumber
                                    ));
                                    // Further processing (and looping over multiple events) can be added here.
                                }
                                // Update the last_record marker.
                                last_record = newest;
                            },
                            Err(e) => {
                                let last_error = unsafe { GetLastError() };
                                let io_error = std::io::Error::from_raw_os_error(last_error.0 as i32);

                                write_to_debug_log(&format!(
                                    "Error details:\n\
                                     - Windows error: {:?}\n\
                                     - Error code: {:#x}\n\
                                     - Raw code: {}\n\
                                     - IO Error: {}\n\
                                     - Description: {}",
                                    e,
                                    last_error.0,
                                    last_error.0,
                                    io_error,
                                    io_error.to_string()
                                ));
                            }
                        }
                    } else {
                        write_to_debug_log("No new events");
                    }
                }
            } else {
                write_to_debug_log("Failed to get record count");
            }

            unsafe { let _ = CloseEventLog(handle); };
        }

        std::thread::sleep(Duration::from_secs(1));
    }

    // Tell SCM we're stopping
    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::StopPending,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::from_secs(1),
        process_id: None,
    })?;

    log_event(EVENTLOG_INFORMATION_TYPE.0, "Service is stopping");

    // Tell SCM we've stopped
    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    log_event(EVENTLOG_INFORMATION_TYPE.0, "Service stopped");
    Ok(())
}