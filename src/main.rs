use std::{ffi::OsString, time::Duration, fs::OpenOptions, io::Write};
use std::io::Error as IoError;
use windows::{
    Win32::System::EventLog::*,
    // Win32::System::EventLog::{
    //     EVENTLOGRECORD, CloseEventLog, ReadEventLogW, OpenEventLogW, GetOldestEventLogRecord, EVENTLOG_SEQUENTIAL_READ, EVENTLOG_INFORMATION_TYPE, EVENTLOG_ERROR_TYPE,
    // },
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
const EVENTLOG_BACKWARDS_READ: u32 = 0x00000008;
// const EVENTLOG_SEEK_READ: u32 = 0x00000002;
// const EVENTLOG_FORWARDS_READ: u32 = 0x00000004; // Needed for forward reading

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
                running_clone.store(false, std::sync::atomic::Ordering::SeqCst); // Changed to SeqCst
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
        current_state: ServiceState::StartPending,  // Added StartPending state
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

    while running.load(std::sync::atomic::Ordering::SeqCst) {
        if let Ok(handle) = unsafe { OpenEventLogW(
            PCWSTR::null(),
            &windows::core::HSTRING::from("Application"),
        )} {
            write_to_debug_log("Successfully opened Application event log");
            
            let mut record_count: u32 = 0;
            let count_result = unsafe { GetNumberOfEventLogRecords(handle, &mut record_count) };
            
            match count_result {
                Ok(_) => {
                    write_to_debug_log(&format!("Number of records in log: {}", record_count));
                    
                    if record_count > 0 {
                        let mut bytes_read: u32 = 0;
                        let mut bytes_needed: u32 = 0;
                        let mut buffer = vec![0u8; 0x10000];
                        
                        let read_result = unsafe {
                            ReadEventLogW(
                                handle,
                                READ_EVENT_LOG_READ_FLAGS(EVENTLOG_SEQUENTIAL_READ.0 | EVENTLOG_BACKWARDS_READ),
                                0,
                                buffer.as_mut_ptr() as *mut _,
                                buffer.len() as u32,
                                &mut bytes_read,
                                &mut bytes_needed
                            )
                        };

                        write_to_debug_log(&format!("Read attempt completed. Bytes read: {}, Bytes needed: {}", 
                            bytes_read, bytes_needed));

                        match read_result {
                            Ok(_) => {
                                write_to_debug_log("ReadEventLogW succeeded");
                                if bytes_read > 0 {
                                    let event_record = unsafe {
                                        &*(buffer.as_ptr() as *const EVENTLOGRECORD)
                                    };

                                    write_to_debug_log(&format!(
                                        "Event found - ID: {}, Length: {}, Record #: {}", 
                                        event_record.EventID,
                                        event_record.Length,
                                        event_record.RecordNumber
                                    ));
                                }
                            },
                            Err(e) => {
                                let last_error = unsafe { GetLastError() };
                                let io_error = IoError::from_raw_os_error(last_error.0 as i32);
                                
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
                        write_to_debug_log("No records in event log");
                    }
                },
                Err(e) => {
                    write_to_debug_log(&format!("Failed to get record count: {:?}", e));
                }
            }

            unsafe { let _ = CloseEventLog(handle); };
        }

        std::thread::sleep(Duration::from_secs(1));
    }

    // Tell SCM we're stopping
    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::StopPending,  // Added StopPending state
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