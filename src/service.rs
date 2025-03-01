use crate::config::{Config, SERVICE_NAME};
use crate::logging::{log_event, write_to_debug_log, EventLogger};
use std::ffi::OsString;
use std::sync::{atomic::AtomicBool, Arc};
use std::time::Duration;
use windows::core::PCWSTR;
use windows::Win32::System::EventLog::*;
use windows_service::{
    service::{
        ServiceAccess, ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceInfo,
        ServiceState, ServiceStatus, ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult, ServiceStatusHandle},
    service_manager::{ServiceManager, ServiceManagerAccess},
};

const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;
const EVENTLOG_SEEK_READ: u32 = 0x00000002;
const EVENTLOG_FORWARDS_READ: u32 = 0x00000004; // Needed for forward reading

pub fn service_main(arguments: Vec<OsString>) {
    let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let running_clone = running.clone();

    let status_handle =
        match service_control_handler::register(SERVICE_NAME, move |control_event| {
            match control_event {
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    log_event(EVENTLOG_INFORMATION_TYPE.0, "Received stop command");
                    running_clone.store(false, std::sync::atomic::Ordering::SeqCst);
                    ServiceControlHandlerResult::NoError
                }
                _ => ServiceControlHandlerResult::NotImplemented,
            }
        }) {
            Ok(handle) => handle,
            Err(e) => {
                log_event(
                    EVENTLOG_ERROR_TYPE.0,
                    &format!("Failed to register service control handler: {:?}", e),
                );
                return;
            }
        };

    if let Err(e) = run_service(arguments, status_handle, running) {
        let error_msg = format!("Service failed: {}", e);
        log_event(EVENTLOG_ERROR_TYPE.0, &error_msg);
    }
}

pub fn run_service(
    _arguments: Vec<OsString>,
    status_handle: ServiceStatusHandle,
    running: Arc<AtomicBool>,
) -> Result<(), windows_service::Error> {
    write_to_debug_log("Service starting...");
    // Set to Running immediately
    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    let config = Config::load();
    write_to_debug_log(&format!(
        "Loaded configuration: monitoring {} event source",
        config.event_source
    ));

    // Log startup based on config
    log_event(EVENTLOG_INFORMATION_TYPE.0, &format!(
        "Service started: monitoring {} event source, debug={}, cloudwatch={}",
        config.event_source, config.debug, config.cloudwatch
    ));

    // Initialize CloudWatch client only if enabled
    let mut cloudwatch_client = if config.cloudwatch {
        let cloudwatch_runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
            
        match cloudwatch_runtime.block_on(async {
            crate::cloudwatch::CloudWatchClient::new(&config).await
        }) {
            Ok(client) => {
                log_event(EVENTLOG_INFORMATION_TYPE.0, "CloudWatch client initialized successfully");
                Some((client, cloudwatch_runtime))
            },
            Err(e) => {
                log_event(EVENTLOG_ERROR_TYPE.0, &format!("Failed to initialize CloudWatch client: {:?}", e));
                None
            }
        }
    } else {
        None
    };

    // Initialize last_record to current newest record
    let mut last_record: u32 = {
        if let Ok(handle) = unsafe {
            OpenEventLogW(
                PCWSTR::null(),
                &windows::core::HSTRING::from(&config.event_source),
            )
        } {
            let mut record_count: u32 = 0;
            let mut oldest: u32 = 0;
            if unsafe { GetNumberOfEventLogRecords(handle, &mut record_count) }.is_ok()
                && unsafe { GetOldestEventLogRecord(handle, &mut oldest) }.is_ok()
            {
                let newest = oldest + record_count - 1;
                unsafe {
                    let _ = CloseEventLog(handle);
                };
                newest
            } else {
                unsafe {
                    let _ = CloseEventLog(handle);
                };
                0
            }
        } else {
            0
        }
    };

    while running.load(std::sync::atomic::Ordering::SeqCst) {
        if let Ok(handle) = unsafe {
            OpenEventLogW(
                PCWSTR::null(),
                &windows::core::HSTRING::from(&config.event_source),
            )
        } {
            let mut record_count: u32 = 0;
            if unsafe { GetNumberOfEventLogRecords(handle, &mut record_count) }.is_ok() {
                let mut oldest: u32 = 0;
                if unsafe { GetOldestEventLogRecord(handle, &mut oldest) }.is_ok() {
                    let newest = oldest + record_count - 1;
                    if newest > last_record {
                        let mut bytes_read: u32 = 0;
                        let mut bytes_needed: u32 = 0;
                        let mut buffer = [0u8; 8192];

                        let read_result = unsafe {
                            ReadEventLogW(
                                handle,
                                READ_EVENT_LOG_READ_FLAGS(
                                    EVENTLOG_SEEK_READ | EVENTLOG_FORWARDS_READ,
                                ),
                                last_record + 1,
                                buffer.as_mut_ptr() as *mut _,
                                buffer.len() as u32,
                                &mut bytes_read,
                                &mut bytes_needed,
                            )
                        };

                        match read_result {
                            Ok(_) => {
                                if bytes_read > 0 {
                                    let event_record =
                                        unsafe { &*(buffer.as_ptr() as *const EVENTLOGRECORD) };
                                    let event_id = event_record.EventID & 0xFFFF;

                                    if config.monitored_event_ids.contains(&event_id) {
                                        // Get strings from the event record
                                        let strings_offset = event_record.StringOffset as usize;
                                        let mut current_offset = strings_offset;
                                        let mut strings = Vec::new();

                                        for _ in 0..event_record.NumStrings {
                                            let mut len = 0;
                                            let string_ptr = unsafe {
                                                let ptr = buffer.as_ptr().add(current_offset)
                                                    as *const u16;
                                                while *ptr.add(len) != 0 {
                                                    len += 1;
                                                }
                                                ptr
                                            };

                                            let string_slice = unsafe {
                                                std::slice::from_raw_parts(string_ptr, len)
                                            };

                                            if let Ok(s) = String::from_utf16(string_slice) {
                                                strings.push(s);
                                            }
                                            current_offset += (len + 1) * 2;
                                        }

                                        // Get source name
                                        let source_offset = event_record.UserSidOffset as usize;
                                        let source_ptr = unsafe {
                                            buffer.as_ptr().add(source_offset) as *const u16
                                        };

                                        let mut source_len = 0;
                                        unsafe {
                                            while *source_ptr.add(source_len) != 0 {
                                                source_len += 1;
                                            }
                                        }

                                        let source_name = unsafe {
                                            let slice =
                                                std::slice::from_raw_parts(source_ptr, source_len);
                                            String::from_utf16_lossy(slice)
                                        };
                                        let event_details = format!(
                                            "Event Details:\n\
                                             ID: {}\n\
                                             Type: {:?}\n\
                                             Source: {}\n\
                                             Record #: {}\n\
                                             Time Generated: {}\n\
                                             Time Written: {}\n\
                                             Category: {}\n\
                                             Strings: {:?}\n\
                                             Raw Data Length: {}",
                                            event_id,
                                            event_record.EventType,
                                            source_name,
                                            event_record.RecordNumber,
                                            event_record.TimeGenerated,
                                            event_record.TimeWritten,
                                            event_record.EventCategory,
                                            strings,
                                            event_record.DataLength
                                        );

                                        if config.debug {
                                            write_to_debug_log(&event_details);
                                        }

                                        if config.cloudwatch {
                                            if let Some((client, runtime)) = &mut cloudwatch_client {
                                                let formatted_event = crate::cloudwatch::format_event_for_cloudwatch(
                                                    event_id,
                                                    event_record.EventType.0 as u32,
                                                    &source_name,
                                                    event_record.RecordNumber,
                                                    event_record.TimeGenerated,
                                                    event_record.TimeWritten,
                                                    event_record.EventCategory,
                                                    &strings,
                                                );
                                                if let Err(e) = runtime.block_on(async {
                                                    client.send_event(&formatted_event).await
                                                }) {
                                                    log_event(EVENTLOG_WARNING_TYPE.0, &format!("Failed to send event to CloudWatch: {:?}", e));
                                                }
                                            }
                                        }
                                    }
                                    last_record = newest;
                                }
                            }
                            Err(e) => {
                                write_to_debug_log(&format!("Error reading events: {:?}", e));
                            }
                        }
                    }
                }
            }
            unsafe {
                let _ = CloseEventLog(handle);
            };
        }

        std::thread::sleep(Duration::from_secs(1));
    }

    // Set to Stopped when exiting
    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    Ok(())
}

pub fn install_service() -> windows_service::Result<()> {
    let exe_path = std::env::current_exe().unwrap();
    let config_path = exe_path.parent().unwrap().join("example-config.toml");

    // Create default config if it doesn't exist
    if !config_path.exists() {
        if let Err(e) = Config::save_default(&config_path) {
            log_event(
                EVENTLOG_WARNING_TYPE.0,
                &format!("Failed to create config: {}", e),
            );
        }
    }

    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
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

    let service = manager.create_service(
        &service_info,
        ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::STOP,
    )?;

    // Check service status
    if let Ok(status) = service.query_status() {
        log_event(
            EVENTLOG_INFORMATION_TYPE.0,
            &format!("Service installed with state: {:?}", status.current_state),
        );
    }

    if EventLogger::new(SERVICE_NAME).is_some() {
        log_event(
            EVENTLOG_INFORMATION_TYPE.0,
            "Event source registered successfully",
        );
    }
    Ok(())
}
