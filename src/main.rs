use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::{ffi::OsString, fs::OpenOptions, io::Write, time::Duration};
use windows::{
    core::PCWSTR,
    Win32::{Foundation::HANDLE, System::EventLog::*},
};
use windows_service::{
    define_windows_service,
    service::{
        ServiceAccess, ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceInfo,
        ServiceState, ServiceStatus, ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult, ServiceStatusHandle},
    service_dispatcher,
    service_manager::{ServiceManager, ServiceManagerAccess},
};

#[derive(Deserialize, Serialize)]
struct Config {
    event_source: String,
    monitored_event_ids: Vec<u32>,
    debug: bool,
    debug_path: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            event_source: "Application".to_string(),
            monitored_event_ids: vec![1001, 1006],
            debug: true, // set this to false on release build somehow?
            debug_path: Some("C:\\Temp".to_string()),
        }
    }
}

impl Config {
    fn load() -> Self {
        let exe_path = std::env::current_exe().unwrap_or_default();
        let example_config_path = exe_path
            .parent()
            .unwrap_or_else(|| Path::new(""))
            .join("example-config.toml");

        let config_path = exe_path
            .parent()
            .unwrap_or_else(|| Path::new(""))
            .join("config.toml");

        if (config_path).exists() {
            if let Ok(content) = std::fs::read_to_string(&config_path) {
                let config = toml::from_str(&content).unwrap_or_else(|e| {
                    write_to_debug_log(&format!("Error parsing config: {}. Using defaults.", e));
                    Config::default()
                });
                // Write directly to file instead of using write_to_debug_log
                if config.debug {
                    if let Some(debug_path) = &config.debug_path {
                        let log_path = Path::new(debug_path).join("winvent_debug.log");
                        if let Ok(mut file) =
                            OpenOptions::new().create(true).append(true).open(log_path)
                        {
                            let _ = writeln!(file, "Loaded config.toml: source={}, debug={}, debug_path={:?}, monitored_event_ids={:?}",
                                config.event_source,
                                config.debug,
                                config.debug_path,
                                config.monitored_event_ids,
                            );
                        }
                    }
                }

                return config;
            } else {
                write_to_debug_log("config.toml file not found, looking for example-config.toml");
                Config::default()
            }
        } else if (example_config_path).exists() {
            if let Ok(content) = std::fs::read_to_string(&example_config_path) {
                let config = toml::from_str(&content).unwrap_or_else(|e| {
                    write_to_debug_log(&format!("Error parsing config: {}. Using defaults.", e));
                    Config::default()
                });
                // Write directly to file instead of using write_to_debug_log
                if config.debug {
                    if let Some(debug_path) = &config.debug_path {
                        let log_path = Path::new(debug_path).join("winvent_debug.log");
                        if let Ok(mut file) =
                            OpenOptions::new().create(true).append(true).open(log_path)
                        {
                            let _ = writeln!(file, "Loaded example-config.toml: source={}, debug={}, debug_path={:?}, monitored_event_ids={:?}",
                                config.event_source,
                                config.debug,
                                config.debug_path,
                                config.monitored_event_ids,
                            );
                        }
                    }
                }

                return config;
            } else {
                write_to_debug_log("example-config.toml file not found, using defaults");
                Config::default()
            }
        } else {
            write_to_debug_log("No config files found. Using application defaults.");
            Config::default()
        }
    }

    fn save_default(path: &PathBuf) -> std::io::Result<()> {
        let config = Config::default();
        let toml = toml::to_string_pretty(&config)
            .unwrap_or_else(|_| String::from("# Failed to serialize config"));
        std::fs::write(path, toml)
    }
}

//const MONITORED_EVENT_IDS: &[u32] = &[1005, 1006];
//const EVENT_SOURCE: &str = "Application";
const SERVICE_NAME: &str = "WindowsEventLogger";
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;
const EVENTLOG_SEEK_READ: u32 = 0x00000002;
const EVENTLOG_FORWARDS_READ: u32 = 0x00000004; // Needed for forward reading

define_windows_service!(ffi_service_main, service_main);

fn main() -> Result<(), windows_service::Error> {
    if std::env::args()
        .nth(1)
        .map_or(false, |arg| arg == "install")
    {
        install_service()?;
        println!("Service installed successfully");
    } else {
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
    }
    Ok(())
}

fn install_service() -> windows_service::Result<()> {
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

struct EventLogger {
    handle: HANDLE,
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

fn log_event(event_type: u16, message: &str) {
    if let Some(logger) = EventLogger::new(SERVICE_NAME) {
        logger.log(event_type, message);
    }
}

fn service_main(arguments: Vec<OsString>) {
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

fn write_to_debug_log(message: &str) {
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

fn run_service(
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
                                        write_to_debug_log(&format!(
                                            "Monitored Event - ID: {}, Record #: {}, Type: {:?}",
                                            event_id,
                                            event_record.RecordNumber,
                                            event_record.EventType
                                        ));
                                    }
                                }
                                last_record = newest;
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
