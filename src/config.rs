use crate::logging::write_to_debug_log;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::{fs::OpenOptions, io::Write};

pub const SERVICE_NAME: &str = "WindowsEventLogger";
// pub const SERVICE_DISPLAY_NAME: &str = "Windows Event Logger Service";

#[derive(Deserialize, Serialize)]
pub struct Config {
    pub event_source: String,
    pub monitored_event_ids: Vec<u32>,
    pub debug: bool,
    pub debug_path: Option<String>,
    pub cloudwatch: bool,
    pub aws_region: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            event_source: "Application".to_string(),
            monitored_event_ids: vec![1001, 1006],
            debug: true, // set this to false on release build somehow?
            debug_path: Some("C:\\Temp".to_string()),
            cloudwatch: false,
            aws_region: Some("eu-west-1".to_string()),
        }
    }
}

impl Config {
    pub fn load() -> Self {
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
                            let _ = writeln!(file, "Loaded config.toml: source={}, debug={}, debug_path={:?}, monitored_event_ids={:?}, cloudwatch={}, aws_region={:?}",
                                config.event_source,
                                config.debug,
                                config.debug_path,
                                config.monitored_event_ids,
                                config.cloudwatch,
                                config.aws_region,
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
                            let _ = writeln!(file, "Loaded example-config.toml: source={}, debug={}, debug_path={:?}, monitored_event_ids={:?}, cloudwatch={}, aws_region={:?}",
                                config.event_source,
                                config.debug,
                                config.debug_path,
                                config.monitored_event_ids,
                                config.cloudwatch,
                                config.aws_region,
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

    pub fn save_default(path: &PathBuf) -> std::io::Result<()> {
        let config = Config::default();
        let toml = toml::to_string_pretty(&config)
            .unwrap_or_else(|_| String::from("# Failed to serialize config"));
        std::fs::write(path, toml)
    }
}
