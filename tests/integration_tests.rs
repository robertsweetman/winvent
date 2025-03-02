#[cfg(test)]
mod integration_tests {
    use std::process::Command;

    #[test]
    fn test_service_installation() {
        println!("Starting service installation test");
    
        let admin = is_running_as_admin();
        println!("Running as admin: {}", admin);
        // Skip if not running as admin
        if !admin {
            println!("Skipping service installation test - requires admin privileges");
            return;
        }
    
        // Check if service already exists
        let pre_check = Command::new("sc")
            .args(&["query", "WindowsEventLogger"])
            .output()
            .expect("Failed to execute sc query");
        
        println!("Pre-check service exists: {}", pre_check.status.success());
        if pre_check.status.success() {
            println!("Service already exists, removing first");
            let _ = Command::new("sc")
                .args(&["delete", "WindowsEventLogger"])
                .output();
            // Give Windows time to process the deletion
            std::thread::sleep(std::time::Duration::from_secs(2));
        }
    
        // Run the service installation
        println!("Executing service installation command...");
        let output = Command::new(env!("CARGO_BIN_EXE_winvent"))
            .arg("install")
            .output()
            .expect("Failed to execute process");
    
        // Print output for debugging
        println!("Command executed. Status: {}", output.status);
        println!("Status: {}", output.status);
        println!("Stdout: {}", String::from_utf8_lossy(&output.stdout));
        println!("Stderr: {}", String::from_utf8_lossy(&output.stderr));
    
        // Give Windows time to process the installation
        std::thread::sleep(std::time::Duration::from_secs(2));
    
        // Verify service exists
        let sc_query = Command::new("sc")
            .args(&["query", "WindowsEventLogger"])
            .output()
            .expect("Failed to execute sc query");
        
        println!("Service exists check: {}", sc_query.status.success());
        println!("Service query output: {}", String::from_utf8_lossy(&sc_query.stdout));
    
        // Get detailed service configuration
        let sc_qc = Command::new("sc")
            .args(&["qc", "WindowsEventLogger"])
            .output()
            .expect("Failed to execute sc qc");
        
        println!("Service configuration: {}", String::from_utf8_lossy(&sc_qc.stdout));
    
        assert!(output.status.success(), "Service installation command failed");
        assert!(sc_query.status.success(), "Service does not exist after installation");
    
        // Uncomment to skip cleanup for debugging
        // println!("Skipping cleanup for debugging");
        // return;
    
        // Clean up - remove the service
        println!("Cleaning up - removing service");
        let cleanup = Command::new("sc")
            .args(&["delete", "WindowsEventLogger"])
            .output()
            .expect("Failed to execute sc delete");
        
        println!("Cleanup status: {}", cleanup.status);
        println!("Cleanup output: {}", String::from_utf8_lossy(&cleanup.stdout));
    }

    fn is_running_as_admin() -> bool {
        // Implementation to check if test is running with admin privileges
        #[cfg(windows)]
        {
            use windows::Win32::Foundation::HANDLE;
            use windows::Win32::Security::{GetTokenInformation, TOKEN_QUERY};
            use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

            unsafe {
                // Define a custom struct that matches TokenElevation's memory layout
                #[repr(C)]
                struct TokenElevationStruct {
                    token_is_elevated: u32,
                }

                let mut token: HANDLE = Default::default();
                if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
                    return false;
                }

                let mut elevation = TokenElevationStruct {
                    token_is_elevated: 0,
                };
                let mut size = std::mem::size_of::<TokenElevationStruct>() as u32;

                if GetTokenInformation(
                    token,
                    windows::Win32::Security::TokenElevation,
                    Some(&mut elevation as *mut _ as *mut _),
                    size,
                    &mut size,
                )
                .is_err()
                {
                    return false;
                }

                elevation.token_is_elevated != 0
            }
        }

        #[cfg(not(windows))]
        {
            false
        }
    }
}
