use crate::config::Config;
use aws_config::meta::region::RegionProviderChain;
use aws_sdk_cloudwatchlogs::types::InputLogEvent;
use aws_sdk_cloudwatchlogs::{Client, Error};
use aws_types::region::Region;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct CloudWatchClient {
    client: Client,
    log_group: String,
    log_stream: String,
    sequence_token: Option<String>,
}

impl CloudWatchClient {
    pub async fn new(config: &Config) -> Result<Self, Error> {
        // Set up AWS region from config, falling back to us-east-1 if not specified
        let region = config
            .aws_region
            .as_ref()
            .map(|r| Region::new(r.clone()))
            .unwrap_or_else(|| Region::new("eu-west-1"));

        let region_provider = RegionProviderChain::first_try(region);
        let shared_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(region_provider)
            .load()
            .await;
        let client = Client::new(&shared_config);

        // Log group and stream names
        let log_group = "winvent".to_string();
        let log_stream = format!(
            "windows-events-{}",
            std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".to_string())
        );

        // Create log group if it doesn't exist
        match client
            .create_log_group()
            .log_group_name(&log_group)
            .send()
            .await
        {
            Ok(_) => (),
            Err(e) => {
                if !e.to_string().contains("ResourceAlreadyExistsException") {
                    return Err(e.into());
                }
            }
        }

        // Create log stream if it doesn't exist
        match client
            .create_log_stream()
            .log_group_name(&log_group)
            .log_stream_name(&log_stream)
            .send()
            .await
        {
            Ok(_) => (),
            Err(e) => {
                if !e.to_string().contains("ResourceAlreadyExistsException") {
                    return Err(e.into());
                }
            }
        }

        Ok(Self {
            client,
            log_group,
            log_stream,
            sequence_token: None,
        })
    }

    pub async fn send_event(&mut self, event_data: &str) -> Result<(), Error> {
        self.send_event_internal(event_data, None).await
    }

    async fn send_event_internal(
        &mut self,
        event_data: &str,
        retry_token: Option<String>,
    ) -> Result<(), Error> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        let mut request = self
            .client
            .put_log_events()
            .log_group_name(&self.log_group)
            .log_stream_name(&self.log_stream)
            .log_events(
                InputLogEvent::builder()
                    .timestamp(timestamp)
                    .message(event_data)
                    .build()
                    .expect("Failed to build InputLogEvent"),
            );

        // Add sequence token if we have one
        if let Some(token) = retry_token.or_else(|| self.sequence_token.clone()) {
            request = request.sequence_token(token);
        }

        // Send the log event
        match request.send().await {
            Ok(response) => {
                // Update sequence token for next call
                self.sequence_token = response.next_sequence_token;
                Ok(())
            }
            Err(e) => {
                // Handle invalid sequence token errors
                if e.to_string().contains("InvalidSequenceTokenException") {
                    // Extract the correct token from the error message
                    if let Some(token) = extract_sequence_token_from_error(&e.to_string()) {
                        self.sequence_token = Some(token.clone());
                        // Use Box::pin for recursion in async functions
                        return Box::pin(self.send_event_internal(event_data, Some(token))).await;
                    }
                }
                Err(e.into())
            }
        }
    }
}

// Helper function to extract sequence token from error message
fn extract_sequence_token_from_error(error_message: &str) -> Option<String> {
    if let Some(start) = error_message.find("sequenceToken is: ") {
        let start = start + "sequenceToken is: ".len();
        if let Some(end) = error_message[start..].find('"') {
            return Some(error_message[start..start + end].to_string());
        }
    }
    None
}

// Function to format Windows event for CloudWatch
pub fn format_event_for_cloudwatch(
    event_id: u32,
    event_type: u32,
    source: &str,
    record_number: u32,
    time_generated: u32,
    time_written: u32,
    category: u16,
    strings: &[String],
) -> String {
    serde_json::json!({
        "event_id": event_id,
        "event_type": event_type,
        "source": source,
        "record_number": record_number,
        "time_generated": time_generated,
        "time_written": time_written,
        "category": category,
        "strings": strings,
        "hostname": std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".to_string()),
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockall::predicate::*;
    use mockall::*;

    mock! {
        CloudWatchClient {
            async fn send_event(&mut self, event_data: &str) -> Result<(), Error>;
        }
    }

    #[test]
    fn test_format_event_for_cloudwatch() {
        let event = format_event_for_cloudwatch(
            1001,
            2,
            "Application",
            12345,
            1620000000,
            1620000001,
            0,
            &vec!["Test message".to_string()],
        );

        let parsed: serde_json::Value = serde_json::from_str(&event).unwrap();
        assert_eq!(parsed["event_id"], 1001);
        assert_eq!(parsed["event_type"], 2);
        assert_eq!(parsed["source"], "Application");
        assert_eq!(parsed["strings"][0], "Test message");
    }
}
