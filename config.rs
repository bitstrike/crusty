// config.rs - Shared configuration for TLS Chat system
// This file contains constants and settings used by both client and server

use serde::{Serialize, Deserialize};

// Event-driven message signing constants
pub const SIGNED_MESSAGE_PREFIX: &str = "[SIGNED:";
pub const SIGNED_MESSAGE_SEPARATOR: &str = "] ";

// Legacy message constants removed - replaced with ServerEvent system

// Message content constants (kept for server console output)
#[allow(dead_code)]
pub const MESSAGE_JOINED_CHAT: &str = "joined the chat";
#[allow(dead_code)]
pub const MESSAGE_LEFT_CHAT: &str = "left the chat";
#[allow(dead_code)]
pub const MESSAGE_TIMED_OUT_LEFT: &str = "timed out and left the chat";
#[allow(dead_code)]
pub const MESSAGE_NICKNAME_CHANGE: &str = "is now known as";

// Message signing helper (kept for existing message signing)
pub fn format_signed_message(signature: &str, content: &str) -> String {
    format!("{}{}{}{}", SIGNED_MESSAGE_PREFIX, signature, SIGNED_MESSAGE_SEPARATOR, content)
}

// Note: Message formatting functions removed - not used in current implementation

// Duplicate section removed

// Message parsing helpers (kept for existing message verification)
#[allow(dead_code)]
pub fn extract_signed_content(signed_message: &str) -> Option<String> {
    // Parse: [SIGNED:<signature>] *** message content ***
    if let Some(separator_pos) = signed_message.find(SIGNED_MESSAGE_SEPARATOR) {
        let content_start = separator_pos + SIGNED_MESSAGE_SEPARATOR.len();
        Some(signed_message[content_start..].to_string())
    } else {
        None
    }
}

#[allow(dead_code)]
pub fn extract_signature(signed_message: &str) -> Option<String> {
    // Parse: [SIGNED:<signature>] *** message content ***
    if let Some(prefix_pos) = signed_message.find(SIGNED_MESSAGE_PREFIX) {
        if let Some(separator_pos) = signed_message.find(SIGNED_MESSAGE_SEPARATOR) {
            let sig_start = prefix_pos + SIGNED_MESSAGE_PREFIX.len();
            Some(signed_message[sig_start..separator_pos].to_string())
        } else {
            None
        }
    } else {
        None
    }
}

#[allow(dead_code)]
pub fn is_signed_message(message: &str) -> bool {
    message.starts_with(SIGNED_MESSAGE_PREFIX) && message.contains(SIGNED_MESSAGE_SEPARATOR)
}

// cert and key paths
pub const CERT_PATH: &str = "cert.pem";
#[allow(dead_code)]
pub const KEY_PATH: &str = "key.pem";

// Server configuration
#[allow(dead_code)]
pub const MAX_USERS: usize = 5;
#[allow(dead_code)]
pub const MAX_LAST_SEEN_SECONDS: u64 = 60; // Increased from 10 to 60 seconds
#[allow(dead_code)]
pub const HEARTBEAT_CHECK_INTERVAL_SECONDS: u64 = 5;

// Message signing constants
// Note: These are used internally by UnifiedKeyManager for HMAC-SHA256 signing

// Command constants
pub const COMMAND_REGISTER_KEY: &str = "/register_key";
#[allow(dead_code)]
pub const COMMAND_SIGNING_STATUS: &str = "/signing_status";
#[allow(dead_code)]
pub const COMMAND_NICK: &str = "/nick";
pub const COMMAND_WHO: &str = "/who";
#[allow(dead_code)]
pub const COMMAND_STATUS: &str = "/status";
#[allow(dead_code)]
pub const COMMAND_QUIT: &str = "/quit";

// Response messages
pub const RESPONSE_KEY_REGISTERED: &str = "Client signing key registered successfully";
#[allow(dead_code)]
pub const RESPONSE_VERIFICATION_FAILED: &str = "Message verification failed";
// Note: Other response constants are kept for future use in error handling

// Connection timeouts
#[allow(dead_code)]
pub const CONNECTION_STABILIZATION_MS: u64 = 200;
#[allow(dead_code)]
pub const KEY_REGISTRATION_WAIT_MS: u64 = 200;
// Note: These are used by client connection logic

// Client configuration  
#[allow(dead_code)]
pub const MAX_CHAT_HISTORY_LINES: usize = 1024;
// Note: Heartbeat constants are kept for potential future use

// Event-driven architecture constants
#[allow(dead_code)]
pub const ROSTER_SNAPSHOT_INTERVAL_SECONDS: u64 = 30; // Periodic roster updates instead of 1-3s polling

// Event types for server-side broadcasting
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ServerEvent {
    // Global events (broadcast to all users)
    UserJoin { user_id: usize, nickname: String, timestamp: u64 },
    UserLeave { user_id: usize, nickname: String, reason: String, timestamp: u64 },
    UserTimeout { user_id: usize, nickname: String, timestamp: u64 },
    NicknameChange { user_id: usize, old_nickname: String, new_nickname: String, timestamp: u64 },
    RosterSnapshot { users: Vec<UserStatus>, total_users: usize, timestamp: u64 },
    
    // User-specific events (single user only)
    ConnectionEstablished { user_id: usize, nickname: String, timestamp: u64 },
    WelcomeMessage { user_id: usize, message: String, timestamp: u64 },
    KeyRegistration { user_id: usize, nickname: String, timestamp: u64 },
    KeyRegistrationFailed { user_id: usize, reason: String, timestamp: u64 },
    CommandResponse { user_id: usize, response: String, timestamp: u64 },
    ErrorResponse { user_id: usize, error: String, timestamp: u64 },
}

// User status structure for roster updates
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UserStatus {
    pub id: usize,
    pub nickname: String,
    pub state: String,
    pub last_seen: u64,
    pub nickname_changed: bool,
    pub old_nickname: Option<String>,
}

