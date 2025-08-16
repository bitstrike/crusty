// Shared configuration for TLS Chat system
// This file contains constants and settings used by both client and server

// Message formatting constants
pub const CONTROL_MESSAGE_PREFIX: &str = "***";
pub const CONTROL_MESSAGE_SUFFIX: &str = "***";
pub const SIGNED_MESSAGE_PREFIX: &str = "[SIGNED:";
pub const SIGNED_MESSAGE_SEPARATOR: &str = "] ";

// Message content constants
pub const MESSAGE_JOINED_CHAT: &str = "joined the chat";
pub const MESSAGE_LEFT_CHAT: &str = "left the chat";
pub const MESSAGE_TIMED_OUT_LEFT: &str = "timed out and left the chat";
pub const MESSAGE_NICKNAME_CHANGE: &str = "is now known as";
pub const MESSAGE_USER_PREFIX: &str = "User ";

// Message templates
pub fn format_control_message(message: &str) -> String {
    format!("{} {} {}", CONTROL_MESSAGE_PREFIX, message, CONTROL_MESSAGE_SUFFIX)
}

pub fn format_signed_message(signature: &str, content: &str) -> String {
    format!("{}{}{}{}", SIGNED_MESSAGE_PREFIX, signature, SIGNED_MESSAGE_SEPARATOR, content)
}

// Common message patterns
pub fn format_join_message(nickname: &str) -> String {
    format_control_message(&format!("{} {}", nickname, MESSAGE_JOINED_CHAT))
}

pub fn format_leave_message(nickname: &str) -> String {
    format_control_message(&format!("{} {}", nickname, MESSAGE_LEFT_CHAT))
}

pub fn format_timeout_message(nickname: &str) -> String {
    format_control_message(&format!("{} {}", nickname, MESSAGE_TIMED_OUT_LEFT))
}

pub fn format_nickname_change_message(old_nick: &str, new_nick: &str) -> String {
    format_control_message(&format!("{}{} {}", old_nick, MESSAGE_NICKNAME_CHANGE, new_nick))
}

// Message parsing helpers
pub fn extract_signed_content(signed_message: &str) -> Option<String> {
    // Parse: [SIGNED:<signature>] *** message content ***
    if let Some(separator_pos) = signed_message.find(SIGNED_MESSAGE_SEPARATOR) {
        let content_start = separator_pos + SIGNED_MESSAGE_SEPARATOR.len();
        Some(signed_message[content_start..].to_string())
    } else {
        None
    }
}

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

pub fn is_signed_message(message: &str) -> bool {
    message.starts_with(SIGNED_MESSAGE_PREFIX) && message.contains(SIGNED_MESSAGE_SEPARATOR)
}

// Server configuration
pub const MAX_USERS: usize = 5;
pub const MAX_LAST_SEEN_SECONDS: u64 = 10;
pub const HEARTBEAT_CHECK_INTERVAL_SECONDS: u64 = 5;

// Client configuration  
pub const MAX_CHAT_HISTORY_LINES: usize = 1024;
pub const HEARTBEAT_INTERVAL_MIN_MS: u64 = 1000;
pub const HEARTBEAT_INTERVAL_MAX_MS: u64 = 3000;
