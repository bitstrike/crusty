use std::collections::HashMap;
use std::io::{Write, Read};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::sync::mpsc::{Sender, Receiver, channel};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use rustls::{Certificate, PrivateKey, ServerConfig, StreamOwned, ServerConnection};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::fs::{self, File};
use std::io::BufReader as StdBufReader;
use regex::Regex;
use serde::{Serialize, Deserialize};
use hmac::{Hmac, Mac};
use sha2::{Sha256, Digest};
use base64::{Engine as _, engine::general_purpose};
mod config;
use config::*;

type TlsStream = StreamOwned<ServerConnection, TcpStream>;

// JSON Status Protocol Structures
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UserStatus {
    pub id: usize,
    pub nickname: String,
    pub state: String,
    pub last_seen: u64,
    pub nickname_changed: bool,
    pub old_nickname: Option<String>, // Track old nickname for change notifications
}

#[derive(Serialize, Deserialize, Debug)]
pub struct StatusResponse {
    pub timestamp: u64,
    pub users: Vec<UserStatus>,
    pub total_users: usize,
}

struct ChatUser {
    nickname: String,
    message_sender: Sender<String>,
    last_seen: Instant,
    state: String,
    nickname_changed: bool,
    old_nickname: Option<String>, // Track previous nickname
}

type SharedUsers = Arc<Mutex<HashMap<usize, ChatUser>>>;

// MessageManager handles all message signing, verification, and control message generation
struct MessageManager {
    private_key: Vec<u8>, // HMAC secret key
    public_cert: Vec<Certificate>,
    // Client verification tracking
    client_keys: Arc<Mutex<HashMap<usize, Vec<u8>>>>, // user_id -> client_signing_key
}

impl MessageManager {
    fn new(key_path: &str, cert_path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        // For HMAC, we'll use a simple secret key derived from the key file
        let key_data = fs::read_to_string(key_path)?;
        // Use a hash of the key file content as HMAC secret to ensure proper length
        let mut hasher = Sha256::new();
        hasher.update(key_data.as_bytes());
        let secret_key = hasher.finalize().to_vec();
        
        let public_cert = load_certs(cert_path)?;
        
        Ok(MessageManager {
            private_key: secret_key,
            public_cert,
            client_keys: Arc::new(Mutex::new(HashMap::new())),
        })
    }
    
    fn sign_message(&self, message: &str) -> Result<String, Box<dyn std::error::Error>> {
        // Create HMAC-SHA256 signature
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.private_key)
            .map_err(|_| "Invalid key length")?;
        
        mac.update(message.as_bytes());
        let result = mac.finalize();
        
        // Encode the signature as base64 for transmission
        Ok(general_purpose::STANDARD.encode(result.into_bytes()))
    }
    
    fn generate_control_message(&self, message_type: &str, nickname: &str, additional_info: Option<&str>) -> Result<String, Box<dyn std::error::Error>> {
        let base_message = match message_type {
            "nickname_change" => {
                if let Some(new_nick) = additional_info {
                    format_nickname_change_message(nickname, new_nick)
                } else {
                    format_control_message(message_type)
                }
            },
            "user_join" => format_join_message(nickname),
            "user_leave" => format_leave_message(nickname),
            "user_timeout" => format_timeout_message(nickname),
            _ => format_control_message(message_type)
        };
        
        // Generate HMAC signature for server authentication
        let signature = self.sign_message(&base_message)?;
        Ok(format_signed_message(&signature, &base_message))
    }
    
    fn broadcast_control_message(&self, message_type: &str, nickname: &str, additional_info: Option<&str>, users: &SharedUsers, sender_id: usize) -> Result<(), Box<dyn std::error::Error>> {
        let signed_message = self.generate_control_message(message_type, nickname, additional_info)?;
        broadcast_message(&signed_message, sender_id, users);
        Ok(())
    }
    
    fn verify_client_message(&self, signed_message: &str, user_id: usize) -> Result<Option<String>, Box<dyn std::error::Error>> {
        // Check if this is a signed message
        if !is_signed_message(signed_message) {
            return Ok(None); // Not a signed message, treat as regular message
        }
        
        // Extract signature metadata and actual message content
        let signature_metadata = extract_signature(signed_message)
            .ok_or("Could not extract signature")?;
        
        let actual_message = extract_signed_content(signed_message)
            .ok_or("Could not extract message content")?;
        
        // Get client's signing key
        let client_key = {
            let keys_lock = self.client_keys.lock().unwrap();
            keys_lock.get(&user_id).cloned()
        };
        
        if let Some(client_key) = client_key {
            // Parse signature metadata: "timestamp|nonce|signature"
            let parts: Vec<&str> = signature_metadata.splitn(3, '|').collect();
            if parts.len() != 3 {
                return Err("Invalid signature format: expected timestamp|nonce|signature".into());
            }
            
            let timestamp = parts[0];
            let nonce = parts[1];
            let signature_base64 = parts[2];
            
            // Decode the base64 signature
            let signature_bytes = general_purpose::STANDARD.decode(signature_base64)?;
            
            // Reconstruct the exact string that was signed by client
            let message_to_verify = format!("{}|{}|{}", timestamp, nonce, actual_message);
            
            // Verify HMAC-SHA256 signature
            let mut mac = Hmac::<Sha256>::new_from_slice(&client_key)
                .map_err(|_| "Invalid key length")?;
            mac.update(message_to_verify.as_bytes());
            
            let result = mac.verify_slice(&signature_bytes);
            match result {
                Ok(()) => {
                    debug_log(&format!("✅ Client message signature verified for user {}: {}", user_id, actual_message));
                    Ok(Some(actual_message.to_string()))
                }
                Err(_) => {
                    debug_log(&format!("❌ Client message signature verification failed for user {}: {}", user_id, actual_message));
                    Err("Invalid client message signature".into())
                }
            }
        } else {
            // No client key registered yet, treat as unsigned message
            debug_log(&format!("⚠️  No client key for user {}, treating as unsigned message: {}", user_id, actual_message));
            Ok(Some(actual_message))
        }
    }
    
    fn register_client_key(&self, user_id: usize, client_key: Vec<u8>) {
        let mut keys_lock = self.client_keys.lock().unwrap();
        keys_lock.insert(user_id, client_key);
        debug_log(&format!("🔑 Registered client signing key for user {}", user_id));
    }
    
    fn send_signed_response(&self, message: &str, user_id: usize, users: &SharedUsers) -> Result<(), Box<dyn std::error::Error>> {
        let signed_message = self.sign_message(message)?;
        let formatted_message = format_signed_message(&signed_message, message);
        
        if let Some(user) = users.lock().unwrap().get(&user_id) {
            let _ = user.message_sender.send(formatted_message);
        }
        Ok(())
    }
}



static DEBUG: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn debug_log(msg: &str) {
    if DEBUG.load(std::sync::atomic::Ordering::Relaxed) {
        use std::time::SystemTime;
        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let hours = (now / 3600) % 24;
        let minutes = (now / 60) % 60;
        let seconds = now % 60;
        println!("[{:02}:{:02}:{:02}  DBG] {}", hours, minutes, seconds, msg);
    }
}

fn broadcast_message(message: &str, sender_id: usize, users: &SharedUsers) {
    debug_log(&format!("Broadcasting: {} (excluding sender {})", message, sender_id));
    let users_lock = users.lock().unwrap();
    for (&user_id, user) in users_lock.iter() {
        if user_id != sender_id {
            match user.message_sender.send(message.to_string()) {
                Ok(()) => debug_log(&format!("Sent to user {}: {}", user_id, message)),
                Err(e) => debug_log(&format!("Failed to send to user {}: {}", user_id, e)),
            }
        }
    }
}

fn load_certs(filename: &str) -> Result<Vec<Certificate>, Box<dyn std::error::Error>> {
    let certfile = File::open(filename)?;
    let mut reader = StdBufReader::new(certfile);
    let certs = certs(&mut reader)?;
    Ok(certs.into_iter().map(Certificate).collect())
}

fn load_private_key(filename: &str) -> Result<PrivateKey, Box<dyn std::error::Error>> {
    let keyfile = File::open(filename)?;
    let mut reader = StdBufReader::new(keyfile);
    let keys = pkcs8_private_keys(&mut reader)?;
    if keys.is_empty() {
        return Err("No private key found".into());
    }
    Ok(PrivateKey(keys[0].clone()))
}

fn sanitize_message(input: &str) -> Option<String> {
    // Allow alphanumeric, spaces, basic punctuation, and base64 characters
    let re = Regex::new(r"^[a-zA-Z0-9\s/.,!?'_+=\-]+$").unwrap();
    let trimmed = input.trim();
    
    // Special case: always allow /register_key commands with base64 keys
    if trimmed.starts_with("/register_key ") {
        let parts: Vec<&str> = trimmed.splitn(2, ' ').collect();
        if parts.len() == 2 {
            let key_part = parts[1];
            // Validate base64 format (alphanumeric + / + = padding)
            let base64_re = Regex::new(r"^[a-zA-Z0-9+/]+=*$").unwrap();
            if key_part.len() <= 64 && base64_re.is_match(key_part) {
                return Some(trimmed.to_string());
            }
        }
        return None;
    }
    
    // Regular validation for other messages
    if trimmed.len() <= 256 && re.is_match(trimmed) && !trimmed.is_empty() {
        Some(trimmed.to_string())
    } else {
        None
    }
}

fn sanitize_nickname(input: &str) -> Option<String> {
    let re = Regex::new(r"^[a-zA-Z0-9_]+$").unwrap(); // Allow underscores
    if input.len() <= 16 && input.len() >= 1 && re.is_match(input) {
        Some(input.to_string())
    } else {
        None
    }
}

fn handle_client(user_id: usize, mut tls_stream: TlsStream, users: SharedUsers, message_manager: Arc<MessageManager>) {
    let initial_nickname = format!("User{}", user_id);
    
    // Set the underlying TCP stream to non-blocking mode for real-time message delivery
    if let Err(e) = tls_stream.get_mut().set_nonblocking(true) {
        debug_log(&format!("Failed to set non-blocking mode: {}", e));
        return;
    }
    
    // Create channel for receiving messages to send to this client
    let (message_sender, message_receiver): (Sender<String>, Receiver<String>) = channel();
    
    // Add user to collection
    {
        let mut users_lock = users.lock().unwrap();
        users_lock.insert(user_id, ChatUser {
            nickname: initial_nickname.clone(),
            message_sender,
            last_seen: Instant::now(),
            state: "connected".to_string(),
            nickname_changed: false,
            old_nickname: None,
        });
    }

    // Send welcome messages
    let _ = writeln!(tls_stream, "Welcome! Commands: {} <n>, {}, {} <key>, {}", COMMAND_NICK, COMMAND_WHO, COMMAND_REGISTER_KEY, COMMAND_SIGNING_STATUS);
    let _ = writeln!(tls_stream, "You are {}.", initial_nickname);
    let _ = tls_stream.flush();

    println!("{} {}", initial_nickname, MESSAGE_JOINED_CHAT);
    
    // Broadcast join notification to all other users
    if let Err(e) = message_manager.broadcast_control_message("user_join", &initial_nickname, None, &users, user_id) {
        debug_log(&format!("Failed to broadcast join message: {}", e));
    }

    // Real-time message handling with non-blocking I/O (similar to client fix)
    let mut read_buffer = String::new();
    let mut temp_buf = [0u8; 1024];
    
    loop {
        // Priority 1: Process ALL pending outgoing messages first (real-time delivery)
        let mut processed_outgoing = false;
        while let Ok(message) = message_receiver.try_recv() {
            processed_outgoing = true;
            debug_log(&format!("Sent to user {}: {}", user_id, message));
            if let Err(_) = writeln!(tls_stream, "{}", message).and_then(|_| tls_stream.flush()) {
                debug_log("Failed to write message to client, ending connection");
                return;
            }
        }
        
        // Priority 2: Check for incoming data (non-blocking)
        match tls_stream.read(&mut temp_buf) {
            Ok(0) => break, // Connection closed
            Ok(n) => {
                // Process received data
                if let Ok(data) = std::str::from_utf8(&temp_buf[..n]) {
                    read_buffer.push_str(data);
                    
                    // Process complete lines
                    while let Some(newline_pos) = read_buffer.find('\n') {
                        let input = read_buffer[..newline_pos].trim().to_string();
                        read_buffer = read_buffer[newline_pos + 1..].to_string();
                        
                        if !input.is_empty() {
                            // Special handling for /register_key - allow unsigned
                            let (verified_message, _is_signed) = if input.starts_with(COMMAND_REGISTER_KEY) {
                                // /register_key commands are allowed unsigned for bootstrap
                                debug_log(&format!("🔑 Processing unsigned /register_key command from user {}", user_id));
                                (input.clone(), false)
                            } else {
                                // All other messages must be verified
                                match message_manager.verify_client_message(&input, user_id) {
                                    Ok(Some(content)) => {
                                        debug_log(&format!("✅ Verified signed message from user {}: {}", user_id, content));
                                        (content, true)
                                    }
                                    Ok(None) => {
                                        // Not a signed message, treat as regular message
                                        (input.clone(), false)
                                    }
                                    Err(e) => {
                                        debug_log(&format!("❌ Message verification failed for user {}: {}", user_id, e));
                                        // Send error response and continue
                                        if let Some(user) = users.lock().unwrap().get(&user_id) {
                                            let _ = user.message_sender.send(format!("Error: {}", RESPONSE_VERIFICATION_FAILED));
                                        }
                                        continue;
                                    }
                                }
                            };
                            
                            // Process the verified message (existing logic)
                            let sanitized = match sanitize_message(&verified_message) {
                                Some(msg) => msg,
                                None => {
                                    println!("Invalid message from {}: {}", initial_nickname, verified_message);
                                    continue;
                                }
                            };

                            if sanitized.starts_with(COMMAND_NICK) && sanitized.len() > COMMAND_NICK.len() {
                                let new_nick = sanitized.trim_start_matches(COMMAND_NICK).trim();
                                match sanitize_nickname(new_nick) {
                                    Some(nick) => {
                                        let old_nick = {
                                            let mut users_lock = users.lock().unwrap();
                                            if let Some(user) = users_lock.get_mut(&user_id) {
                                                let old = user.nickname.clone();
                                                user.old_nickname = Some(old.clone());
                                                user.nickname = nick.clone();
                                                user.nickname_changed = true;
                                                user.last_seen = Instant::now(); // Update last_seen on activity
                                                old
                                            } else {
                                                continue;
                                            }
                                        };
                                        debug_log(&format!("{} {} {}", old_nick, MESSAGE_NICKNAME_CHANGE, nick));
                                        
                                        // Generate and broadcast control message to all clients
                                        if let Err(e) = message_manager.broadcast_control_message("nickname_change", &old_nick, Some(&nick), &users, user_id) {
                                            debug_log(&format!("Failed to broadcast nickname change message: {}", e));
                                        }
                                        
                                        // Send signed confirmation back to client
                                        if let Err(e) = message_manager.send_signed_response(&format!("Your nickname is now: {}", nick), user_id, &users) {
                                            debug_log(&format!("Failed to send signed nickname confirmation: {}", e));
                                        }
                                        
                                        // Reset nickname change flags after processing
                                        if let Some(user) = users.lock().unwrap().get_mut(&user_id) {
                                            user.nickname_changed = false;
                                            user.old_nickname = None;
                                        }
                                    }
                                    None => {
                                        println!("Invalid nickname from {}: {}", initial_nickname, new_nick);
                                        // Send error back to client via channel
                                        if let Some(user) = users.lock().unwrap().get(&user_id) {
                                            let _ = user.message_sender.send(format!("Error: Invalid nickname '{}'. Use 1-16 alphanumeric characters only.", new_nick));
                                        }
                                    }
                                }
                            } else if sanitized == COMMAND_WHO {
                                let user_list = {
                                    let users_lock = users.lock().unwrap();
                                    let mut names: Vec<String> = users_lock.values()
                                        .map(|u| u.nickname.clone())
                                        .collect();
                                    names.sort();
                                    if names.is_empty() {
                                        "No users online".to_string()
                                    } else {
                                        format!("Online users ({}): {}", names.len(), names.join(", "))
                                    }
                                };
                                println!("User list requested: {}", user_list);
                                // Send signed user list back to client
                                if let Err(e) = message_manager.send_signed_response(&user_list, user_id, &users) {
                                    debug_log(&format!("Failed to send signed user list: {}", e));
                                }
                            } else if sanitized == COMMAND_STATUS {
                                // Update last_seen for the requesting user and send JSON status
                                {
                                    let mut users_lock = users.lock().unwrap();
                                    if let Some(user) = users_lock.get_mut(&user_id) {
                                        user.last_seen = Instant::now();
                                    }
                                }
                                
                                let status_json = generate_status_json(&users);
                                debug_log(&format!("Status requested by user {}", user_id));
                                
                                // Send signed JSON status response
                                if let Err(e) = message_manager.send_signed_response(&status_json, user_id, &users) {
                                    debug_log(&format!("Failed to send signed status response: {}", e));
                                }
                            } else if sanitized.starts_with(COMMAND_REGISTER_KEY) && sanitized.len() > COMMAND_REGISTER_KEY.len() {
                                // Client key registration: /register_key <base64_encoded_key>
                                let key_part = sanitized.trim_start_matches(COMMAND_REGISTER_KEY).trim();
                                if let Ok(client_key) = general_purpose::STANDARD.decode(key_part) {
                                    message_manager.register_client_key(user_id, client_key);
                                    // Send signed confirmation
                                    if let Err(e) = message_manager.send_signed_response(RESPONSE_KEY_REGISTERED, user_id, &users) {
                                        debug_log(&format!("Failed to send signed response: {}", e));
                                    }
                                } else {
                                    // Send error response
                                    if let Some(user) = users.lock().unwrap().get(&user_id) {
                                        let _ = user.message_sender.send("Error: Invalid key format. Use base64 encoding.".to_string());
                                    }
                                }
                            } else if sanitized == "/signing_status" {
                                // Check if client has registered a signing key
                                let has_key = {
                                    let keys_lock = message_manager.client_keys.lock().unwrap();
                                    keys_lock.contains_key(&user_id)
                                };
                                
                                let status_msg = if has_key {
                                    "✅ Client signing key is registered and active"
                                } else {
                                    "⚠️  No client signing key registered. Use /register_key <key> to register."
                                };
                                
                                if let Err(e) = message_manager.send_signed_response(status_msg, user_id, &users) {
                                    debug_log(&format!("Failed to send signed signing status: {}", e));
                                }
                            } else if sanitized == COMMAND_QUIT {
                                debug_log(&format!("User {} requested to quit", user_id));
                                
                                // Send signed confirmation to client
                                if let Err(e) = message_manager.send_signed_response("Goodbye!", user_id, &users) {
                                    debug_log(&format!("Failed to send signed goodbye: {}", e));
                                }
                                
                                // Small delay to ensure message is sent before breaking
                                thread::sleep(Duration::from_millis(100));
                                
                                // Break from the client loop to trigger cleanup
                                break;
                            } else {
                                // Regular message - update last_seen
                                let nickname = {
                                    let mut users_lock = users.lock().unwrap();
                                    if let Some(user) = users_lock.get_mut(&user_id) {
                                        user.last_seen = Instant::now();
                                        user.nickname.clone()
                                    } else {
                                        String::new()
                                    }
                                };
                                debug_log(&format!("{}: {}", nickname, sanitized));
                                
                                // Broadcast this message to all connected clients (excluding sender)
                                let message = format!("[{}]: {}", nickname, sanitized);
                                broadcast_message(&message, user_id, &users);
                                
                                // Also echo back to sender with signed confirmation
                                if let Err(e) = message_manager.send_signed_response(&message, user_id, &users) {
                                    debug_log(&format!("Failed to send signed message echo: {}", e));
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    // No data available right now - this is normal for non-blocking I/O
                } else {
                    debug_log(&format!("Read error from user {}: {}", user_id, e));
                    break;
                }
            }
        }
        
        // Small sleep only if no work was done to prevent CPU spinning
        if !processed_outgoing {
            thread::sleep(Duration::from_millis(10));
        }
    }

    // Cleanup
    let nickname = {
        let mut users_lock = users.lock().unwrap();
        users_lock.remove(&user_id).map(|u| u.nickname).unwrap_or_default()
    };
    
    println!("{} {}", nickname, MESSAGE_LEFT_CHAT);
    
    // Broadcast leave notification to all remaining users
    if let Err(e) = message_manager.broadcast_control_message("user_leave", &nickname, None, &users, user_id) {
        debug_log(&format!("Failed to broadcast leave message: {}", e));
    }
}

fn generate_status_json(users: &SharedUsers) -> String {
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    let users_lock = users.lock().unwrap();
    let mut user_statuses = Vec::new();
    
    for (&id, user) in users_lock.iter() {
        let last_seen_seconds = user.last_seen.elapsed().as_secs();
        
        user_statuses.push(UserStatus {
            id,
            nickname: user.nickname.clone(),
            state: user.state.clone(),
            last_seen: last_seen_seconds,
            nickname_changed: user.nickname_changed,
            old_nickname: user.old_nickname.clone(),
        });
    }
    
    let status_response = StatusResponse {
        timestamp: current_time,
        users: user_statuses.clone(),
        total_users: user_statuses.len(),
    };
    
    serde_json::to_string(&status_response).unwrap_or_else(|_| "{}".to_string())
}



fn cleanup_disconnected_users(users: &SharedUsers, message_manager: &MessageManager) {
    let mut users_to_remove = Vec::new();
    {
        let users_lock = users.lock().unwrap();
        for (&id, user) in users_lock.iter() {
            if user.last_seen.elapsed().as_secs() > MAX_LAST_SEEN_SECONDS {
                users_to_remove.push((id, user.nickname.clone()));
            }
        }
    }
    
    for (user_id, nickname) in users_to_remove {
        debug_log(&format!("Auto-removing inactive user: {} (id: {})", nickname, user_id));
        let mut users_lock = users.lock().unwrap();
        users_lock.remove(&user_id);
        
        // Broadcast leave notification
        drop(users_lock); // Release lock before broadcasting
        if let Err(e) = message_manager.broadcast_control_message("user_timeout", &nickname, None, users, user_id) {
            debug_log(&format!("Failed to broadcast timeout message: {}", e));
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Check for --debug flag
    let args: Vec<String> = std::env::args().collect();
    if args.contains(&"--debug".to_string()) {
        DEBUG.store(true, std::sync::atomic::Ordering::Relaxed);
        println!("Debug mode enabled");
    }

    // Create MessageManager for handling signed messages
    let message_manager = MessageManager::new(KEY_PATH, CERT_PATH)?;
    
    // Use the same certs and key for TLS configuration
    let certs = message_manager.public_cert.clone();
    // Load the key file for TLS configuration using the proper loader
    let key = load_private_key(KEY_PATH)?;

    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    let config = Arc::new(config);
    let users: SharedUsers = Arc::new(Mutex::new(HashMap::new()));
    let message_manager = Arc::new(message_manager); // Make it shareable across threads
    let listener = TcpListener::bind("0.0.0.0:8443")?;
    let mut user_counter = 0;

    // Start background cleanup thread
    let users_cleanup = users.clone();
    let message_manager_cleanup = message_manager.clone();
    thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_secs(HEARTBEAT_CHECK_INTERVAL_SECONDS)); // Check every 5 seconds
            cleanup_disconnected_users(&users_cleanup, &message_manager_cleanup);
        }
    });

    println!("TLS Chat Server started on 0.0.0.0:8443 (max {} users)", MAX_USERS);

    for stream in listener.incoming() {
        match stream {
            Ok(tcp_stream) => {
                {
                    let users_lock = users.lock().unwrap();
                    if users_lock.len() >= MAX_USERS {
                        println!("Connection rejected: maximum {} users reached", MAX_USERS);
                        let _ = tcp_stream.shutdown(std::net::Shutdown::Both);
                        continue;
                    }
                }

                let config = config.clone();
                let users = users.clone();
                let message_manager = message_manager.clone();
                user_counter += 1;
                let user_id = user_counter;

                thread::spawn(move || {
                    match ServerConnection::new(config) {
                        Ok(conn) => {
                            let tls_stream = StreamOwned::new(conn, tcp_stream);
                            handle_client(user_id, tls_stream, users, message_manager);
                        }
                        Err(e) => {
                            println!("TLS connection failed: {}", e);
                        }
                    }
                });
            }
            Err(e) => {
                eprintln!("Error accepting connection: {}", e);
            }
        }
    }

    Ok(())
}