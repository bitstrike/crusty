use std::io::{self, Write, Read};
use std::net::TcpStream;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, Duration};
use std::fs;
use rustls::{ClientConfig, ClientConnection, StreamOwned, Certificate, ServerName};
use rustls::client::{ServerCertVerifier, ServerCertVerified};
use serde::{Serialize, Deserialize};
use rand::{Rng, RngCore};
use hmac::{Hmac, Mac};
use sha2::{Sha256, Digest};
use base64::{Engine as _, engine::general_purpose};
mod config;
use config::*;

// TUI imports
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
    Frame, Terminal,
};
use std::collections::VecDeque;

type TlsStream = StreamOwned<ClientConnection, TcpStream>;

// Thread-safe signing state for debug client
#[derive(Clone)]
struct SigningState {
    signing_key: Vec<u8>,
    message_counter: Arc<Mutex<u64>>,
}

impl SigningState {
    fn new() -> Self {
        let mut rng = rand::thread_rng();
        let mut signing_key = vec![0u8; CLIENT_SIGNING_KEY_SIZE];
        rng.fill_bytes(&mut signing_key);
        
        Self {
            signing_key,
            message_counter: Arc::new(Mutex::new(0)),
        }
    }
    
    fn sign_message(&self, message: &str) -> Result<String, Box<dyn std::error::Error>> {
        use std::time::UNIX_EPOCH;
        
        // Get current timestamp and increment message counter for replay protection
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let nonce = {
            let mut counter = self.message_counter.lock().unwrap();
            let current = *counter;
            *counter += 1;
            current
        };
        
        // Create message to sign: "timestamp|nonce|message" for HMAC verification
        let message_to_sign = format!("{}|{}|{}", timestamp, nonce, message);
        
        // Sign with HMAC-SHA256 using client's signing key
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.signing_key)
            .map_err(|_| "Invalid key length")?;
        mac.update(message_to_sign.as_bytes());
        let result = mac.finalize();
        
        // Encode the signature as base64 for transmission
        let signature = general_purpose::STANDARD.encode(result.into_bytes());
        
        // Store signature metadata for server verification
        let signature_with_metadata = format!("{}|{}|{}", timestamp, nonce, signature);
        
        // Use config.rs constants for consistent message formatting
        // Format: [SIGNED:timestamp|nonce|signature] message
        // Server can extract timestamp, nonce, and signature to reconstruct signed content
        Ok(format_signed_message(&signature_with_metadata, message))
    }
    
    fn get_signing_key(&self) -> &[u8] {
        &self.signing_key
    }
}

// Common trait for both chat clients to share signing behavior
trait ChatClient {
    fn sign_and_send_message(&self, message: &str, tx: &Sender<String>) -> Result<(), Box<dyn std::error::Error>>;
}

// ClientMessageManager handles server message verification
struct ClientMessageManager {
    server_secret_key: Vec<u8>, // HMAC secret key (derived from server's key.pem)
}

impl ClientMessageManager {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        // Derive server secret key from key.pem (same as server)
        let key_data = fs::read_to_string("key.pem")?;
        let mut hasher = Sha256::new();
        hasher.update(key_data.as_bytes());
        let secret_key = hasher.finalize().to_vec();
        
        Ok(ClientMessageManager {
            server_secret_key: secret_key,
        })
    }
    
    fn is_signed_message(&self, message: &str) -> bool {
        is_signed_message(message)
    }
    
    fn extract_message_content(&self, signed_message: &str) -> Option<String> {
        extract_signed_content(signed_message)
    }
    
    fn extract_signature(&self, signed_message: &str) -> Option<String> {
        extract_signature(signed_message)
    }
    
    fn verify_message(&self, signed_message: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
        // Extract the signature and content
        let signature_base64 = self.extract_signature(signed_message)
            .ok_or("Could not extract signature")?;
        
        let message_content = self.extract_message_content(signed_message)
            .ok_or("Could not extract message content")?;
        
        debug_log(&format!("🔍 Verifying message: '{}'", signed_message));
        debug_log(&format!("🔑 Extracted signature: {}", signature_base64));
        debug_log(&format!("📝 Extracted content: '{}'", message_content));
        debug_log(&format!("📏 Content length: {}", message_content.len()));
        debug_log(&format!("🔍 Content bytes: {:?}", message_content.as_bytes()));
        
        // Decode the base64 signature
        let signature_bytes = general_purpose::STANDARD.decode(signature_base64)?;
        debug_log(&format!("🔑 Decoded signature bytes: {:?}", signature_bytes));
        debug_log(&format!("🔑 Server secret key length: {}", self.server_secret_key.len()));
        
        // Verify HMAC-SHA256 signature
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.server_secret_key)
            .map_err(|_| "Invalid key length")?;
        mac.update(message_content.as_bytes());
        
        let result = mac.verify_slice(&signature_bytes);
        debug_log(&format!("🔐 Verification result: {:?}", result));
        
        match result {
            Ok(()) => {
                debug_log(&format!("✅ Message signature verified: {}", message_content));
                Ok(Some(message_content))
            }
            Err(_) => {
                debug_log(&format!("❌ Message signature verification failed: {}", message_content));
                Err("Invalid message signature".into())
            }
        }
    }
    
    fn verify_message_simple(&self, signed_message: &str) -> bool {
        // Simple boolean verification - returns true if signature is valid, false otherwise
        match self.verify_message(signed_message) {
            Ok(Some(_)) => true,  // Signature verified successfully
            Ok(None) => false,     // Not a signed message
            Err(_) => false,       // Signature verification failed
        }
    }
}

// JSON Status Protocol Structures (matching server)
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

struct Args {
    host: String,
    port: u16,
    debug: bool,
    tui: bool,
}

impl Args {
    fn parse() -> Self {
        let args: Vec<String> = std::env::args().collect();
        let mut host = "localhost".to_string();
        let mut port = 8443u16;
        let mut debug = false;
        let mut tui = false;
        
        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "--host" => {
                    if i + 1 < args.len() {
                        host = args[i + 1].clone();
                        i += 1;
                    }
                }
                "--port" => {
                    if i + 1 < args.len() {
                        port = args[i + 1].parse().unwrap_or(8443);
                        i += 1;
                    }
                }
                "--debug" => debug = true,
                "--tui" => tui = true,
                _ => {}
            }
            i += 1;
        }
        
        Args { host, port, debug, tui }
    }
}

static DEBUG: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn debug_log(msg: &str) {
    if DEBUG.load(std::sync::atomic::Ordering::Relaxed) {
        println!("[DEBUG] {}", msg);
    }
}

struct AcceptAllVerifier;

impl ServerCertVerifier for AcceptAllVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: SystemTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        debug_log("Accepting server certificate");
        Ok(ServerCertVerified::assertion())
    }
}

struct DebugChatClient {
    #[allow(dead_code)]
    nickname: String,
    running: bool,
    tx_write: Option<Sender<String>>,
    rx_output: Option<Receiver<String>>,
    // Thread-safe client message signing
    signing_state: SigningState,
    key_registered: bool,
}

impl ChatClient for DebugChatClient {
    fn sign_and_send_message(&self, message: &str, tx: &Sender<String>) -> Result<(), Box<dyn std::error::Error>> {
        let signed_message = self.signing_state.sign_message(message)?;
        tx.send(signed_message)?;
        Ok(())
    }
}

impl DebugChatClient {
    fn new() -> Self {
        Self {
            nickname: "User".to_string(),
            running: false,
            tx_write: None,
            rx_output: None,
            signing_state: SigningState::new(),
            key_registered: false,
        }
    }

    fn connect(&mut self, host: &str, port: u16) -> Result<(), Box<dyn std::error::Error>> {
        debug_log(&format!("Connecting to {}:{}", host, port));
        
        let config = ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(std::sync::Arc::new(AcceptAllVerifier))
            .with_no_client_auth();

        let tcp_stream = TcpStream::connect(format!("{}:{}", host, port))?;
        // Set non-blocking mode for OpenSSL compatibility
        tcp_stream.set_nonblocking(true)?;
        let server_name = host.try_into()?;
        let conn = ClientConnection::new(std::sync::Arc::new(config), server_name)?;
        let tls_stream = StreamOwned::new(conn, tcp_stream);

        debug_log("TLS connection established");
        
        // Small delay to allow TLS handshake to complete
        thread::sleep(Duration::from_millis(100));
        
        self.running = true;

        let (tx_write, rx_write) = channel();
        let (tx_output, rx_output) = channel();
        
        self.tx_write = Some(tx_write);
        self.rx_output = Some(rx_output);

        // DEBUG CLIENT: Automatically register signing key with server
        debug_log("🔑 Registering client signing key...");
        let key_base64 = general_purpose::STANDARD.encode(self.signing_state.get_signing_key());
        if let Some(ref tx) = self.tx_write {
            // Note: Key registration bypasses signing since client doesn't have a key yet
            let _ = tx.send(format!("{} {}", COMMAND_REGISTER_KEY, key_base64));
        }
        
        // Wait for key registration to complete
        thread::sleep(Duration::from_millis(KEY_REGISTRATION_WAIT_MS));

        self.start_stream_handler(tls_stream, rx_write, tx_output);

        Ok(())
    }

    fn start_stream_handler(&self, mut stream: TlsStream, rx_write: Receiver<String>, tx_output: Sender<String>) {
        // Single-threaded approach like OpenSSL s_client - no Arc<Mutex> deadlocks
        thread::spawn(move || {
            debug_log("Stream handler started (OpenSSL-compatible single thread)");
            let mut read_buffer = String::new();
            
            loop {
                // Priority 1: Process ALL pending outgoing messages first (non-blocking)
                let mut processed_outgoing = false;
                while let Ok(msg) = rx_write.try_recv() {
                    processed_outgoing = true;
                    debug_log(&format!("Processing outgoing message: {}", msg));
                    
                    // DEBUG CLIENT: Handle non-blocking write with retry logic
                    let mut write_success = false;
                    let mut retry_count = 0;
                    const MAX_WRITE_RETRIES: usize = 10;
                    
                    while !write_success && retry_count < MAX_WRITE_RETRIES {
                        match write!(stream, "{}\r\n", &msg) {
                                                                Ok(()) => {
                                        match stream.flush() {
                                            Ok(()) => {
                                                debug_log(&format!("Sent: {}", msg));
                                                write_success = true;
                                            }
                                    Err(e) => {
                                        if e.kind() == std::io::ErrorKind::WouldBlock {
                                            // Stream not ready for flush, retry after small delay
                                            thread::sleep(Duration::from_millis(5));
                                            retry_count += 1;
                                        } else {
                                            debug_log(&format!("Flush error: {}", e));
                                            let _ = tx_output.send("DISCONNECT".to_string());
                                            return;
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                if e.kind() == std::io::ErrorKind::WouldBlock {
                                    // Stream not ready for writing, retry after small delay
                                    thread::sleep(Duration::from_millis(5));
                                    retry_count += 1;
                                } else {
                                    debug_log(&format!("Write error: {}", e));
                                    let _ = tx_output.send("DISCONNECT".to_string());
                                    return;
                                }
                            }
                        }
                    }
                    
                    if !write_success {
                        debug_log(&format!("Failed to write message after {} retries: {}", MAX_WRITE_RETRIES, msg));
                        let _ = tx_output.send("DISCONNECT".to_string());
                        return;
                    }
                }
                
                // Priority 2: Check for incoming data (like OpenSSL s_client polling)
                let mut temp_buf = [0u8; 1024];
                match stream.read(&mut temp_buf) {
                    Ok(0) => {
                        debug_log("Server closed connection");
                        let _ = tx_output.send("DISCONNECT".to_string());
                        break;
                    }
                    Ok(n) => {
                        // Process received data
                        if let Ok(data) = std::str::from_utf8(&temp_buf[..n]) {
                            read_buffer.push_str(data);
                            
                            // Process complete lines
                            while let Some(newline_pos) = read_buffer.find('\n') {
                                let line = read_buffer[..newline_pos].trim().to_string();
                                read_buffer = read_buffer[newline_pos + 1..].to_string();
                                
                                if !line.is_empty() {
                                    debug_log(&format!("Received: {}", line));
                                    if tx_output.send(line).is_err() {
                                        debug_log("Output channel disconnected");
                                        return;
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            // No data available right now - this is normal for non-blocking I/O
                            // Continue to next iteration to check for outgoing messages
                        } else {
                            debug_log(&format!("Read error: {}", e));
                            let _ = tx_output.send("DISCONNECT".to_string());
                            break;
                        }
                    }
                }
                
                // Small sleep only if no work was done to prevent CPU spinning
                if !processed_outgoing {
                    thread::sleep(Duration::from_millis(10));
                }
            }
            debug_log("Stream handler ended");
        });
    }

    fn run_terminal(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let rx_output = self.rx_output.take().unwrap();
        
        println!("=== Debug Chat Client ===");
        println!("Type messages and press Enter to send");
        println!("Commands: /nick <name>, /who, /quit");
        println!("Signing Key: {}", if self.key_registered { "✅ Registered" } else { "❌ Not Registered" });
        println!("===========================");
        print!("> ");
        io::stdout().flush().unwrap();

        // Start input thread
        let tx_write = self.tx_write.clone();
        let signing_state = self.signing_state.clone();
        let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let running_clone = running.clone();
        
        thread::spawn(move || {
            loop {
                let mut input = String::new();
                match io::stdin().read_line(&mut input) {
                    Ok(_) => {
                        let msg = input.trim().to_string();
                        if !msg.is_empty() {
                            if let Some(ref tx) = tx_write {
                                debug_log(&format!("Sending: {}", msg));
                                
                                // Handle special case: /register_key command should be sent unsigned
                                let message_to_send = if msg.starts_with("/register_key") {
                                    debug_log("Sending unsigned /register_key command");
                                    msg.clone()
                                } else {
                                    // Sign all other messages using thread-safe signing state
                                    match signing_state.sign_message(&msg) {
                                        Ok(signed_msg) => {
                                            debug_log("Message signed successfully");
                                            signed_msg
                                        }
                                        Err(e) => {
                                            debug_log(&format!("Failed to sign message: {}", e));
                                            msg.clone() // Fallback to unsigned
                                        }
                                    }
                                };
                                
                                match tx.send(message_to_send) {
                                    Ok(()) => {
                                        debug_log("Message queued successfully");
                                        // Check if this was a quit command AFTER sending it
                                        if msg == "/quit" {
                                            debug_log("Quit command sent, waiting for graceful disconnect");
                                            thread::sleep(Duration::from_millis(500)); // Wait for server to process
                                            running_clone.store(false, std::sync::atomic::Ordering::Relaxed);
                                            break;
                                        }
                                    }
                                    Err(e) => {
                                        debug_log(&format!("Failed to send message: {}", e));
                                        running_clone.store(false, std::sync::atomic::Ordering::Relaxed);
                                        break;
                                    }
                                }
                            }
                        }
                        // Only print new prompt if still running
                        if running_clone.load(std::sync::atomic::Ordering::Relaxed) {
                            print!("> ");
                            io::stdout().flush().unwrap();
                        }
                    }
                    Err(e) => {
                        debug_log(&format!("Input error: {}", e));
                        running_clone.store(false, std::sync::atomic::Ordering::Relaxed);
                        break;
                    }
                }
            }
        });

        // Main message loop - check the shared running flag
        while running.load(std::sync::atomic::Ordering::Relaxed) {
            if let Ok(msg) = rx_output.try_recv() {
                if msg == "DISCONNECT" {
                    println!("\n[CONNECTION LOST]");
                    running.store(false, std::sync::atomic::Ordering::Relaxed);
                    break;
                } else if msg.contains("Client signing key registered successfully") {
                    self.key_registered = true;
                    println!("🔑 {}", msg);
                    print!("> ");
                    io::stdout().flush().unwrap();
                } else {
                    println!("<< {}", msg);
                    // Reprint prompt after server message
                    print!("> ");
                    io::stdout().flush().unwrap();
                }
            }
            thread::sleep(Duration::from_millis(50));
        }

        println!("\nExiting chat client...");
        Ok(())
    }

    #[allow(dead_code)]
    fn get_nickname(&self) -> &str {
        &self.nickname
    }
    
    fn send_message(&mut self, message: String) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(ref tx) = self.tx_write {
            self.sign_and_send_message(&message, tx)?;
        }
        Ok(())
    }
}

// TUI Chat Client with beautiful interface
struct TuiChatClient {
    nickname: String,
    messages: VecDeque<String>,
    users: Vec<String>,
    input: String,
    status: String,
    tx_write: Option<Sender<String>>,
    rx_output: Option<Receiver<String>>,
    running: bool,
    last_heartbeat: std::time::Instant,
    heartbeat_interval: Duration,
    // Chat scrolling functionality
    scroll_offset: usize,
    auto_scroll: bool,
    // Input cursor functionality
    cursor_position: usize,
    // Message signature verification
    message_manager: ClientMessageManager,
    // Client message signing
    signing_key: Vec<u8>,
    message_counter: u64,
    key_registered: bool,
}

impl ChatClient for TuiChatClient {
    fn sign_and_send_message(&self, message: &str, tx: &Sender<String>) -> Result<(), Box<dyn std::error::Error>> {
        // TuiChatClient uses traditional signing with mutable counter
        // This is a simplified version - the full implementation should use the unified approach
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.signing_key)
            .map_err(|_| "Invalid key length")?;
        
        // For now, use a simple timestamp-based nonce (TUI client should be updated to use SigningState)
        let timestamp = SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
        let message_to_sign = format!("{}|0|{}", timestamp, message); // Using 0 as nonce placeholder
        
        mac.update(message_to_sign.as_bytes());
        let result = mac.finalize();
        let signature = general_purpose::STANDARD.encode(result.into_bytes());
        let signature_with_metadata = format!("{}|0|{}", timestamp, signature);
        
        let signed_message = format_signed_message(&signature_with_metadata, message);
        tx.send(signed_message)?;
        Ok(())
    }
}

impl TuiChatClient {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        // Random heartbeat interval between 1-3 seconds
        let mut rng = rand::thread_rng();
        let heartbeat_interval = Duration::from_millis(HEARTBEAT_INTERVAL_MIN_MS + rng.gen_range(0..(HEARTBEAT_INTERVAL_MAX_MS - HEARTBEAT_INTERVAL_MIN_MS)));
        
        // Initialize message manager for signature verification
        let message_manager = ClientMessageManager::new()?;
        
        // Generate client signing key
        let mut signing_key = vec![0u8; CLIENT_SIGNING_KEY_SIZE];
        rng.fill_bytes(&mut signing_key);
        
        Ok(Self {
            nickname: "User".to_string(),
            messages: VecDeque::new(),
            users: Vec::new(),
            input: String::new(),
            status: "Initializing...".to_string(),
            tx_write: None,
            rx_output: None,
            running: false,
            last_heartbeat: std::time::Instant::now(),
            heartbeat_interval,
            scroll_offset: 0,
            auto_scroll: true,
            cursor_position: 0,
            message_manager,
            signing_key,
            message_counter: 0,
            key_registered: false,
        })
    }

    fn connect(&mut self, host: &str, port: u16) -> Result<(), Box<dyn std::error::Error>> {
        self.status = format!("Connecting to {}:{}...", host, port);
        debug_log(&format!("TUI client connecting to {}:{}", host, port));
        
        let config = ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(std::sync::Arc::new(AcceptAllVerifier))
            .with_no_client_auth();

        self.status = "Establishing TCP connection...".to_string();
        let tcp_stream = TcpStream::connect(format!("{}:{}", host, port))?;
        tcp_stream.set_nonblocking(true)?;
        
        self.status = "Negotiating TLS handshake...".to_string();
        let server_name = host.try_into()?;
        let conn = ClientConnection::new(std::sync::Arc::new(config), server_name)?;
        let tls_stream = StreamOwned::new(conn, tcp_stream);

        self.status = "Connected! Setting up chat...".to_string();
        debug_log("TUI TLS connection established");
        
        // Small delay to allow TLS handshake to complete
        thread::sleep(Duration::from_millis(100));
        
        self.running = true;

        let (tx_write, rx_write) = channel();
        let (tx_output, rx_output) = channel();
        
        self.tx_write = Some(tx_write);
        self.rx_output = Some(rx_output);

        self.start_stream_handler(tls_stream, rx_write, tx_output);
        Ok(())
    }

    fn start_stream_handler(&self, mut stream: TlsStream, rx_write: Receiver<String>, tx_output: Sender<String>) {
        thread::spawn(move || {
            debug_log("TUI stream handler started");
            let mut read_buffer = String::new();
            
            loop {
                let mut processed_outgoing = false;
                while let Ok(msg) = rx_write.try_recv() {
                    processed_outgoing = true;
                    debug_log(&format!("TUI processing outgoing: {}", msg));
                    
                    // Handle non-blocking write with retry logic
                    let mut write_success = false;
                    let mut retry_count = 0;
                    const MAX_WRITE_RETRIES: usize = 10;
                    
                    while !write_success && retry_count < MAX_WRITE_RETRIES {
                        match write!(stream, "{}\r\n", msg) {
                            Ok(()) => {
                                match stream.flush() {
                                    Ok(()) => {
                                        debug_log(&format!("TUI sent: {}", msg));
                                        write_success = true;
                                    }
                                    Err(e) => {
                                        if e.kind() == std::io::ErrorKind::WouldBlock {
                                            // Stream not ready for flush, retry after small delay
                                            thread::sleep(Duration::from_millis(5));
                                            retry_count += 1;
                                        } else {
                                            debug_log(&format!("TUI flush error: {}", e));
                                            let _ = tx_output.send("DISCONNECT".to_string());
                                            return;
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                if e.kind() == std::io::ErrorKind::WouldBlock {
                                    // Stream not ready for writing, retry after small delay
                                    thread::sleep(Duration::from_millis(5));
                                    retry_count += 1;
                                } else {
                                    debug_log(&format!("TUI write error: {}", e));
                                    let _ = tx_output.send("DISCONNECT".to_string());
                                    return;
                                }
                            }
                        }
                    }
                    
                    if !write_success {
                        debug_log(&format!("Failed to write message after {} retries: {}", MAX_WRITE_RETRIES, msg));
                        let _ = tx_output.send("DISCONNECT".to_string());
                        return;
                    }
                }
                
                let mut temp_buf = [0u8; 1024];
                match stream.read(&mut temp_buf) {
                    Ok(0) => {
                        debug_log("TUI server closed connection");
                        let _ = tx_output.send("DISCONNECT".to_string());
                        break;
                    }
                    Ok(n) => {
                        if let Ok(data) = std::str::from_utf8(&temp_buf[..n]) {
                            read_buffer.push_str(data);
                            
                            while let Some(newline_pos) = read_buffer.find('\n') {
                                let line = read_buffer[..newline_pos].trim().to_string();
                                read_buffer = read_buffer[newline_pos + 1..].to_string();
                                
                                if !line.is_empty() {
                                    debug_log(&format!("TUI received: {}", line));
                                    debug_log(&format!("TUI processing line: '{}'", line));
                                    
                                    // Check if this is a signed message from the server
                                    if line.contains(SIGNED_MESSAGE_PREFIX) {
                                        debug_log("🔐 TUI: Message appears to be signed by server");
                                    }
                                    
                                    if tx_output.send(line).is_err() {
                                        debug_log("TUI output channel disconnected");
                                        return;
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        if e.kind() != std::io::ErrorKind::WouldBlock {
                            debug_log(&format!("TUI read error: {}", e));
                            let _ = tx_output.send("DISCONNECT".to_string());
                            break;
                        }
                    }
                }
                
                if !processed_outgoing {
                    thread::sleep(Duration::from_millis(10));
                }
            }
            debug_log("TUI stream handler ended");
        });
    }

    fn run_tui(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Setup terminal
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        // Automatically register signing key with server
        self.status = "Registering signing key...".to_string();
        let key_base64 = general_purpose::STANDARD.encode(&self.signing_key);
        debug_log(&format!("🔑 Registering client signing key: {}...", key_base64));
        self.send_message(format!("{} {}", COMMAND_REGISTER_KEY, key_base64))?;
        
        // Wait for key registration to complete
        thread::sleep(Duration::from_millis(KEY_REGISTRATION_WAIT_MS));
        
        // Send initial /who command to populate user list
        self.status = "Getting user list...".to_string();
        thread::sleep(Duration::from_millis(CONNECTION_STABILIZATION_MS)); // Wait for connection to stabilize
        self.send_message(COMMAND_WHO.to_string())?;

        let rx_output = self.rx_output.take().unwrap();
        let result = self.run_tui_loop(&mut terminal, rx_output);

        // Restore terminal
        disable_raw_mode()?;
        execute!(
            terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        )?;
        terminal.show_cursor()?;

        result
    }

    fn run_tui_loop<B: Backend>(&mut self, terminal: &mut Terminal<B>, rx_output: Receiver<String>) -> Result<(), Box<dyn std::error::Error>> {
        let mut last_tick = std::time::Instant::now();
        let tick_rate = Duration::from_millis(100);

        loop {
            terminal.draw(|f| self.ui(f))?;

            let timeout = tick_rate.saturating_sub(last_tick.elapsed());
            if crossterm::event::poll(timeout)? {
                if let Event::Key(key) = event::read()? {
                    if key.kind == KeyEventKind::Press {
                        match key.code {
                            KeyCode::Char('q') if key.modifiers.contains(crossterm::event::KeyModifiers::CONTROL) => {
                                self.status = "Disconnecting...".to_string();
                                self.send_message("/quit".to_string())?;
                                break;
                            }
                            KeyCode::Esc => {
                                self.status = "Press Ctrl+Q or type /quit to exit".to_string();
                            }
                            KeyCode::PageUp => {
                                self.scroll_up();
                            }
                            KeyCode::PageDown => {
                                self.scroll_down();
                            }
                            KeyCode::End => {
                                self.scroll_to_bottom();
                            }
                            KeyCode::Home => {
                                self.scroll_to_top();
                            }
                            // Ctrl+A: Move cursor to beginning of line
                            KeyCode::Char('a') if key.modifiers.contains(crossterm::event::KeyModifiers::CONTROL) => {
                                self.cursor_position = 0;
                            }
                            // Ctrl+E: Move cursor to end of line
                            KeyCode::Char('e') if key.modifiers.contains(crossterm::event::KeyModifiers::CONTROL) => {
                                self.cursor_position = self.input.len();
                            }
                            KeyCode::Enter => {
                                if !self.input.is_empty() {
                                    let message = self.input.clone();
                                    self.input.clear();
                                    self.cursor_position = 0;
                                    
                                    // Handle /quit command
                                    if message == "/quit" {
                                        self.status = "Disconnecting...".to_string();
                                        self.send_message(message)?;
                                        break;
                                    } else {
                                        self.status = "Message sent".to_string();
                                        self.send_message(message)?;
                                    }
                                }
                            }
                            KeyCode::Backspace => {
                                if self.cursor_position > 0 {
                                    self.cursor_position -= 1;
                                    self.input.remove(self.cursor_position);
                                }
                            }
                            KeyCode::Delete => {
                                if self.cursor_position < self.input.len() {
                                    self.input.remove(self.cursor_position);
                                }
                            }
                            KeyCode::Left => {
                                if self.cursor_position > 0 {
                                    self.cursor_position -= 1;
                                }
                            }
                            KeyCode::Right => {
                                if self.cursor_position < self.input.len() {
                                    self.cursor_position += 1;
                                }
                            }
                            KeyCode::Char(c) => {
                                if self.input.len() < 256 {
                                    self.input.insert(self.cursor_position, c);
                                    self.cursor_position += 1;
                                    // Clear previous status messages when typing
                                    if self.status == "Press Ctrl+Q or type /quit to exit" || self.status == "Message sent" {
                                        self.status = "Ready".to_string();
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }

            // Check for incoming messages
            while let Ok(msg) = rx_output.try_recv() {
                if msg == "DISCONNECT" {
                    self.status = "Connection lost!".to_string();
                    self.add_message("⚠️  Connection lost".to_string());
                    break;
                } else {
                    self.process_message(msg);
                }
            }

            // Heartbeat: Send /status request at randomized intervals
            if self.last_heartbeat.elapsed() >= self.heartbeat_interval {
                debug_log(&format!("Sending heartbeat (interval: {}ms)", self.heartbeat_interval.as_millis()));
                if let Err(e) = self.send_message("/status".to_string()) {
                    debug_log(&format!("Heartbeat failed: {}", e));
                }
                self.last_heartbeat = std::time::Instant::now();
                
                // Randomize next interval (1-3 seconds)
                let mut rng = rand::thread_rng();
                self.heartbeat_interval = Duration::from_millis(1000 + rng.gen_range(0..2000));
            }

            if last_tick.elapsed() >= tick_rate {
                last_tick = std::time::Instant::now();
            }
        }

        Ok(())
    }



    fn process_message(&mut self, msg: String) {
        // Check if this is a JSON status response
        if msg.starts_with('{') && msg.contains("\"users\"") {
            if let Ok(status_response) = serde_json::from_str::<StatusResponse>(&msg) {
                self.process_status_response(status_response);
                return;
            } else {
                debug_log(&format!("Failed to parse JSON status: {}", msg));
            }
        }
        
        // Parse different message types and update UI state
        if msg.contains("joined the chat") {
            self.add_message(format!("🟢 {}", msg));
            // Extract username from "*** username joined the chat ***"
            if let Some(username) = self.extract_username_from_join(&msg) {
                self.status = format!("{} joined the chat", username);
                if !self.users.contains(&username) {
                    self.users.push(username);
                    self.users.sort();
                }
            }
        } else if msg.contains("left the chat") {
            self.add_message(format!("🔴 {}", msg));
            // Extract username from "*** username left the chat ***"
            if let Some(username) = self.extract_username_from_leave(&msg) {
                self.status = format!("{} left the chat", username);
                self.users.retain(|u| u != &username);
            }
        } else if msg.starts_with("Online users") {
            // Parse user list: "Online users (2): alice, bob"
            if let Some(users_part) = msg.split(": ").nth(1) {
                self.users = users_part.split(", ").map(|s| s.trim().to_string()).collect();
                self.users.sort();
            }
            self.status = format!("{} users online", self.users.len());
            self.add_message(format!("👥 {}", msg));
        } else if msg.starts_with("Your nickname is now:") {
            if let Some(nick) = msg.split(": ").nth(1) {
                let old_nick = self.nickname.clone();
                self.nickname = nick.to_string();
                self.status = format!("Nickname changed to {}", nick);
                // Update the nickname in the user list
                if let Some(pos) = self.users.iter().position(|u| u == &old_nick) {
                    self.users[pos] = nick.to_string();
                    self.users.sort();
                }
            }
            self.add_message(format!("📝 {}", msg));
        } else if msg.starts_with("Welcome!") {
            self.status = "Connected! Welcome to the chat".to_string();
            self.add_message(format!("🎉 {}", msg));
        } else if msg.starts_with("You are User") {
            // Extract initial username from "You are User1."
            if let Some(user_part) = msg.strip_prefix("You are ").and_then(|s| s.strip_suffix(".")) {
                self.nickname = user_part.to_string();
                self.status = format!("Logged in as {}", user_part);
                if !self.users.contains(&self.nickname) {
                    self.users.push(self.nickname.clone());
                    self.users.sort();
                }
            }
            self.add_message(format!("🎉 {}", msg));
        } else if msg.starts_with("Error:") {
            self.status = "Error: Invalid command or nickname".to_string();
            self.add_message(format!("❌ {}", msg));
        } else if msg.contains("Client signing key registered successfully") {
            self.key_registered = true;
            self.status = "✅ Signing key registered with server".to_string();
            self.add_message(format!("🔑 {}", msg));
        } else {
            // Regular chat message
            if msg.starts_with('[') && msg.contains("]:") {
                self.status = "Ready".to_string();
                
                // Extract sender from chat message format "[sender]: message"
                if let Some(sender_end) = msg.find("]:") {
                    let sender = &msg[1..sender_end]; // Remove the '[' and get username
                    
                    // Check if this is a new username we haven't seen before
                    if !sender.is_empty() && !self.users.contains(&sender.to_string()) {
                        // This might be a user who changed their nickname
                        // Add them to the roster and trigger a /who to get accurate list
                        self.users.push(sender.to_string());
                        self.users.sort();
                        self.status = format!("Detected new user: {}", sender);
                        
                        // Send /who command to refresh the complete user list
                        // Note: This direct tx.send call bypasses signing - this is intentional for internal commands
                    }
                }
            }
            self.add_message(msg);
        }
    }

    fn process_status_response(&mut self, status: StatusResponse) {
        debug_log(&format!("Processing status response: {} users", status.total_users));
        
        // Update user roster from status response
        let mut new_users = Vec::new();
        let mut nickname_changes = Vec::new();
        
        for user_status in &status.users {
            new_users.push(user_status.nickname.clone());
            
            if user_status.nickname_changed {
                nickname_changes.push(user_status.nickname.clone());
            }
        }
        
        // Check for users who left (were in old list but not in new list)
        for old_user in &self.users {
            if !new_users.contains(old_user) {
                self.status = format!("{} left the chat", old_user);
                debug_log(&format!("User {} left (detected via heartbeat)", old_user));
            }
        }
        
        // Check for users who joined (were not in old list but are in new list)
        for new_user in &new_users {
            if !self.users.contains(new_user) {
                self.status = format!("{} joined the chat", new_user);
                debug_log(&format!("User {} joined (detected via heartbeat)", new_user));
            }
        }
        
        // Update the user list
        self.users = new_users;
        self.users.sort();
        
        // Handle nickname changes
        if !nickname_changes.is_empty() {
            for user_status in &status.users {
                if user_status.nickname_changed {
                    if let Some(old_nick) = &user_status.old_nickname {
                        let nickname_change_msg = format!("*** User {} is now {} ***", old_nick, user_status.nickname);
                        self.add_message(nickname_change_msg.clone());
                        self.status = format!("{} changed nickname to {}", old_nick, user_status.nickname);
                        debug_log(&format!("Nickname change: {} -> {}", old_nick, user_status.nickname));
                    } else {
                        self.status = format!("{} changed nickname", user_status.nickname);
                        debug_log(&format!("Nickname change detected: {}", user_status.nickname));
                    }
                }
            }
        }
        
        // Update status bar with current info
        if self.status.starts_with("Ready") || self.status.contains("users online") {
            self.status = format!("{} users online", status.total_users);
        }
    }

    fn extract_username_from_join(&self, msg: &str) -> Option<String> {
        // Parse "*** username joined the chat ***"
        if msg.starts_with("*** ") && msg.ends_with(" joined the chat ***") {
            let username = msg.strip_prefix("*** ")?.strip_suffix(" joined the chat ***")?;
            Some(username.to_string())
        } else {
            None
        }
    }

    fn extract_username_from_leave(&self, msg: &str) -> Option<String> {
        // Parse "*** username left the chat ***"
        if msg.starts_with("*** ") && msg.ends_with(" left the chat ***") {
            let username = msg.strip_prefix("*** ")?.strip_suffix(" left the chat ***")?;
            Some(username.to_string())
        } else {
            None
        }
    }

    fn add_message(&mut self, message: String) {
        // Check for key registration success
        if message.contains(RESPONSE_KEY_REGISTERED) {
            self.key_registered = true;
            debug_log("✅ TUI Client signing key registered successfully");
        }
        
        self.messages.push_back(message);
        if self.messages.len() > MAX_CHAT_HISTORY_LINES {
            self.messages.pop_front();
        }
        
        // Auto-scroll to bottom when new messages arrive (unless user manually scrolled up)
        if self.auto_scroll {
            self.scroll_offset = 0;
        }
    }

    // Scrolling functionality
    fn scroll_up(&mut self) {
        const SCROLL_PAGE_SIZE: usize = 10;
        let max_offset = self.messages.len().saturating_sub(1);
        self.scroll_offset = (self.scroll_offset + SCROLL_PAGE_SIZE).min(max_offset);
        self.auto_scroll = false;
        self.status = format!("Scrolled up (offset: {}/{})", self.scroll_offset, max_offset);
    }

    fn scroll_down(&mut self) {
        const SCROLL_PAGE_SIZE: usize = 10;
        if self.scroll_offset >= SCROLL_PAGE_SIZE {
            self.scroll_offset -= SCROLL_PAGE_SIZE;
            self.status = format!("Scrolled down (offset: {})", self.scroll_offset);
        } else {
            self.scroll_offset = 0;
            self.auto_scroll = true;
            self.status = "Auto-scroll enabled".to_string();
        }
    }

    fn scroll_to_top(&mut self) {
        self.scroll_offset = self.messages.len().saturating_sub(1);
        self.auto_scroll = false;
        self.status = format!("Scrolled to top (offset: {})", self.scroll_offset);
    }

    fn scroll_to_bottom(&mut self) {
        self.scroll_offset = 0;
        self.auto_scroll = true;
        self.status = "Scrolled to bottom (auto-scroll enabled)".to_string();
    }



    fn ui(&self, f: &mut Frame) {
        // Main layout: Top area and status bar at bottom
        let main_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(1), Constraint::Length(1)].as_ref())
            .split(f.size());

        // Top area: Chat (left) and Users (right)
        let top_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(75), Constraint::Percentage(25)].as_ref())
            .split(main_chunks[0]);

        // Left side: Chat messages and input
        let left_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(1), Constraint::Length(3)].as_ref())
            .split(top_chunks[0]);

        // Chat messages window with proper viewport-based scrolling
        let total_messages = self.messages.len();
        let chat_height = left_chunks[0].height.saturating_sub(2); // Account for borders
        
        let visible_messages: Vec<ListItem> = if total_messages > 0 && chat_height > 0 {
            // Calculate which messages to show based on viewport and scroll offset
            let max_visible = chat_height as usize;
            
            if self.auto_scroll {
                // Auto-scroll: show the last 'max_visible' messages
                let start_index = if total_messages > max_visible {
                    total_messages - max_visible
                } else {
                    0
                };
                
                self.messages
                    .range(start_index..total_messages)
                    .map(|m| {
                        let style = if m.contains("🟢") || m.contains("🔴") {
                            Style::default().fg(Color::Yellow)
                        } else if m.contains("👥") || m.contains("📝") || m.contains("🎉") {
                            Style::default().fg(Color::Cyan)
                        } else if m.starts_with('[') && m.contains("]:") {
                            Style::default().fg(Color::Green)
                        } else {
                            Style::default().fg(Color::White)
                        };
                        ListItem::new(Line::from(Span::styled(m.clone(), style)))
                    })
                    .collect()
            } else {
                // Manual scroll: show messages based on scroll offset
                let start_index = if self.scroll_offset >= total_messages {
                    0
                } else {
                    total_messages.saturating_sub(self.scroll_offset).saturating_sub(max_visible)
                };
                let end_index = total_messages.saturating_sub(self.scroll_offset);
                
                self.messages
                    .range(start_index..end_index)
                    .map(|m| {
                        let style = if m.contains("🟢") || m.contains("🔴") {
                            Style::default().fg(Color::Yellow)
                        } else if m.contains("👥") || m.contains("📝") || m.contains("🎉") {
                            Style::default().fg(Color::Cyan)
                        } else if m.starts_with('[') && m.contains("]:") {
                            Style::default().fg(Color::Green)
                        } else {
                            Style::default().fg(Color::White)
                        };
                        ListItem::new(Line::from(Span::styled(m.clone(), style)))
                    })
                    .collect()
            }
        } else {
            Vec::new()
        };

        let messages_block = Block::default()
            .borders(Borders::ALL)
            .style(Style::default().fg(Color::Blue))
            .title(format!(" 💬 Chat - {} {} ", 
                self.nickname, 
                if self.scroll_offset > 0 { 
                    format!("(↑{} lines)", self.scroll_offset) 
                } else { 
                    String::new() 
                }
            ));

        let messages_list = List::new(visible_messages)
            .block(messages_block)
            .style(Style::default().fg(Color::White));

        f.render_widget(messages_list, left_chunks[0]);

        // Input box
        let input_block = Block::default()
            .borders(Borders::ALL)
            .style(Style::default().fg(Color::Green))
            .title(" 💭 Type | ←→: cursor | Ctrl+A/E: start/end | PgUp/PgDn: scroll | Ctrl+Q: quit ");

        // Create input string with visible cursor
        let mut input_with_cursor = self.input.clone();
        if self.cursor_position <= input_with_cursor.len() {
            input_with_cursor.insert(self.cursor_position, '│'); // Using vertical bar as cursor
        }

        let input_paragraph = Paragraph::new(input_with_cursor.as_str())
            .style(Style::default().fg(Color::White))
            .block(input_block)
            .wrap(Wrap { trim: true });

        f.render_widget(input_paragraph, left_chunks[1]);

        // User roster
        let users: Vec<ListItem> = self
            .users
            .iter()
            .map(|u| {
                let style = if u == &self.nickname {
                    Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::Green)
                };
                ListItem::new(Line::from(Span::styled(format!("👤 {}", u), style)))
            })
            .collect();

        let users_block = Block::default()
            .borders(Borders::ALL)
            .style(Style::default().fg(Color::Magenta))
            .title(format!(" 👥 Users ({}) ", self.users.len()));

        let users_list = List::new(users)
            .block(users_block)
            .style(Style::default().fg(Color::Green));

        f.render_widget(users_list, top_chunks[1]);

        // Status bar at the bottom
        let status_color = if self.status.contains("Error") || self.status.contains("lost") {
            Color::Red
        } else if self.status.contains("joined") || self.status.contains("Connected") {
            Color::Green
        } else if self.status.contains("Disconnecting") {
            Color::Yellow
        } else {
            Color::Cyan
        };

        let status_bar = Paragraph::new(format!(" 📡 {} | 🔑 Key: {}", 
            self.status, 
            if self.key_registered { "✅ Registered" } else { "❌ Not Registered" }
        ))
            .style(Style::default().fg(status_color).add_modifier(Modifier::BOLD))
            .block(Block::default().style(Style::default().fg(Color::Gray)));

        f.render_widget(status_bar, main_chunks[1]);
    }
    
    fn send_message(&mut self, message: String) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(ref tx) = self.tx_write {
            self.sign_and_send_message(&message, tx)?;
        }
        Ok(())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    
    if args.debug {
        DEBUG.store(true, std::sync::atomic::Ordering::Relaxed);
        debug_log("Debug mode enabled");
    }

    if args.tui {
        // TUI Mode - Beautiful terminal interface
        println!("Starting TUI Chat Client...");
        println!("Connecting to {}:{}...", args.host, args.port);
        
        let mut tui_client = TuiChatClient::new()?;
        match tui_client.connect(&args.host, args.port) {
            Ok(()) => {
                tui_client.run_tui()?;
            }
            Err(e) => {
                eprintln!("Connection failed: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        // Debug Mode - Terminal with debug output
        println!("Connecting to {}:{}...", args.host, args.port);

        let mut client = DebugChatClient::new();
        match client.connect(&args.host, args.port) {
            Ok(()) => {
                println!("Connected!");
                client.run_terminal()?;
            }
            Err(e) => {
                eprintln!("Connection failed: {}", e);
                std::process::exit(1);
            }
        }
    }

    println!("Goodbye!");
    Ok(())
}