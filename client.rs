// client.rs - Fixed Client implementation for TLS Chat system
use std::io::{self, Write, Read};
use std::net::TcpStream;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, Duration};

use rustls::{ClientConfig, ClientConnection, StreamOwned, Certificate, ServerName};
use rustls::client::{ServerCertVerifier, ServerCertVerified};
// Removed unused serde imports
use rand::RngCore;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use base64::{Engine as _, engine::general_purpose};
use pbkdf2::pbkdf2_hmac_array;
mod config;
use config::*;

type TlsStream = StreamOwned<ClientConnection, TcpStream>;

// Unified certificate verifier with command line control
struct ConfigurableCertVerifier {
    allow_self_signed: bool,
}

impl ConfigurableCertVerifier {
    fn new(allow_self_signed: bool) -> Self {
        Self { allow_self_signed }
    }
}

impl ServerCertVerifier for ConfigurableCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: SystemTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if self.allow_self_signed {
            debug_log("Accepting self-signed certificate (--allow-self-signed enabled)");
            Ok(ServerCertVerified::assertion())
        } else {
            // Use default WebPKI verification for production
            Err(rustls::Error::General("Certificate verification not implemented for production use".into()))
        }
    }
}

// Unified key manager for client message signing only
#[derive(Clone)]
struct UnifiedKeyManager {
    signing_key: Vec<u8>,
    message_counter: Arc<Mutex<u64>>,
}

impl UnifiedKeyManager {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        // Generate secure signing key with PBKDF2 strengthening
        let mut base_key = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut base_key);
        
        // Use PBKDF2 for key strengthening (client-side only)
        let salt = b"chat_client_signing_salt_2024";
        let signing_key: [u8; 32] = pbkdf2_hmac_array::<Sha256, 32>(&base_key, salt, 100_000);
        
        debug_log("Client signing key generated with PBKDF2");
        
        Ok(Self {
            signing_key: signing_key.to_vec(),
            message_counter: Arc::new(Mutex::new(0)),
        })
    }
    
    fn sign_message(&self, message: &str) -> Result<String, Box<dyn std::error::Error>> {
        use std::time::UNIX_EPOCH;
        
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let nonce = {
            let mut counter = self.message_counter.lock().unwrap();
            let current = *counter;
            *counter += 1;
            current
        };
        
        let message_to_sign = format!("{}|{}|{}", timestamp, nonce, message);
        
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.signing_key)
            .map_err(|_| "Invalid signing key length")?;
        mac.update(message_to_sign.as_bytes());
        let result = mac.finalize();
        
        let signature = general_purpose::STANDARD.encode(result.into_bytes());
        let signature_with_metadata = format!("{}|{}|{}", timestamp, nonce, signature);
        
        Ok(format_signed_message(&signature_with_metadata, message))
    }
    
    fn get_signing_key_b64(&self) -> String {
        general_purpose::STANDARD.encode(&self.signing_key)
    }
}

// Unified stream handler for both client types
struct UnifiedStreamHandler;

impl UnifiedStreamHandler {
    fn handle_stream(
        mut stream: TlsStream,
        rx_write: Receiver<String>,
        tx_output: Sender<String>,
        client_type: String,
    ) {
        thread::spawn(move || {
            debug_log(&format!("{} stream handler started", client_type));
            let mut read_buffer = String::new();
            
            loop {
                // Process outgoing messages with unified retry logic
                let mut processed_outgoing = false;
                while let Ok(msg) = rx_write.try_recv() {
                    processed_outgoing = true;
                    debug_log(&format!("{} processing outgoing: {}", client_type, msg));
                    
                    if let Err(e) = Self::write_with_retry(&mut stream, &msg) {
                        debug_log(&format!("{} write error: {}", client_type, e));
                        let _ = tx_output.send("DISCONNECT".to_string());
                        return;
                    }
                }
                
                // Process incoming messages
                if let Err(e) = Self::read_messages(&mut stream, &mut read_buffer, &tx_output, &client_type) {
                    if e.kind() != std::io::ErrorKind::WouldBlock {
                        debug_log(&format!("{} read error: {}", client_type, e));
                        let _ = tx_output.send("DISCONNECT".to_string());
                        break;
                    }
                }
                
                if !processed_outgoing {
                    thread::sleep(Duration::from_millis(10));
                }
            }
            debug_log(&format!("{} stream handler ended", client_type));
        });
    }
    
    fn write_with_retry(stream: &mut TlsStream, msg: &str) -> std::io::Result<()> {
        let mut retry_count = 0;
        const MAX_RETRIES: usize = 10;
                    
        while retry_count < MAX_RETRIES {
            match write!(stream, "{}\r\n", msg) {
            Ok(()) => {
                    match stream.flush() {
                        Ok(()) => {
                            debug_log(&format!("Sent: {}", msg));
                            return Ok(());
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(5));
                            retry_count += 1;
                        }
                        Err(e) => return Err(e),
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                    retry_count += 1;
                }
                Err(e) => return Err(e),
            }
        }
        
        Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("Failed to write after {} retries", MAX_RETRIES)
        ))
    }
    
    fn read_messages(
        stream: &mut TlsStream,
        read_buffer: &mut String,
        tx_output: &Sender<String>,
        client_type: &String,
    ) -> std::io::Result<()> {
        let mut temp_buf = [0u8; 1024];
        match stream.read(&mut temp_buf) {
            Ok(0) => {
                debug_log(&format!("{} server closed connection", client_type));
                let _ = tx_output.send("DISCONNECT".to_string());
                Err(std::io::Error::new(std::io::ErrorKind::ConnectionAborted, "Server closed"))
            }
            Ok(n) => {
                if let Ok(data) = std::str::from_utf8(&temp_buf[..n]) {
                    read_buffer.push_str(data);
                    
                    while let Some(newline_pos) = read_buffer.find('\n') {
                        let line = read_buffer[..newline_pos].trim().to_string();
                        *read_buffer = read_buffer[newline_pos + 1..].to_string();
                        
                        if !line.is_empty() {
                            debug_log(&format!("{} received: {}", client_type, line));
                            if tx_output.send(line).is_err() {
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::BrokenPipe, 
                                    "Output channel disconnected"
                                ));
                            }
                        }
                    }
                }
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
}

// Unified message processor for both client types
struct UnifiedMessageProcessor {
    key_manager: UnifiedKeyManager,
    nickname: String,
    key_registered: bool,
    messages: std::collections::VecDeque<String>,
    users: Vec<String>,
    status: String,
}

impl UnifiedMessageProcessor {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            key_manager: UnifiedKeyManager::new()?,
            nickname: "User".to_string(),
            key_registered: false,
            messages: std::collections::VecDeque::new(),
            users: Vec::new(),
            status: "Initializing...".to_string(),
        })
    }

    fn process_server_message(&mut self, msg: String) -> ProcessedMessage {
        // Handle key registration success - only update status, don't show in chat
        if msg.contains(RESPONSE_KEY_REGISTERED) {
            self.key_registered = true;
            self.status = "✅ Signing key registered with server".to_string();
            debug_log("🔑 Client signing key registered successfully");
            return ProcessedMessage::StatusUpdate;
        }
        
        // Handle event-driven messages from server
        if let Ok(event) = serde_json::from_str::<ServerEvent>(&msg) {
            return self.handle_server_event(event);
        }
        
        // Add normal messages to chat history
        self.messages.push_back(msg.clone());
        if self.messages.len() > MAX_CHAT_HISTORY_LINES {
            self.messages.pop_front();
        }
        
        ProcessedMessage::ChatMessage(msg)
    }

    fn handle_server_event(&mut self, event: ServerEvent) -> ProcessedMessage {
        match event {
            ServerEvent::UserJoin { nickname, .. } => {
                let join_msg = format!("*** {} joined the chat ***", nickname);
                self.messages.push_back(join_msg.clone());
                self.update_user_list();
                ProcessedMessage::ChatMessage(join_msg)
            },
            ServerEvent::UserLeave { nickname, reason, .. } => {
                let leave_msg = format!("*** {} left the chat ({}) ***", nickname, reason);
                self.messages.push_back(leave_msg.clone());
                self.update_user_list();
                ProcessedMessage::ChatMessage(leave_msg)
            },
            ServerEvent::UserTimeout { nickname, .. } => {
                let timeout_msg = format!("*** {} timed out and left the chat ***", nickname);
                self.messages.push_back(timeout_msg.clone());
                self.update_user_list();
                ProcessedMessage::ChatMessage(timeout_msg)
            },
            ServerEvent::NicknameChange { old_nickname, new_nickname, .. } => {
                let change_msg = format!("*** {} is now known as {} ***", old_nickname, new_nickname);
                self.messages.push_back(change_msg.clone());
                self.update_user_list();
                ProcessedMessage::ChatMessage(change_msg)
            },
            ServerEvent::RosterSnapshot { users, total_users, .. } => {
                self.update_roster_from_snapshot(users);
                self.status = format!("✅ Connected | {} users online", total_users);
                ProcessedMessage::StatusUpdate
            },
            ServerEvent::ConnectionEstablished { nickname, .. } => {
                self.nickname = nickname;
                self.status = "✅ Connected and authenticated".to_string();
                ProcessedMessage::StatusUpdate
            },
            ServerEvent::WelcomeMessage { message, .. } => {
                let welcome_msg = format!("🔐 {}", message);
                self.messages.push_back(welcome_msg.clone());
                ProcessedMessage::ChatMessage(welcome_msg)
            },
            ServerEvent::KeyRegistration { .. } => {
                self.key_registered = true;
                self.status = "✅ Signing key registered with server".to_string();
                ProcessedMessage::StatusUpdate
            },
            ServerEvent::CommandResponse { response, .. } => {
                let cmd_msg = format!("📋 {}", response);
                self.messages.push_back(cmd_msg.clone());
                ProcessedMessage::ChatMessage(cmd_msg)
            },
            ServerEvent::ErrorResponse { error, .. } => {
                let err_msg = format!("❌ {}", error);
                self.messages.push_back(err_msg.clone());
                ProcessedMessage::ChatMessage(err_msg)
            },
            _ => {
                debug_log(&format!("Unhandled server event: {:?}", event));
                ProcessedMessage::StatusUpdate
            }
        }
    }

    fn update_user_list(&mut self) {
        self.status = "🔄 Updating user list...".to_string();
    }

    fn update_roster_from_snapshot(&mut self, users: Vec<config::UserStatus>) {
        self.users = users.into_iter().map(|u| u.nickname).collect();
        debug_log(&format!("Updated roster: {} users", self.users.len()));
    }

    fn sign_and_send_message(&self, message: &str, tx: &Sender<String>) -> Result<(), Box<dyn std::error::Error>> {
        let signed_message = self.key_manager.sign_message(message)?;
        tx.send(signed_message)?;
        Ok(())
    }

    fn get_signing_key_b64(&self) -> String {
        self.key_manager.get_signing_key_b64()
    }
}

#[derive(Debug)]
enum ProcessedMessage {
    ChatMessage(String),
    StatusUpdate,
}

// Connection management
struct UnifiedConnection {
    tx_write: Option<Sender<String>>,
    rx_output: Option<Receiver<String>>,
    running: bool,
    allow_self_signed: bool,
}

impl UnifiedConnection {
    fn new() -> Self {
        Self {
            tx_write: None,
            rx_output: None,
            running: false,
            allow_self_signed: false,
        }
    }

    fn connect(&mut self, host: &str, port: u16, allow_self_signed: bool) -> Result<(), Box<dyn std::error::Error>> {
        self.allow_self_signed = allow_self_signed;
        debug_log(&format!("Connecting to {}:{}", host, port));
        
        let config = ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(std::sync::Arc::new(
                ConfigurableCertVerifier::new(allow_self_signed)
            ))
            .with_no_client_auth();

        let tcp_stream = TcpStream::connect(format!("{}:{}", host, port))?;
        tcp_stream.set_nonblocking(true)?;
        let server_name = host.try_into()?;
        let conn = ClientConnection::new(std::sync::Arc::new(config), server_name)?;
        let tls_stream = StreamOwned::new(conn, tcp_stream);

        debug_log("TLS connection established");
        thread::sleep(Duration::from_millis(100));
        
        self.running = true;

        let (tx_write, rx_write) = channel();
        let (tx_output, rx_output) = channel();
        
        self.tx_write = Some(tx_write);
        self.rx_output = Some(rx_output);

        // Use unified stream handler
        UnifiedStreamHandler::handle_stream(tls_stream, rx_write, tx_output, "CLIENT".to_string());

        Ok(())
    }

    fn register_key(&self, key_base64: &str) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(ref tx) = self.tx_write {
            let _ = tx.send(format!("{} {}", COMMAND_REGISTER_KEY, key_base64));
            thread::sleep(Duration::from_millis(KEY_REGISTRATION_WAIT_MS));
            Ok(())
                                        } else {
            Err("Not connected".into())
        }
    }
}

// Debug Chat Client using unified components
struct DebugChatClient {
    connection: UnifiedConnection,
    processor: UnifiedMessageProcessor,
}

impl DebugChatClient {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            connection: UnifiedConnection::new(),
            processor: UnifiedMessageProcessor::new()?,
        })
    }

    fn connect(&mut self, host: &str, port: u16, allow_self_signed: bool) -> Result<(), Box<dyn std::error::Error>> {
        self.connection.connect(host, port, allow_self_signed)?;
        
        // Register signing key
        debug_log("🔑 Registering client signing key...");
        let key_base64 = self.processor.get_signing_key_b64();
        self.connection.register_key(&key_base64)?;
        
        Ok(())
    }

    fn run_terminal(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let rx_output = self.connection.rx_output.take().unwrap();
        
        println!("=== Debug Chat Client ===");
        println!("Cert file: {}", CERT_PATH);
        let cert_indicator = if self.connection.allow_self_signed { "⚠️ SS cert" } else { "🔒 Cert" };
        println!("Certificate: {}", cert_indicator);
        println!("Commands: /nick <name>, /who, /quit");
        println!("===========================");

        // Input handling thread
        let tx_write = self.connection.tx_write.clone();
        let key_manager = self.processor.key_manager.clone();
        let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let running_clone = running.clone();
        
        thread::spawn(move || {
            let mut current_nick = String::from("you");
            loop {
                print!("> ");
                io::stdout().flush().unwrap();
                
                let mut input = String::new();
                match io::stdin().read_line(&mut input) {
                    Ok(_) => {
                        let msg = input.trim().to_string();
                        if !msg.is_empty() {
                            if let Some(ref tx) = tx_write {
                                let message_to_send = if msg.starts_with("/register_key") {
                                    msg.clone() // Send unsigned
                                } else {
                                    match key_manager.sign_message(&msg) {
                                        Ok(signed_msg) => signed_msg,
                                        Err(e) => {
                                            debug_log(&format!("Failed to sign message: {}", e));
                                            msg.clone()
                                        }
                                    }
                                };
                                
                                // If changing nickname, update our local display name immediately
                                if let Some(rest) = msg.strip_prefix("/nick ") {
                                    let new_nick = rest.trim();
                                    if !new_nick.is_empty() {
                                        current_nick = new_nick.to_string();
                                    }
                                }

                                let send_failed = tx.send(message_to_send).is_err();
                                // Local echo for non-command messages
                                if !msg.starts_with('/') {
                                    println!("[{}]: {}", current_nick, msg);
                                }
                                if send_failed || msg == "/quit" {
                                    running_clone.store(false, std::sync::atomic::Ordering::Relaxed);
                                    break;
                                }
                            }
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

        // Message processing loop
        while running.load(std::sync::atomic::Ordering::Relaxed) {
            if let Ok(msg) = rx_output.try_recv() {
                if msg == "DISCONNECT" {
                    println!("\n[CONNECTION LOST]");
                    break;
                } else {
                    match self.processor.process_server_message(msg) {
                        ProcessedMessage::ChatMessage(chat_msg) => {
                            if chat_msg.contains(RESPONSE_KEY_REGISTERED) {
                                println!("🔑 {}", chat_msg);
                            } else if let Some(rest) = chat_msg.strip_prefix("📋 Your nickname is now: ") {
                                // Sync local nickname if server confirms change
                                let new_nick = rest.trim();
                                if !new_nick.is_empty() {
                                    self.processor.nickname = new_nick.to_string();
                                }
                                println!("<< {}", chat_msg);
                            } else {
                                println!("<< {}", chat_msg);
                            }
                        }
                        ProcessedMessage::StatusUpdate => {
                            // Status updates handled internally by processor
                        }
                    }
                }
            }
            thread::sleep(Duration::from_millis(50));
        }

        println!("\nExiting chat client...");
        Ok(())
    }
}

// TUI Chat Client using unified components
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Direction, Layout},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
    Frame, Terminal,
};
// Removed unused VecDeque import
use serde_json;

struct TuiChatClient {
    connection: UnifiedConnection,
    processor: UnifiedMessageProcessor,
    input: String,
    cursor_position: usize,
    scroll_offset: usize,
    auto_scroll: bool,
}

impl TuiChatClient {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            connection: UnifiedConnection::new(),
            processor: UnifiedMessageProcessor::new()?,
            input: String::new(),
            cursor_position: 0,
            scroll_offset: 0,
            auto_scroll: true,
        })
    }

    fn connect(&mut self, host: &str, port: u16, allow_self_signed: bool) -> Result<(), Box<dyn std::error::Error>> {
        self.processor.status = format!("Connecting to {}:{}...", host, port);
        debug_log(&format!("TUI client connecting to {}:{}", host, port));
        
        self.connection.connect(host, port, allow_self_signed)?;
        
        self.processor.status = "Connected! Setting up chat...".to_string();
        
        Ok(())
    }

    fn run_tui(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        // Register signing key
        self.processor.status = "Registering signing key...".to_string();
        let key_base64 = self.processor.get_signing_key_b64();
        self.connection.register_key(&key_base64)?;
        
        self.processor.status = "Getting user list...".to_string();
        thread::sleep(Duration::from_millis(CONNECTION_STABILIZATION_MS));
        self.send_message(COMMAND_WHO.to_string())?;

        let rx_output = self.connection.rx_output.take().unwrap();
        let result = self.run_tui_loop(&mut terminal, rx_output);

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
            // Adjust scroll offset to keep messages visible
            self.adjust_scroll_for_display(terminal.size()?);
            
            terminal.draw(|f| self.ui(f))?;

            let timeout = tick_rate.saturating_sub(last_tick.elapsed());
            if crossterm::event::poll(timeout)? {
                if let Event::Key(key) = event::read()? {
                    if key.kind == KeyEventKind::Press {
                        match key.code {
                            KeyCode::Char('q') if key.modifiers.contains(crossterm::event::KeyModifiers::CONTROL) => {
                                self.processor.status = "Disconnecting...".to_string();
                                self.send_message("/quit".to_string())?;
                                break;
                            }
                            KeyCode::Enter => {
                                if !self.input.is_empty() {
                                    let message = self.input.clone();
                                    self.input.clear();
                                    self.cursor_position = 0;
                                    
                                    if message == "/quit" {
                                        self.processor.status = "Disconnecting...".to_string();
                                        self.send_message(message)?;
                                        break;
                                    } else {
                                        // If user changes nickname locally, update immediately for local echo formatting
                                        if let Some(rest) = message.strip_prefix("/nick ") {
                                            let new_nick = rest.trim();
                                            if !new_nick.is_empty() {
                                                self.processor.nickname = new_nick.to_string();
                                            }
                                        }
                                        // If it's not a command, append our own message locally
                                        if !message.starts_with('/') {
                                            let display = format!("[{}]: {}", self.processor.nickname, message);
                                            self.processor.messages.push_back(display);
                                            if self.processor.messages.len() > MAX_CHAT_HISTORY_LINES {
                                                self.processor.messages.pop_front();
                                            }
                                            if self.auto_scroll {
                                                self.scroll_offset = 0;
                                            }
                                        }
                                        self.processor.status = "Message sent".to_string();
                                        self.send_message(message)?;
                                    }
                                }
                            }
                            KeyCode::Char(c) => {
                                if self.input.len() < 256 {
                                    self.input.insert(self.cursor_position, c);
                                    self.cursor_position += 1;
                                }
                            }
                            KeyCode::Backspace => {
                                if self.cursor_position > 0 {
                                    self.cursor_position -= 1;
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
                            KeyCode::Up => {
                                // Manual scroll up
                                self.auto_scroll = false;
                                if self.scroll_offset < self.processor.messages.len().saturating_sub(1) {
                                    self.scroll_offset += 1;
                                }
                            }
                            KeyCode::Down => {
                                // Manual scroll down
                                if self.scroll_offset > 0 {
                                    self.scroll_offset -= 1;
                                } else {
                                    // Re-enable auto scroll when at bottom
                                    self.auto_scroll = true;
                                }
                            }
                            KeyCode::PageUp => {
                                self.auto_scroll = false;
                                self.scroll_offset = (self.scroll_offset + 10).min(self.processor.messages.len().saturating_sub(1));
                            }
                            KeyCode::PageDown => {
                                if self.scroll_offset >= 10 {
                                    self.scroll_offset -= 10;
                                } else {
                                    self.scroll_offset = 0;
                                    self.auto_scroll = true;
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }

            // Process incoming messages
            while let Ok(msg) = rx_output.try_recv() {
                if msg == "DISCONNECT" {
                    self.processor.status = "Connection lost!".to_string();
                    break;
                } else {
                    let result = self.processor.process_server_message(msg);
                    if matches!(result, ProcessedMessage::ChatMessage(_)) && self.auto_scroll {
                        // Keep scroll at bottom for new messages when auto-scrolling
                        self.scroll_offset = 0;
                    }
                }
            }

            if last_tick.elapsed() >= tick_rate {
                last_tick = std::time::Instant::now();
            }
        }

        Ok(())
    }

    fn adjust_scroll_for_display(&mut self, size: ratatui::layout::Rect) {
        // Calculate available height for messages (accounting for borders and input/status bars)
        let available_height = size.height.saturating_sub(6) as usize; // 3 lines for input/status + borders
        let total_messages = self.processor.messages.len();
        
        if total_messages <= available_height {
            // All messages fit, no scrolling needed
            self.scroll_offset = 0;
            } else {
            // Auto-scroll to bottom when new messages arrive (if auto_scroll is enabled)
        if self.auto_scroll {
                self.scroll_offset = 0; // 0 means show most recent messages
        } else {
                // Ensure scroll_offset doesn't exceed bounds
                let max_scroll = total_messages.saturating_sub(available_height);
                if self.scroll_offset > max_scroll {
                    self.scroll_offset = max_scroll;
                }
            }
        }
    }

    fn ui(&self, f: &mut Frame) {
        let main_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(1), Constraint::Length(3), Constraint::Length(1)].as_ref())
            .split(f.size());

        // Calculate visible message range based on scroll offset and available height
        let available_height = main_chunks[0].height.saturating_sub(2) as usize; // Account for borders
        let total_messages = self.processor.messages.len();
        
        let visible_messages: Vec<ListItem> = if total_messages == 0 {
            vec![]
                } else {
            // end index is the most recent message index + 1 (slice end), adjusted by scroll_offset
            let end_idx = total_messages.saturating_sub(self.scroll_offset);
            // start index backs off by available height (or to 0 if fewer messages)
            let start_idx = end_idx.saturating_sub(available_height);
            let start_idx = start_idx.min(total_messages);
            let end_idx = end_idx.min(total_messages);
            
            if start_idx < end_idx {
                self.processor.messages.range(start_idx..end_idx)
                    .map(|m| ListItem::new(Line::from(Span::raw(m))))
                    .collect()
            } else {
                vec![]
            }
        };

        let scroll_indicator = if !self.auto_scroll && self.scroll_offset > 0 {
            format!(" Chat - {} (↑{}) ", self.processor.nickname, self.scroll_offset)
                        } else {
            format!(" Chat - {} ", self.processor.nickname)
        };

        let messages_block = Block::default()
            .borders(Borders::ALL)
            .title(scroll_indicator);

        let messages_list = List::new(visible_messages).block(messages_block);
        f.render_widget(messages_list, main_chunks[0]);

        // Input
        let mut input_with_cursor = self.input.clone();
        if self.cursor_position <= input_with_cursor.len() {
            input_with_cursor.insert(self.cursor_position, '│');
        }

        let input_block = Block::default()
            .borders(Borders::ALL)
            .title(" Type message (↑↓ scroll, Ctrl+Q quit) ");

        let input_paragraph = Paragraph::new(input_with_cursor)
            .block(input_block)
            .wrap(Wrap { trim: true });

        f.render_widget(input_paragraph, main_chunks[1]);

        // Status
        let cert_indicator = if self.connection.allow_self_signed {
            "⚠️ SS cert"
                } else {
            "🔒 Cert"
        };
        
        let status_bar = Paragraph::new(format!(" {} | Key: {} | Cert: {} | {}", 
            self.processor.status,
            if self.processor.key_registered { "✅" } else { "❌" },
            CERT_PATH,
            cert_indicator
        ))
        .style(Style::default().fg(Color::Cyan));

        f.render_widget(status_bar, main_chunks[2]);
    }

    fn send_message(&mut self, message: String) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(ref tx) = self.connection.tx_write {
            self.processor.sign_and_send_message(&message, tx)?;
        }
        Ok(())
    }
}

// Fixed argument parsing with --server support
struct Args {
    host: String,
    port: u16,
    debug: bool,
    tui: bool,
    allow_self_signed: bool,
}

impl Args {
    fn parse() -> Self {
        let args: Vec<String> = std::env::args().collect();
        let mut host = "localhost".to_string();
        let mut port = 8443u16;
        let mut debug = false;
        let mut tui = false;
        let mut allow_self_signed = false;
        
        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "--host" | "--server" => {  // Accept both --host and --server
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
                "--allow-self-signed" => {
                    allow_self_signed = true;
                    eprintln!("⚠️  WARNING: Accepting self-signed certificates");
                }
                "--help" => {
                    println!("Usage: {} [OPTIONS]", args[0]);
                    println!("Options:");
                    println!("  --host HOST              Server hostname (default: localhost)");
                    println!("  --server HOST            Server hostname (alias for --host)");
                    println!("  --port PORT              Server port (default: 8443)");
                    println!("  --debug                  Enable debug output");
                    println!("  --tui                    Use terminal UI mode");
                    println!("  --allow-self-signed      Accept self-signed certificates");
                    println!("  --help                   Show this help");
                    println!("\nCert file: {}", CERT_PATH);
                    std::process::exit(0);
                }
                _ => {}
            }
            i += 1;
        }
        
        Args { host, port, debug, tui, allow_self_signed }
    }
}

static DEBUG: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn debug_log(msg: &str) {
    if DEBUG.load(std::sync::atomic::Ordering::Relaxed) {
        println!("[DEBUG] {}", msg);
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    
    if args.debug {
        DEBUG.store(true, std::sync::atomic::Ordering::Relaxed);
        debug_log("Debug mode enabled");
        debug_log(&format!("Using cert file: {}", CERT_PATH));
    }

    if args.tui {
        println!("Starting TUI Chat Client...");
        println!("Cert file: {}", CERT_PATH);
        if args.allow_self_signed {
            println!("⚠️  Self-signed certificates allowed");
        }
        println!("Connecting to {}:{}...", args.host, args.port);
        
        let mut tui_client = TuiChatClient::new().map_err(|e| {
            format!("Failed to initialize TUI client: {}.", e)
        })?;
        
        match tui_client.connect(&args.host, args.port, args.allow_self_signed) {
            Ok(()) => {
                tui_client.run_tui()?;
            }
            Err(e) => {
                eprintln!("Connection failed: {}", e);
                if !args.allow_self_signed {
                    eprintln!("💡 Tip: Use --allow-self-signed if the server uses a self-signed certificate");
                }
                std::process::exit(1);
            }
        }
    } else {
        println!("=== Debug Chat Client ===");
        println!("Cert file: {}", CERT_PATH);
        if args.allow_self_signed {
            println!("⚠️  Self-signed certificates allowed");
        }
        println!("Connecting to {}:{}...", args.host, args.port);

        let mut client = DebugChatClient::new().map_err(|e| {
            format!("Failed to initialize debug client: {}.", e)
        })?;
        
        match client.connect(&args.host, args.port, args.allow_self_signed) {
            Ok(()) => {
                println!("Connected!");
                client.run_terminal()?;
            }
            Err(e) => {
                eprintln!("Connection failed: {}", e);
                if !args.allow_self_signed {
                    eprintln!("💡 Tip: Use --allow-self-signed if the server uses a self-signed certificate");
                }
                std::process::exit(1);
            }
        }
    }

    println!("Goodbye!");
    Ok(())
}