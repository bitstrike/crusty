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
use pbkdf2::pbkdf2_hmac;
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

// Unified key manager with proper derivation
#[derive(Clone)]
struct UnifiedKeyManager {
    signing_key: Vec<u8>,
    server_verification_key: Vec<u8>,
    message_counter: Arc<Mutex<u64>>,
}

impl UnifiedKeyManager {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        // Generate secure signing key with PBKDF2 strengthening
        let mut base_key = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut base_key);
        
        // Use PBKDF2 for key strengthening
        let salt = b"chat_client_signing_salt_2024";
        let mut signing_key = vec![0u8; CLIENT_SIGNING_KEY_SIZE];
        pbkdf2_hmac::<Sha256>(&base_key, salt, 100_000, &mut signing_key);
        
        // Derive server verification key from KEY_PATH constant
        let key_data = fs::read_to_string(KEY_PATH)
            .map_err(|e| format!("Failed to read key file '{}': {}", KEY_PATH, e))?;
        
        let server_salt = b"chat_server_verify_salt_2024";
        let mut server_verification_key = vec![0u8; 32];
        pbkdf2_hmac::<Sha256>(key_data.as_bytes(), server_salt, 100_000, &mut server_verification_key);
        
        debug_log(&format!("Keys derived from {}", KEY_PATH));
        
        Ok(Self {
            signing_key,
            server_verification_key,
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
    
    fn verify_server_message(&self, signed_message: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
        let signature_base64 = extract_signature(signed_message)
            .ok_or("Could not extract signature")?;
        
        let message_content = extract_signed_content(signed_message)
            .ok_or("Could not extract message content")?;
        
        let signature_bytes = general_purpose::STANDARD.decode(signature_base64)?;
        
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.server_verification_key)
            .map_err(|_| "Invalid server verification key length")?;
        mac.update(message_content.as_bytes());
        
        match mac.verify_slice(&signature_bytes) {
            Ok(()) => {
                debug_log(&format!("✅ Server message verified: {}", message_content));
                Ok(Some(message_content))
            }
            Err(_) => {
                debug_log(&format!("❌ Server message verification failed: {}", message_content));
                Err("Invalid server message signature".into())
            }
        }
    }
}

// Unified stream handler for both client types
struct UnifiedStreamHandler;

impl UnifiedStreamHandler {
    fn handle_stream(
        mut stream: TlsStream,
        rx_write: Receiver<String>,
        tx_output: Sender<String>,
        client_type: &str,
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
                if let Err(e) = Self::read_messages(&mut stream, &mut read_buffer, &tx_output, client_type) {
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
        client_type: &str,
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

// Common trait for both chat clients
trait ChatClient {
    fn sign_and_send_message(&self, message: &str, tx: &Sender<String>) -> Result<(), Box<dyn std::error::Error>>;
}

// Updated DebugChatClient using unified components
struct DebugChatClient {
    nickname: String,
    running: bool,
    tx_write: Option<Sender<String>>,
    rx_output: Option<Receiver<String>>,
    key_manager: UnifiedKeyManager,
    key_registered: bool,
}

impl ChatClient for DebugChatClient {
    fn sign_and_send_message(&self, message: &str, tx: &Sender<String>) -> Result<(), Box<dyn std::error::Error>> {
        let signed_message = self.key_manager.sign_message(message)?;
        tx.send(signed_message)?;
        Ok(())
    }
}

impl DebugChatClient {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            nickname: "User".to_string(),
            running: false,
            tx_write: None,
            rx_output: None,
            key_manager: UnifiedKeyManager::new()?,
            key_registered: false,
        })
    }

    fn connect(&mut self, host: &str, port: u16, allow_self_signed: bool) -> Result<(), Box<dyn std::error::Error>> {
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

        // Register signing key
        debug_log("🔑 Registering client signing key...");
        let key_base64 = self.key_manager.get_signing_key_b64();
        if let Some(ref tx) = self.tx_write {
            let _ = tx.send(format!("{} {}", COMMAND_REGISTER_KEY, key_base64));
        }
        
        thread::sleep(Duration::from_millis(KEY_REGISTRATION_WAIT_MS));

        // Use unified stream handler
        UnifiedStreamHandler::handle_stream(tls_stream, rx_write, tx_output, "DEBUG");

        Ok(())
    }

    fn run_terminal(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let rx_output = self.rx_output.take().unwrap();
        
        println!("=== Debug Chat Client ===");
        println!("Key file: {}", KEY_PATH);
        println!("Cert file: {}", CERT_PATH);
        println!("Commands: /nick <name>, /who, /quit");
        println!("===========================");

        // Input handling thread
        let tx_write = self.tx_write.clone();
        let key_manager = self.key_manager.clone();
        let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let running_clone = running.clone();
        
        thread::spawn(move || {
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
                                
                                if tx.send(message_to_send).is_err() || msg == "/quit" {
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
                } else if msg.contains("Client signing key registered successfully") {
                    self.key_registered = true;
                    println!("🔑 {}", msg);
                } else {
                    println!("<< {}", msg);
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
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
    Frame, Terminal,
};
use std::collections::VecDeque;

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
    scroll_offset: usize,
    auto_scroll: bool,
    cursor_position: usize,
    key_manager: UnifiedKeyManager,
    key_registered: bool,
}

impl ChatClient for TuiChatClient {
    fn sign_and_send_message(&self, message: &str, tx: &Sender<String>) -> Result<(), Box<dyn std::error::Error>> {
        let signed_message = self.key_manager.sign_message(message)?;
        tx.send(signed_message)?;
        Ok(())
    }
}

impl TuiChatClient {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let mut rng = rand::thread_rng();
        let heartbeat_interval = Duration::from_millis(
            HEARTBEAT_INTERVAL_MIN_MS + rng.gen_range(0..(HEARTBEAT_INTERVAL_MAX_MS - HEARTBEAT_INTERVAL_MIN_MS))
        );
        
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
            key_manager: UnifiedKeyManager::new()?,
            key_registered: false,
        })
    }

    fn connect(&mut self, host: &str, port: u16, allow_self_signed: bool) -> Result<(), Box<dyn std::error::Error>> {
        self.status = format!("Connecting to {}:{}...", host, port);
        debug_log(&format!("TUI client connecting to {}:{}", host, port));
        
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

        self.status = "Connected! Setting up chat...".to_string();
        thread::sleep(Duration::from_millis(100));
        
        self.running = true;

        let (tx_write, rx_write) = channel();
        let (tx_output, rx_output) = channel();
        
        self.tx_write = Some(tx_write);
        self.rx_output = Some(rx_output);

        // Use unified stream handler
        UnifiedStreamHandler::handle_stream(tls_stream, rx_write, tx_output, "TUI");
        Ok(())
    }

    fn run_tui(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        // Register signing key
        self.status = "Registering signing key...".to_string();
        let key_base64 = self.key_manager.get_signing_key_b64();
        self.send_message(format!("{} {}", COMMAND_REGISTER_KEY, key_base64))?;
        
        thread::sleep(Duration::from_millis(KEY_REGISTRATION_WAIT_MS));
        
        self.status = "Getting user list...".to_string();
        thread::sleep(Duration::from_millis(CONNECTION_STABILIZATION_MS));
        self.send_message(COMMAND_WHO.to_string())?;

        let rx_output = self.rx_output.take().unwrap();
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
                            KeyCode::Enter => {
                                if !self.input.is_empty() {
                                    let message = self.input.clone();
                                    self.input.clear();
                                    self.cursor_position = 0;
                                    
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
                            _ => {}
                        }
                    }
                }
            }

            // Process incoming messages
            while let Ok(msg) = rx_output.try_recv() {
                if msg == "DISCONNECT" {
                    self.status = "Connection lost!".to_string();
                    break;
                } else {
                    self.process_message(msg);
                }
            }

            // Heartbeat
            if self.last_heartbeat.elapsed() >= self.heartbeat_interval {
                if let Err(e) = self.send_message("/status".to_string()) {
                    debug_log(&format!("Heartbeat failed: {}", e));
                }
                self.last_heartbeat = std::time::Instant::now();
                
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
        // Handle key registration success
        if msg.contains(RESPONSE_KEY_REGISTERED) {
            self.key_registered = true;
            self.status = "✅ Signing key registered with server".to_string();
        }
        
        self.messages.push_back(msg);
        if self.messages.len() > MAX_CHAT_HISTORY_LINES {
            self.messages.pop_front();
        }
        
        if self.auto_scroll {
            self.scroll_offset = 0;
        }
    }

    fn ui(&self, f: &mut Frame) {
        let main_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(1), Constraint::Length(3), Constraint::Length(1)].as_ref())
            .split(f.size());

        // Messages
        let messages: Vec<ListItem> = self.messages
            .iter()
            .map(|m| ListItem::new(Line::from(Span::raw(m))))
            .collect();

        let messages_block = Block::default()
            .borders(Borders::ALL)
            .title(format!(" Chat - {} ", self.nickname));

        let messages_list = List::new(messages).block(messages_block);
        f.render_widget(messages_list, main_chunks[0]);

        // Input
        let mut input_with_cursor = self.input.clone();
        if self.cursor_position <= input_with_cursor.len() {
            input_with_cursor.insert(self.cursor_position, '│');
        }

        let input_block = Block::default()
            .borders(Borders::ALL)
            .title(" Type message ");

        let input_paragraph = Paragraph::new(input_with_cursor)
            .block(input_block)
            .wrap(Wrap { trim: true });

        f.render_widget(input_paragraph, main_chunks[1]);

        // Status
        let status_bar = Paragraph::new(format!(" {} | Key: {} | Files: {} {}", 
            self.status,
            if self.key_registered { "✅" } else { "❌" },
            KEY_PATH,
            CERT_PATH
        ))
        .style(Style::default().fg(Color::Cyan));

        f.render_widget(status_bar, main_chunks[2]);
    }

    fn send_message(&mut self, message: String) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(ref tx) = self.tx_write {
            self.sign_and_send_message(&message, tx)?;
        }
        Ok(())
    }
}

// Updated argument parsing with self-signed certificate option
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
                "--allow-self-signed" => {
                    allow_self_signed = true;
                    eprintln!("⚠️  WARNING: Accepting self-signed certificates");
                }
                "--help" => {
                    println!("Usage: {} [OPTIONS]", args[0]);
                    println!("Options:");
                    println!("  --host HOST              Server hostname (default: localhost)");
                    println!("  --port PORT              Server port (default: 8443)");
                    println!("  --debug                  Enable debug output");
                    println!("  --tui                    Use terminal UI mode");
                    println!("  --allow-self-signed      Accept self-signed certificates");
                    println!("  --help                   Show this help");
                    println!("\nKey file: {}", KEY_PATH);
                    println!("Cert file: {}", CERT_PATH);
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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UserStatus {
    pub id: usize,
    pub nickname: String,
    pub state: String,
    pub last_seen: u64,
    pub nickname_changed: bool,
    pub old_nickname: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct StatusResponse {
    pub timestamp: u64,
    pub users: Vec<UserStatus>,
    pub total_users: usize,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    
    if args.debug {
        DEBUG.store(true, std::sync::atomic::Ordering::Relaxed);
        debug_log("Debug mode enabled");
        debug_log(&format!("Using key file: {}", KEY_PATH));
        debug_log(&format!("Using cert file: {}", CERT_PATH));
    }

    if args.tui {
        println!("Starting TUI Chat Client...");
        println!("Key file: {}", KEY_PATH);
        println!("Cert file: {}", CERT_PATH);
        if args.allow_self_signed {
            println!("⚠️  Self-signed certificates allowed");
        }
        println!("Connecting to {}:{}...", args.host, args.port);
        
        let mut tui_client = TuiChatClient::new().map_err(|e| {
            format!("Failed to initialize TUI client: {}. Check that '{}' exists.", e, KEY_PATH)
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
        println!("Key file: {}", KEY_PATH);
        println!("Cert file: {}", CERT_PATH);
        if args.allow_self_signed {
            println!("⚠️  Self-signed certificates allowed");
        }
        println!("Connecting to {}:{}...", args.host, args.port);

        let mut client = DebugChatClient::new().map_err(|e| {
            format!("Failed to initialize debug client: {}. Check that '{}' exists.", e, KEY_PATH)
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