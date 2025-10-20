//! Password Hash Generator
//!
//! A cross-platform password hash generation tool supporting multiple hash algorithms and custom formatting.
//! Supports Windows, Linux, macOS on x86_64 and AArch64 architectures.
//!
//! # Features
//! - Multi-platform support (Windows, Linux, macOS)
//! - Multiple hash algorithms (MD5, SHA1, SHA256, SHA512)
//! - Flexible configuration system (CLI args, environment variables, config files)
//! - Custom hash output formatting (truncation, end characters, case conversion)
//! - Result saving and file operations

use std::collections::HashMap;
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::Path;
use clap::{Arg, Command, Parser};
use regex::Regex;
use sha1::Sha1;
use sha2::{Sha256, Sha512, Digest};
use anyhow::Result;
use log::{info, error, warn, debug};
use serde::Deserialize;
use chrono::{Utc, DateTime};

/// Platform information
#[derive(Debug)]
struct PlatformInfo {
    os: String,
    arch: String,
    family: String,
}

impl PlatformInfo {
    fn new() -> Self {
        Self {
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            family: std::env::consts::FAMILY.to_string(),
        }
    }
    
    fn display(&self) -> String {
        format!("{}-{}", self.os, self.arch)
    }
}

/// Command line arguments
#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Cross-platform Password Hash Generator",
    long_about = r#"Password Hash Generator

A cross-platform password hash generation tool supporting multiple hash algorithms
and custom formatting. Supports Windows, Linux, macOS on x86_64 and AArch64 architectures.

Features:
• Multi-platform support (Windows, Linux, macOS)
• Multiple hash algorithms (MD5, SHA1, SHA256, SHA512)  
• Flexible configuration system (CLI args, environment variables, config files)
• Custom hash output formatting (truncation, end characters, case conversion)
• Result saving and file operations

Examples:
  # Basic usage
  pass-craft --text "name:john,site:example.com" --hash "method:sha256,cut:10"

  # Read configuration from file
  pass-craft --file config.txt --save passwords.txt

  # Show platform information  
  pass-craft --show-platform

  # Show configuration
  pass-craft --show-config --text "name:test,site:example.com"
"#,
    after_help = "See https://github.com/ymc-github/pass-craft for more information."
)]
struct CliArgs {
    /// Command
    #[arg(default_value = "add")]
    cmd: String,

    /// Text parameter
    #[arg(long)]
    text: Option<String>,

    /// Hash parameters
    #[arg(long)]
    hash: Option<String>,

    /// String key-value configuration
    #[arg(long)]
    slkv: Option<String>,

    /// Secure string format configuration
    #[arg(long)]
    sslf: Option<String>,

    /// Save file path
    #[arg(long)]
    save: Option<String>,

    /// Input file path
    #[arg(long)]
    file: Option<String>,

    /// Show configuration and exit
    #[arg(long, default_value = "false")]
    show_config: bool,

    /// Show platform information and exit
    #[arg(long, default_value = "false")]
    show_platform: bool,

    /// Operation mode [default: interactive]
    #[arg(long, default_value = "interactive")]
    mode: String,

    /// Run once and exit
    #[arg(long, default_value = "false")]
    once: bool,
}

/// Application configuration
#[derive(Debug, Deserialize, Clone)]
struct AppConfig {
    // Hash algorithm configuration
    method: String,
    cut_length: usize,
    end_char: String,
    upper_start: usize,
    
    // User information
    name: String,
    email: String,
    site: String,
    
    // File configuration
    input_file: Option<String>,
    output_file: Option<String>,
    
    // Platform specific configuration
    #[serde(default)]
    platform_identifier: String,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            method: "SHA512".to_string(),
            cut_length: 8,
            end_char: "!".to_string(),
            upper_start: 3,
            name: "".to_string(),
            email: "".to_string(),
            site: "".to_string(),
            input_file: None,
            output_file: None,
            platform_identifier: "".to_string(),
        }
    }
}

impl AppConfig {
    fn new() -> Result<Self> {
        let cli_args = CliArgs::parse();
        
        // Set default configuration
        let mut config = AppConfig::default();
        
        // Get configuration from various parameters
        if let Some(text) = &cli_args.text {
            Self::apply_text_config(&mut config, text);
        }
        
        if let Some(hash) = &cli_args.hash {
            Self::apply_hash_config(&mut config, hash);
        }
        
        if let Some(slkv) = &cli_args.slkv {
            Self::apply_slkv_config(&mut config, slkv);
        }
        
        if let Some(sslf) = &cli_args.sslf {
            Self::apply_sslf_config(&mut config, sslf);
        }
        
        // Get configuration from file
        if let Some(file_path) = &cli_args.file {
            if let Ok(file_config) = Self::load_from_file(file_path) {
                config = file_config;
            }
        }
        
        config.input_file = cli_args.file.clone();
        config.output_file = cli_args.save.clone();
        
        Ok(config)
    }
    
    fn apply_text_config(config: &mut AppConfig, text: &str) {
        // Parse text configuration format: name:value,email:value,site:value
        let pairs: Vec<&str> = text.split(',').collect();
        for pair in pairs {
            if let Some((key, value)) = pair.split_once(':') {
                match key.trim() {
                    "name" => config.name = value.trim().to_string(),
                    "email" => config.email = value.trim().to_string(),
                    "site" => config.site = value.trim().to_string(),
                    _ => {}
                }
            }
        }
    }
    
    fn apply_hash_config(config: &mut AppConfig, hash: &str) {
        // Parse hash configuration format: method:value,cut:value,end:value,upper-start:value
        let pairs: Vec<&str> = hash.split(',').collect();
        for pair in pairs {
            if let Some((key, value)) = pair.split_once(':') {
                match key.trim() {
                    "method" => config.method = value.trim().to_string(),
                    "cut" => config.cut_length = value.trim().parse().unwrap_or(8),
                    "end" => config.end_char = value.trim().to_string(),
                    "upper-start" => config.upper_start = value.trim().parse().unwrap_or(3),
                    _ => {}
                }
            }
        }
    }
    
    fn apply_slkv_config(config: &mut AppConfig, slkv: &str) {
        Self::apply_text_config(config, slkv);
        Self::apply_hash_config(config, slkv);
    }
    
    fn apply_sslf_config(config: &mut AppConfig, sslf: &str) {
        let head = sslf_get_head(sslf);
        let tail = sslf_get_tail(sslf);
        
        Self::apply_text_config(config, &head);
        Self::apply_hash_config(config, &tail);
    }
    
    fn load_from_file(file_path: &str) -> Result<Self> {
        // let content = fs::read_to_string(file_path)?;
        // let lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();
        
        // 过滤空行和只包含空白字符的行
        // let lines: Vec<String> = content
        //     .lines()
        //     .map(|s| s.trim())  // 去除前后空白
        //     .filter(|line| !line.is_empty())  // 过滤空行
        //     .map(|s| s.to_string())
        //     .collect();

        // 使用现有的sslf_load_file函数，它会清理注释和空行
        let lines = sslf_load_file(file_path, "");

        if let Some(last_line) = lines.last() {
            let mut config = AppConfig::default();
            Self::apply_sslf_config(&mut config, last_line);
            Ok(config)
        } else {
            debug!("配置文件 '{}' 为空或没有有效内容，使用默认配置", file_path);
            Ok(AppConfig::default())
        }
    }
    
    /// Display configuration information (for --show-config)
    fn display_config(&self) {
        info_step("Password Hash Generator Configuration", 60, '=');
        
        // User information configuration
        println!("👤 User Information:");
        println!("  Name: {}", self.name);
        println!("  Email: {}", self.email);
        println!("  Site: {}", self.site);
        
        // Hash algorithm configuration
        println!("🔑 Hash Algorithm Configuration:");
        println!("  Method: {}", self.method);
        println!("  Cut Length: {}", self.cut_length);
        println!("  End Character: {}", self.end_char);
        println!("  Upper Start: {}", self.upper_start);
        
        // File configuration
        println!("📁 File Configuration:");
        println!("  Input File: {}", self.input_file.as_deref().unwrap_or("Not set"));
        println!("  Output File: {}", self.output_file.as_deref().unwrap_or("Not set"));
        
        // Platform configuration
        println!("🔧 Platform Configuration:");
        println!("  Platform Identifier: {}", self.platform_identifier);
        
        // Configuration validation status
        println!("✅ Configuration Validation:");
        match self.validate() {
            Ok(()) => info_status("Status: Valid", 0),
            Err(e) => info_status(&format!("Status: Invalid - {}", e), 1),
        }
    }
    
    /// Validate configuration
    fn validate(&self) -> Result<()> {
        let valid_methods = ["MD5", "SHA1", "SHA256", "SHA512"];
        if !valid_methods.contains(&self.method.to_uppercase().as_str()) {
            return Err(anyhow::anyhow!("Unsupported hash algorithm: {}", self.method));
        }
        
        if self.cut_length == 0 || self.cut_length > 64 {
            return Err(anyhow::anyhow!("Cut length must be between 1-64"));
        }
        
        if self.upper_start > self.cut_length {
            return Err(anyhow::anyhow!("Upper start position cannot exceed cut length"));
        }
        
        Ok(())
    }
}

// Calculate string hash value
fn get_string_hash(string: &str, hash_name: &str) -> String {
    let hash_name = hash_name.to_uppercase();
    
    match hash_name.as_str() {
        "MD5" => {
            let digest = md5::compute(string.as_bytes());
            format!("{:x}", digest)
        }
        "SHA1" => {
            let mut hasher = Sha1::new();
            hasher.update(string.as_bytes());
            format!("{:x}", hasher.finalize())
        }
        "SHA256" => {
            let mut hasher = Sha256::new();
            hasher.update(string.as_bytes());
            format!("{:x}", hasher.finalize())
        }
        "SHA512" => {
            let mut hasher = Sha512::new();
            hasher.update(string.as_bytes());
            format!("{:x}", hasher.finalize())
        }
        _ => panic!("Unsupported hash algorithm: {}", hash_name),
    }
}

// Check if any element in value is in check_list
fn oneof(value: &str, check_list: &[&str]) -> bool {
    if value.is_empty() {
        return false;
    }
    
    let items: Vec<&str> = value.split(',').map(|item| item.trim()).collect();
    
    for item in items {
        if check_list.contains(&item) {
            return true;
        }
    }
    false
}

// Check if all elements in value are in check_list
fn everyof(value: &str, check_list: &[&str]) -> bool {
    if value.is_empty() {
        return false;
    }
    
    let items: Vec<&str> = value.split(',').map(|item| item.trim()).collect();
    
    for item in items {
        if !check_list.contains(&item) {
            return false;
        }
    }
    true
}

// Check if string is empty or contains only whitespace
fn string_is_empty(value: &str) -> bool {
    value.trim().is_empty()
}

// Return default value if string is empty
fn string_get(value: &str, default_value: &str) -> String {
    if string_is_empty(value) {
        default_value.to_string()
    } else {
        value.to_string()
    }
}

// Remove empty lines from multi-line text
fn mlt_del_emptyline(lines: &[String]) -> Vec<String> {
    lines.iter()
        .filter(|line| !line.trim().is_empty())
        .cloned()
        .collect()
}

// Load multi-line text from file, return default text if file doesn't exist
fn mlt_load_file(loc: &str, default_text: &str) -> Vec<String> {
    if Path::new(loc).exists() {
        if let Ok(file) = fs::File::open(loc) {
            let reader = io::BufReader::new(file);
            reader.lines().filter_map(Result::ok).collect()
        } else {
            vec![]
        }
    } else {
        if default_text.is_empty() {
            vec![]
        } else {
            default_text.lines().map(|s| s.to_string()).collect()
        }
    }
}

// Get last line of multi-line text
fn mlt_get_lastline(lines: &[String]) -> String {
    lines.last().cloned().unwrap_or_default()
}

// Get value for specified key from key-value string
fn slkv_get(value: &str, slkv: &str, case_sensitive: bool) -> String {
    if slkv.is_empty() {
        return String::new();
    }
    
    let pairs: Vec<&str> = slkv.split(',').map(|pair| pair.trim()).collect();
    let search_key = if case_sensitive {
        value.trim().to_string()
    } else {
        value.trim().to_uppercase()
    };
    
    for pair in pairs {
        if pair.contains(':') {
            let parts: Vec<&str> = pair.splitn(2, ':').collect();
            let key = parts[0].trim();
            let val = parts[1].trim();
            
            let compare_key = if case_sensitive {
                key.to_string()
            } else {
                key.to_uppercase()
            };
            
            if compare_key == search_key {
                return val.to_string();
            }
        }
    }
    
    String::new()
}

// Get part before semicolon
fn sslf_get_head(data: &str) -> String {
    data.split(';').next().unwrap_or(data).to_string()
}

// Get part after semicolon
fn sslf_get_tail(data: &str) -> String {
    data.split(';').nth(1).unwrap_or("").to_string()
}

// Load file and clean comments and empty lines
fn sslf_load_file(loc: &str, default_text: &str) -> Vec<String> {
    let lines = mlt_load_file(loc, default_text);
    
    // Compile regex patterns
    let comment_re = Regex::new(r"^#.*").unwrap();
    let html_comment_re = Regex::new(r"<!--.*-->").unwrap();
    
    lines.iter()
        .filter_map(|line| {
            // Remove comment lines and HTML comments
            let clean_line = comment_re.replace(line, "");
            let clean_line = html_comment_re.replace(&clean_line, "");
            
            if clean_line.trim().is_empty() {
                None
            } else {
                Some(clean_line.to_string())
            }
        })
        .collect()
}

// Remove name:, email:, site: prefixes from data
fn shtkv_get_pure_v(data: &str) -> String {
    if data.is_empty() {
        return String::new();
    }
    
    // Compile regex patterns
    let prefix_re = Regex::new(r"(name:|email:|site:)").unwrap();
    let trailing_comma_re = Regex::new(r",$").unwrap();
    
    let cleaned = prefix_re.replace_all(data, "");
    let cleaned = trailing_comma_re.replace(&cleaned, "");
    cleaned.trim().to_string()
}

// Get filename from path
fn path_get_name(path: &str) -> String {
    Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("")
        .to_string()
}

// Get directory part from path
fn path_get_dirs(path: &str) -> String {
    Path::new(path)
        .parent()
        .and_then(|parent| parent.to_str())
        .unwrap_or("")
        .to_string()
}

// Normalize path separators
fn path_normalize(path: &str, search: &str, replace: &str) -> String {
    path.replace(search, replace)
}

// Check if path exists
fn os_path_exist(loc: &str) -> bool {
    Path::new(loc).exists()
}

// Create directory
fn os_path_make(loc: &str) -> Result<(), std::io::Error> {
    if !loc.is_empty() && !os_path_exist(loc) {
        fs::create_dir_all(loc)
    } else {
        Ok(())
    }
}

// Add password to file
fn add_password_to_file(loc: &str, password: &str) -> Result<(), std::io::Error> {
    if os_path_exist(loc) {
        let content = fs::read_to_string(loc)?;
        let mut lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();
        lines.push(password.to_string());
        
        fs::write(loc, lines.join("\n"))?;
    } else {
        fs::write(loc, password)?;
    }
    
    Ok(())
}

// Wrap text with HTML comments
fn html_comment_wrap(text: &str) -> String {
    format!("<!-- {} -->", text)
}

// Remove HTML comment wrapping
fn html_comment_unwrap(text: &str) -> String {
    text.trim()
        .trim_start_matches("<!--")
        .trim_end_matches("-->")
        .trim()
        .to_string()
}

/// Get current time in formatted string
fn get_time_now() -> String {
    Utc::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

/// Display a step header with centered text
fn info_step(msg: &str, length: usize, fillchar: char) {
    let msg_len = msg.chars().count();
    if msg_len >= length {
        println!("{}", msg);
        return;
    }
    
    let padding_len = (length - msg_len) / 2;
    let padding = fillchar.to_string().repeat(padding_len);
    
    // Use format! for precise length control
    let formatted = format!("{}{}{}", padding, msg, padding);
    // Truncate to exact length (there might be 1 character difference for odd lengths)
    println!("{}", &formatted[..length.min(formatted.len())]);
}

/// Display status message with appropriate icon
fn info_status(msg_body: &str, status: u8) {
    let icon = match status {
        0 => "✅", // Success
        1 => "❌", // Error
        2 => "⚠️",  // Warning
        _ => "ℹ️", // Info
    };
    println!("{} {}", icon, msg_body);
}

/// Generate password hash
fn generate_password_hash(config: &AppConfig) -> Result<String> {
    info_step("Generating Password Hash", 50, '-');
    
    // Generate base text
    let base_text = format!("{},{},{}", config.name, config.email, config.site);
    info_status(&format!("{} - Base text: {}", get_time_now(), base_text), 3);
    
    // Calculate hash value
    let hash_value = get_string_hash(&base_text, &config.method);
    info_status(&format!("{} - Raw {} hash: {}", get_time_now(), config.method, hash_value), 3);
    
    // Handle hash truncation
    let mut hash_cut = hash_value[..hash_value.len().min(config.cut_length)].to_string();
    info_status(&format!("{} - Truncated to {} chars: {}", get_time_now(), config.cut_length, hash_cut), 3);
    
    // Handle end character
    if !config.end_char.is_empty() {
        if let Some(end_char) = config.end_char.chars().next() {
            if !hash_cut.is_empty() {
                hash_cut.pop();
                hash_cut.push(end_char);
                info_status(&format!("{} - Added end character '{}'", get_time_now(), end_char), 3);
            }
        }
    }
    
    // Handle case conversion
    if config.upper_start <= hash_cut.len() {
        let upper_part = hash_cut[..config.upper_start].to_uppercase();
        let lower_part = &hash_cut[config.upper_start..];
        hash_cut = format!("{}{}", upper_part, lower_part);
        info_status(&format!("{} - First {} characters uppercased", get_time_now(), config.upper_start), 3);
    }
    
    // Generate final result
    let result = format!("{},{},{}", config.name, hash_cut, config.site);
    info_status(&format!("{} - Final result: {}", get_time_now(), result), 0);
    
    Ok(result)
}

/// Display help information
// fn print_help() {
//     println!("Password Hash Generator v{}", env!("CARGO_PKG_VERSION"));
//     println!();
//     println!("A cross-platform password hash generation tool");
//     println!();
//     println!("USAGE:");
//     println!("    pass-craft [COMMAND] [OPTIONS]");
//     println!();
//     println!("COMMANDS:");
//     println!("    add             Add new password (default command)");
//     println!("    generate        Generate password hash");
//     println!();
//     println!("OPTIONS:");
//     println!("    --text <TEXT>           Text parameter (name:value,email:value,site:value)");
//     println!("    --hash <HASH>           Hash parameters (method:value,cut:value,end:value,upper-start:value)");
//     println!("    --slkv <SLKV>           String key-value configuration");
//     println!("    --sslf <SSLF>           Secure string format configuration");
//     println!("    --file <FILE>           Input file path");
//     println!("    --save <FILE>           Save file path");
//     println!("    --show-config           Show configuration information and exit");
//     println!("    --show-platform         Show platform information and exit");
//     println!("    --once                  Run once and exit");
//     println!("    --mode <MODE>           Operation mode [default: interactive]");
//     println!("    --help, -h              Show help information");
//     println!("    --version, -v           Show version information");
//     println!();
//     println!("EXAMPLES:");
//     println!("    # Basic usage");
//     println!("    pass-craft --text \"name:john,site:example.com\" --hash \"method:sha256,cut:10\"");
//     println!();
//     println!("    # Read configuration from file");
//     println!("    pass-craft --file config.txt --save passwords.txt");
//     println!();
//     println!("    # Show platform information");
//     println!("    pass-craft --show-platform");
//     println!();
//     println!("    # Show configuration");
//     println!("    pass-craft --show-config --text \"name:test,site:example.com\"");
// }

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    
    let platform = PlatformInfo::new();
    
    // First parse command line arguments
    let cli_args = CliArgs::parse();
    
    // Check help and version parameters
    // let args: Vec<String> = std::env::args().collect();
    // if args.iter().any(|arg| arg == "--help" || arg == "-h") {
    //     print_help();
    //     return Ok(());
    // }
    
    // if args.iter().any(|arg| arg == "--version" || arg == "-v") {
    //     println!("pass-craft v{}", env!("CARGO_PKG_VERSION"));
    //     return Ok(());
    // }
    
    // Show platform information
    if cli_args.show_platform {
        info_step("Platform Information", 50, '=');
        println!("Operating System: {}", platform.os);
        println!("Architecture: {}", platform.arch);
        println!("Family: {}", platform.family);
        println!("Display Format: {}", platform.display());
        return Ok(());
    }
    
    info!("🚀 Starting Password Hash Generator on {}", platform.display());
    
    // Load configuration
    let config = match AppConfig::new() {
        Ok(config) => config,
        Err(e) => {
            info_step("Configuration Error", 50, '!');
            info_status(&format!("{} - Configuration loading failed: {}", get_time_now(), e), 1);
            info_status("Configuration sources:", 3);
            info_status("  - Command line arguments", 3);
            info_status("  - Configuration files (via --file)", 3);
            info_status("Supported parameters:", 3);
            info_status("  --text: User information (name, email, site)", 3);
            info_status("  --hash: Hash parameters (method, cut, end, upper-start)", 3);
            info_status("  --file: Configuration file path", 3);
            std::process::exit(1);
        }
    };
    
    // Show configuration information
    if cli_args.show_config {
        config.display_config();
        return Ok(());
    }
    
    // Validate configuration
    if let Err(e) = config.validate() {
        info_step("Configuration Validation", 50, '!');
        info_status(&format!("{} - Configuration validation failed: {}", get_time_now(), e), 1);
        std::process::exit(1);
    }
    
    // Show current configuration summary
    info_step("Current Configuration", 50, '=');
    info_status(&format!("Platform: {}", platform.display()), 0);
    info_status(&format!("Algorithm: {}", config.method), 0);
    info_status(&format!("User: {}", config.name), 0);
    info_status(&format!("Site: {}", config.site), 0);
    info_status(&format!("Format: {} chars, end with '{}', first {} uppercase", 
             config.cut_length, config.end_char, config.upper_start), 0);
    
    // Generate password hash
    match generate_password_hash(&config) {
        Ok(result) => {
            info_step("Password Generation Complete", 50, '=');
            info_status(&format!("{} - Generated Password: {}", get_time_now(), result), 0);
            
            // Save result
            if let Some(save_path) = &config.output_file {
                info_step("Saving Result", 50, '-');
                
                let file_path = &config.input_file;
                
                let password_text = if file_path.as_deref() == Some(save_path) {
                    html_comment_wrap(&result)
                } else {
                    let result_wrapped = html_comment_wrap(&result);
                    format!("{}\n{}", 
                           config.input_file.as_ref()
                               .and_then(|path| fs::read_to_string(path).ok())
                               .unwrap_or_default(),
                           result_wrapped)
                };

                match add_password_to_file(save_path, &password_text) {
                    Ok(()) => {
                        info_status(&format!("{} - Successfully saved to: {}", get_time_now(), save_path), 0);
                    }
                    Err(e) => {
                        info_status(&format!("{} - Save failed: {}", get_time_now(), e), 1);
                    }
                }
            }
            
            // If running in once mode, exit after completion
            if cli_args.once {
                info_step("Completed (One-time Mode)", 50, '=');
                return Ok(());
            }
        }
        Err(e) => {
            info_step("Password Generation Failed", 50, '!');
            info_status(&format!("{} - Password generation failed: {}", get_time_now(), e), 1);
            std::process::exit(1);
        }
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_info() {
        let platform = PlatformInfo::new();
        
        // Verify platform information is not empty
        assert!(!platform.os.is_empty());
        assert!(!platform.arch.is_empty());
        assert!(!platform.family.is_empty());
        
        // Verify display format
        let display = platform.display();
        assert!(display.contains(&platform.os));
        assert!(display.contains(&platform.arch));
    }

    #[test]
    fn test_info_step_alignment() {
        // Test various message lengths
        info_step("Configuration", 50, '=');
        info_step("Generating Password Hash", 50, '-');
        info_step("Test", 20, '*');
        info_step("A", 10, '-');
        
        // Test long messages (should display directly)
        info_step("This is a very long message that exceeds the specified length", 30, '+');
    }

    #[test]
    fn test_info_status() {
        // Test all status types
        info_status("Success message", 0);
        info_status("Error message", 1);
        info_status("Warning message", 2);
        info_status("Info message", 3);
        info_status("Default info message", 99);
    }

    #[test]
    fn test_get_time_now() {
        let time1 = get_time_now();
        let time2 = get_time_now();
        
        // Verify time format
        assert_eq!(time1.len(), 19); // "YYYY-MM-DD HH:MM:SS"
        assert!(time1.contains('-')); // Contains date separator
        assert!(time1.contains(':')); // Contains time separator
        
        // Two calls should get different times (or at least same format)
        assert_eq!(time1.len(), time2.len());
    }

    #[test]
    fn test_config_validation() {
        let valid_config = AppConfig {
            method: "SHA256".to_string(),
            cut_length: 8,
            end_char: "!".to_string(),
            upper_start: 3,
            name: "test".to_string(),
            email: "test@example.com".to_string(),
            site: "example.com".to_string(),
            input_file: None,
            output_file: None,
            platform_identifier: "test".to_string(),
        };
        
        assert!(valid_config.validate().is_ok());
        
        // Test invalid configurations
        let invalid_configs = vec![
            AppConfig { method: "INVALID".to_string(), ..valid_config.clone() }, // Invalid algorithm
            AppConfig { cut_length: 0, ..valid_config.clone() }, // Cut length too small
            AppConfig { cut_length: 65, ..valid_config.clone() }, // Cut length too large
            AppConfig { upper_start: 10, ..valid_config.clone() }, // Upper start exceeds cut length
        ];
        
        for (i, config) in invalid_configs.iter().enumerate() {
            assert!(config.validate().is_err(), "Test case {} should fail", i);
        }
    }

    #[test]
    fn test_generate_password_hash() {
        let config = AppConfig {
            method: "MD5".to_string(), // Use MD5 for easier testing
            cut_length: 6,
            end_char: "!".to_string(),
            upper_start: 2,
            name: "test".to_string(),
            email: "test@example.com".to_string(),
            site: "example.com".to_string(),
            ..Default::default()
        };
        
        let result = generate_password_hash(&config).unwrap();
        assert!(result.starts_with("test,"));
        assert!(result.ends_with(",example.com"));
        assert!(result.contains("!"));
    }

    #[test]
    fn test_hash_functions() {
        // Test various hash algorithms
        let test_string = "hello world";
        
        let md5_hash = get_string_hash(test_string, "MD5");
        let sha1_hash = get_string_hash(test_string, "SHA1");
        let sha256_hash = get_string_hash(test_string, "SHA256");
        let sha512_hash = get_string_hash(test_string, "SHA512");
        
        // Verify hash lengths
        assert_eq!(md5_hash.len(), 32);
        assert_eq!(sha1_hash.len(), 40);
        assert_eq!(sha256_hash.len(), 64);
        assert_eq!(sha512_hash.len(), 128);
        
        // Verify known hash values
        assert_eq!(md5_hash, "5eb63bbbe01eeed093cb22bb8f5acdc3");
    }
}