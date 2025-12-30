#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use once_cell::sync::OnceCell;
use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::sync::atomic::AtomicI32;
use std::sync::mpsc;
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::{
    AppHandle, Emitter, Manager,
    image::Image,
    menu::{Menu, MenuItem},
    tray::TrayIconBuilder,
};
use tauri_plugin_store::StoreExt;
use tauri_plugin_log::{Builder, Target, TargetKind};
use whisper_rs::{FullParams, SamplingStrategy, WhisperContext, WhisperContextParameters};
use std::process::Stdio;

static WHISPER: OnceCell<Mutex<WhisperContext>> = OnceCell::new();
static APP_HANDLE: OnceCell<AppHandle> = OnceCell::new();
static IS_RECORDING: AtomicBool = AtomicBool::new(false);
static IS_CANCELLING: AtomicBool = AtomicBool::new(false);
static FRONTMOST_PID: AtomicI32 = AtomicI32::new(0);
static FOCUSED_AX_ELEM: OnceCell<Mutex<Option<usize>>> = OnceCell::new();
static FOCUSED_AX_FINGERPRINT: OnceCell<Mutex<Option<String>>> = OnceCell::new();
static IS_TEXT_INPUT_MODE: AtomicBool = AtomicBool::new(true); // default to paste

enum AudioCmd {
    Start,
    Stop {
        reply: mpsc::Sender<Result<(Vec<f32>, u32), String>>,
    },
}

static AUDIO_TX: OnceCell<mpsc::Sender<AudioCmd>> = OnceCell::new();
static VOLUME_LEVEL_TX: OnceCell<mpsc::Sender<f32>> = OnceCell::new();

// OpenRouter API endpoints
const OPENROUTER_API_URL: &str = "https://openrouter.ai/api/v1/chat/completions";
const OPENROUTER_MODELS_URL: &str = "https://openrouter.ai/api/v1/models";

// AppleScript generation system prompt
const APPLESCRIPT_SYSTEM_PROMPT: &str = r#"You are an AppleScript generator for macOS automation.

Given a voice command from a user, generate a valid AppleScript that accomplishes their request.

Rules:
1. Output ONLY the AppleScript code, nothing else
2. No markdown, no explanation, no backticks
3. Use "tell application" blocks for app control
4. Use "System Events" for keyboard/mouse simulation
5. Keep scripts simple and focused on the single task
6. If the request is unclear, generate a script that does nothing harmful

Common patterns:
- Open app: tell application "AppName" to activate
- Open URL: open location "https://..."
- Type text: tell application "System Events" to keystroke "text"
- Notification: display notification "message" with title "title"
- Click menu: tell application "System Events" to click menu item "X" of menu "Y" of menu bar 1 of process "App"

Examples:
User: "open slack"
Output: tell application "Slack" to activate

User: "open google"
Output: open location "https://google.com"

User: "send a notification saying hello"
Output: display notification "hello" with title "t2t""#;

#[derive(serde::Deserialize)]
struct AgentResponse {
    success: bool,
    script: Option<String>,
    blocked: Option<bool>,
    error: Option<String>,
}

#[derive(serde::Deserialize)]
struct MCPAgentResponse {
    success: bool,
    text: Option<String>,
    #[serde(rename = "toolCalls")]
    tool_calls: Option<Vec<serde_json::Value>>,
    error: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct MCPServer {
    id: String,
    name: String,
    transport: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    args: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    enabled: Option<bool>,
}

#[derive(serde::Serialize)]
struct MCPToolsResponse {
    success: bool,
    tools: Vec<MCPTool>,
    prompts: Vec<MCPPrompt>,
    tools_count: usize,
    prompts_count: usize,
    resources_count: usize,
    error: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct MCPPrompt {
    name: String,
    description: String,
    arguments: Vec<serde_json::Value>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct MCPTool {
    name: String,
    description: String,
    input_schema: serde_json::Value,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct HistoryEntry {
    id: String,
    timestamp: String,
    #[serde(rename = "type")]
    entry_type: String,
    data: serde_json::Value,
}

#[derive(serde::Serialize)]
struct HistoryResponse {
    entries: Vec<HistoryEntry>,
    total: usize,
}

/// Format user message with optional screenshot for image generation models
/// 
/// Creates an OpenAI-compatible message format that can include both text and images.
/// If a screenshot is provided, the message uses the mixed content format with both
/// text and image_url content types. Otherwise, returns a simple text message.
/// 
/// # Arguments
/// * `text` - The user's text prompt/transcript
/// * `screenshot_base64` - Optional base64-encoded image data URI
/// 
/// # Returns
/// JSON value representing the message in OpenAI Chat Completions API format
fn format_user_message(text: &str, screenshot_base64: Option<&str>) -> serde_json::Value {
    if let Some(image_data) = screenshot_base64 {
        // Mixed content: text + image
        serde_json::json!({
            "role": "user",
            "content": [
                {
                    "type": "text",
                    "text": text
                },
                {
                    "type": "image_url",
                    "image_url": {
                        "url": image_data
                    }
                }
            ]
        })
    } else {
        // Text only
        serde_json::json!({
            "role": "user",
            "content": text
        })
    }
}

// Local AppleScript agent: Calls OpenRouter directly, no worker needed
fn call_applescript_agent_local(transcript: &str, openrouter_key: &str, model: &str, app: Option<&AppHandle>) -> Result<AgentResponse, String> {
    // Capture screenshot for vision-capable models (OpenRouter ignores for non-vision models)
    let screenshot = match capture_screenshot() {
        Ok(img) => {
            log_line(&format!("Captured screenshot for model: {}", model));
            Some(img)
        }
        Err(e) => {
            log_line(&format!("Warning: Failed to capture screenshot: {}. Continuing with text-only.", e));
            None
        }
    };
    
    let user_message = format_user_message(transcript, screenshot.as_deref());
    
    // Build request JSON for logging (sanitize API key)
    let request_json = serde_json::json!({
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": APPLESCRIPT_SYSTEM_PROMPT
            },
            user_message.clone()
        ],
        "max_tokens": 500
    });
    
    let client = reqwest::blocking::Client::new();
    let response = client
        .post(OPENROUTER_API_URL)
        .header("Authorization", format!("Bearer {}", openrouter_key))
        .header("HTTP-Referer", "https://github.com/acoyfellow/t2t")
        .header("X-Title", "t2t")
        .json(&request_json)
        .timeout(std::time::Duration::from_secs(60))
        .send()
        .map_err(|e| format!("OpenRouter request failed: {e}"))?;
    
    if !response.status().is_success() {
        let status = response.status();
        let error_body = response.text().unwrap_or_else(|_| "Could not read error body".to_string());
        
        // Log error to history
        if let Some(app_handle) = app {
            let screenshot_thumbnail = screenshot.as_ref()
                .and_then(|s| create_thumbnail(s).ok().flatten());
            if let Err(e) = save_history_entry(
                app_handle.clone(),
                "agent".to_string(),
                serde_json::json!({
                    "transcript": transcript,
                    "model": model,
                    "request": request_json,
                    "response": serde_json::json!({
                        "error": format!("{}: {}", status, error_body)
                    }),
                    "screenshotThumbnail": screenshot_thumbnail,
                    "success": false,
                    "error": format!("{}: {}", status, error_body)
                })
            ) {
                log_line(&format!("Failed to save AppleScript agent history entry (error): {}", e));
            }
        } else {
            log_line("Warning: No app handle available to save AppleScript agent history (error)");
        }
        
        return Err(format!("OpenRouter returned {}: {}", status, error_body));
    }
    
    let openrouter_resp: serde_json::Value = response.json()
        .map_err(|e| format!("Failed to parse OpenRouter response: {e}"))?;
    
    // Parse response - OpenAI format
    let result = if let Some(choices) = openrouter_resp.get("choices").and_then(|c| c.as_array()) {
        if let Some(choice) = choices.first() {
            if let Some(message) = choice.get("message") {
                if let Some(content) = message.get("content").and_then(|v| v.as_str()) {
                    // Strip any markdown code blocks if the model added them
                    let script = content
                        .replace("```applescript", "")
                        .replace("```", "")
                        .trim()
                        .to_string();
                    
                    // Log success to history
                    if let Some(app_handle) = app {
                        let screenshot_thumbnail = screenshot.as_ref()
                            .and_then(|s| create_thumbnail(s).ok().flatten());
                        if let Err(e) = save_history_entry(
                            app_handle.clone(),
                            "agent".to_string(),
                            serde_json::json!({
                                "transcript": transcript,
                                "model": model,
                                "request": request_json,
                                "response": openrouter_resp.clone(),
                                "screenshotThumbnail": screenshot_thumbnail,
                                "success": true
                            })
                        ) {
                            log_line(&format!("Failed to save agent history entry: {}", e));
                        } else {
                            log_line("Successfully saved agent history entry");
                        }
                    } else {
                        log_line("Warning: No app handle available to save agent history");
                    }
                    
                    Ok(AgentResponse {
                        success: true,
                        script: Some(script),
                        blocked: Some(false),
                        error: None,
                    })
                } else {
                    Err("No content in OpenRouter response".to_string())
                }
            } else {
                Err("No message in OpenRouter response".to_string())
            }
        } else {
            Err("No choices in OpenRouter response".to_string())
        }
    } else {
        Err("No content in OpenRouter response".to_string())
    };
    
    // Log error if result is error
    if result.is_err() {
        if let Some(app_handle) = app {
            let screenshot_thumbnail = screenshot.as_ref()
                .and_then(|s| create_thumbnail(s).ok().flatten());
            let error_msg = result.as_ref().err().map(|e| e.clone()).unwrap_or_else(|| "Unknown error".to_string());
            if let Err(e) = save_history_entry(
                app_handle.clone(),
                "agent".to_string(),
                serde_json::json!({
                    "transcript": transcript,
                    "model": model,
                    "request": request_json,
                    "response": openrouter_resp,
                    "screenshotThumbnail": screenshot_thumbnail,
                    "success": false,
                    "error": error_msg
                })
            ) {
                log_line(&format!("Failed to save agent history entry (parse error): {}", e));
            }
        } else {
            log_line("Warning: No app handle available to save agent history (parse error)");
        }
    }
    
    result
}

// Convert MCP tool to OpenAI format
fn mcp_tool_to_openai(tool: &MCPTool) -> serde_json::Value {
    serde_json::json!({
        "type": "function",
        "function": {
            "name": tool.name,
            "description": tool.description,
            "parameters": tool.input_schema
        }
    })
}

// Execute a single MCP tool call via stdio
async fn execute_mcp_tool_stdio(
    server: &MCPServer,
    tool_name: &str,
    arguments: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::process::Command as TokioCommand;

    let command = server.command.as_ref().ok_or("No command specified")?;
    let empty_args: Vec<String> = vec![];
    let args = server.args.as_ref().unwrap_or(&empty_args);

    let mut child = TokioCommand::new(command)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn process: {e}"))?;

    let mut stdin = child.stdin.take().ok_or("Failed to open stdin")?;
    let stdout = child.stdout.take().ok_or("Failed to open stdout")?;
    let mut reader = BufReader::new(stdout);

    // Initialize
    let init_request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "t2t", "version": "0.2.5" }
        }
    });
    stdin.write_all(format!("{}\n", init_request).as_bytes()).await
        .map_err(|e| format!("Failed to write init: {e}"))?;
    stdin.flush().await.map_err(|e| format!("Failed to flush: {e}"))?;

    let mut line = String::new();
    reader.read_line(&mut line).await
        .map_err(|e| format!("Failed to read init response: {e}"))?;

    // Send initialized notification
    let initialized = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    });
    stdin.write_all(format!("{}\n", initialized).as_bytes()).await.ok();
    stdin.flush().await.ok();

    // Call tools/call
    let tool_call = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": arguments
        }
    });
    line.clear();
    stdin.write_all(format!("{}\n", tool_call).as_bytes()).await
        .map_err(|e| format!("Failed to write tool call: {e}"))?;
    stdin.flush().await.map_err(|e| format!("Failed to flush: {e}"))?;

    line.clear();
    reader.read_line(&mut line).await
        .map_err(|e| format!("Failed to read tool response: {e}"))?;

    let response: serde_json::Value = serde_json::from_str(&line)
        .map_err(|e| format!("Invalid tool response: {e}"))?;

    let _ = child.kill().await;

    if let Some(error) = response.get("error") {
        return Err(format!("Tool error: {}", error));
    }

    response.get("result")
        .and_then(|r| r.get("content"))
        .and_then(|c| c.as_array())
        .and_then(|arr| arr.first())
        .and_then(|item| item.get("text"))
        .cloned()
        .ok_or_else(|| "No result in tool response".to_string())
}

// Execute a single MCP tool call via HTTP
async fn execute_mcp_tool_http(
    url: &str,
    tool_name: &str,
    arguments: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    let client = reqwest::Client::new();

    // Initialize
    let init_request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "t2t", "version": "0.2.5" }
        }
    });
    client.post(url).json(&init_request)
        .timeout(std::time::Duration::from_secs(30))
        .send().await
        .map_err(|e| format!("Init request failed: {e}"))?;

    // Call tools/call
    let tool_call = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": arguments
        }
    });

    let response: serde_json::Value = client.post(url).json(&tool_call)
        .timeout(std::time::Duration::from_secs(30))
        .send().await
        .map_err(|e| format!("Tool call request failed: {e}"))?
        .json().await
        .map_err(|e| format!("Failed to parse tool response: {e}"))?;

    if let Some(error) = response.get("error") {
        return Err(format!("Tool error: {}", error));
    }

    response.get("result")
        .and_then(|r| r.get("content"))
        .and_then(|c| c.as_array())
        .and_then(|arr| arr.first())
        .and_then(|item| item.get("text"))
        .cloned()
        .ok_or_else(|| "No result in tool response".to_string())
}

// Local MCP Agent: Calls OpenRouter directly, executes tools locally
fn call_mcp_agent_local(transcript: &str, mcp_servers: Vec<MCPServer>, openrouter_key: String, model: &str, app: Option<&AppHandle>) -> Result<MCPAgentResponse, String> {
    
    // Fetch tools from all enabled servers
    let rt = tokio::runtime::Runtime::new().map_err(|e| format!("Failed to create runtime: {e}"))?;
    
    let mut all_tools = Vec::new();
    let mut server_tool_map: HashMap<String, (MCPServer, Vec<MCPTool>)> = HashMap::new();
    
    for server in &mcp_servers {
        if server.enabled.unwrap_or(true) {
            let tools_result = match server.transport.as_str() {
                "stdio" => {
                    let cmd = server.command.as_ref().ok_or("No command")?;
                    let empty_args: Vec<String> = vec![];
                    let args = server.args.as_ref().unwrap_or(&empty_args);
                    rt.block_on(fetch_mcp_tools_stdio(cmd, args))
                }
                "http" | "https" => {
                    let url = server.url.as_ref().ok_or("No URL")?;
                    rt.block_on(fetch_mcp_tools_http(url))
                }
                _ => continue,
            };
            
            if let Ok(tools_resp) = tools_result {
                server_tool_map.insert(server.id.clone(), (server.clone(), tools_resp.tools.clone()));
                all_tools.extend(tools_resp.tools.clone());
            }
        }
    }
    
    if all_tools.is_empty() {
        // Log early return to history
        if let Some(app_handle) = app {
            if let Err(e) = save_history_entry(
                app_handle.clone(),
                "agent".to_string(),
                serde_json::json!({
                    "transcript": transcript,
                    "model": model,
                    "request": serde_json::json!({
                        "model": model,
                        "messages": [{"role": "user", "content": transcript}]
                    }),
                    "response": serde_json::json!({
                        "error": "No tools available from MCP servers"
                    }),
                    "success": false,
                    "error": "No tools available from MCP servers"
                })
            ) {
                log_line(&format!("Failed to save MCP agent history entry (no tools): {}", e));
            }
        }
        return Ok(MCPAgentResponse {
            success: false,
            text: None,
            tool_calls: None,
            error: Some("No tools available from MCP servers".to_string()),
        });
    }
    
    // Convert to OpenAI format
    let openai_tools: Vec<serde_json::Value> = all_tools.iter()
        .map(mcp_tool_to_openai)
        .collect();
    
    // Capture screenshot for vision-capable models (OpenRouter ignores for non-vision models)
    let screenshot = match capture_screenshot() {
        Ok(img) => {
            log_line(&format!("Captured screenshot for model: {}", model));
            Some(img)
        }
        Err(e) => {
            log_line(&format!("Warning: Failed to capture screenshot: {}. Continuing with text-only.", e));
            None
        }
    };
    
    let user_message = format_user_message(transcript, screenshot.as_deref());
    
    // Build request JSON for logging
    let request_json = serde_json::json!({
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": "You are a helpful assistant with access to tools. Use them when needed."
            },
            user_message.clone()
        ],
        "tools": openai_tools.clone(),
        "tool_choice": "auto"
    });
    
    // Call OpenRouter
    let client = reqwest::blocking::Client::new();
    let response = client
        .post(OPENROUTER_API_URL)
        .header("Authorization", format!("Bearer {}", openrouter_key))
        .header("HTTP-Referer", "https://github.com/yourusername/t2t")
        .header("X-Title", "t2t")
        .json(&request_json)
        .timeout(std::time::Duration::from_secs(60))
        .send()
        .map_err(|e| format!("OpenRouter request failed: {e}"))?;
    
    if !response.status().is_success() {
        let status = response.status();
        let error_body = response.text().unwrap_or_else(|_| "Could not read error body".to_string());
        
        // Log error to history
        if let Some(app_handle) = app {
            let screenshot_thumbnail = screenshot.as_ref()
                .and_then(|s| create_thumbnail(s).ok().flatten());
            if let Err(e) = save_history_entry(
                app_handle.clone(),
                "agent".to_string(),
                serde_json::json!({
                    "transcript": transcript,
                    "model": model,
                    "request": request_json,
                    "response": serde_json::json!({
                        "error": format!("{}: {}", status, error_body)
                    }),
                    "screenshotThumbnail": screenshot_thumbnail,
                    "success": false,
                    "error": format!("{}: {}", status, error_body)
                })
            ) {
                log_line(&format!("Failed to save MCP agent history entry (error): {}", e));
            }
        } else {
            log_line("Warning: No app handle available to save MCP agent history (error)");
        }
        
        return Err(format!("OpenRouter returned {}: {}", status, error_body));
    }
    
    let openrouter_resp: serde_json::Value = response.json()
        .map_err(|e| format!("Failed to parse OpenRouter response: {e}"))?;
    
    let mut tool_calls = Vec::new();
    let mut final_text = None;
    
    // Parse response
    if let Some(choices) = openrouter_resp.get("choices").and_then(|c| c.as_array()) {
        if let Some(choice) = choices.first() {
            if let Some(message) = choice.get("message") {
                // Check for tool calls
                if let Some(tool_calls_array) = message.get("tool_calls").and_then(|tc| tc.as_array()) {
                    // Execute tool calls
                    for tool_call in tool_calls_array {
                        if let (Some(tool_id), Some(function)) = (
                            tool_call.get("id").and_then(|v| v.as_str()),
                            tool_call.get("function")
                        ) {
                            if let (Some(tool_name), Some(arguments_str)) = (
                                function.get("name").and_then(|v| v.as_str()),
                                function.get("arguments").and_then(|v| v.as_str())
                            ) {
                                let arguments: serde_json::Value = serde_json::from_str(arguments_str)
                                    .map_err(|e| format!("Invalid tool arguments: {e}"))?;
                                
                                // Find which server has this tool
                                let mut tool_result = Err("Tool not found".to_string());
                                for (_server_id, (server, tools)) in &server_tool_map {
                                    if tools.iter().any(|t| t.name == tool_name) {
                                        tool_result = match server.transport.as_str() {
                                            "stdio" => {
                                                rt.block_on(execute_mcp_tool_stdio(server, tool_name, &arguments))
                                            }
                                            "http" | "https" => {
                                                let url = server.url.as_ref().unwrap();
                                                rt.block_on(execute_mcp_tool_http(url, tool_name, &arguments))
                                            }
                                            _ => continue,
                                        };
                                        break;
                                    }
                                }
                                
                                let tool_result_value = match tool_result {
                                    Ok(v) => v,
                                    Err(e) => serde_json::json!({ "error": e })
                                };
                                
                                tool_calls.push(serde_json::json!({
                                    "id": tool_id,
                                    "toolName": tool_name,
                                    "arguments": arguments,
                                    "result": tool_result_value
                                }));
                            }
                        }
                    }
                    
                    // If we executed tools, make another call with results
                    if !tool_calls.is_empty() {
                        let mut messages = vec![
                            serde_json::json!({
                                "role": "system",
                                "content": "You are a helpful assistant with access to tools."
                            }),
                            user_message.clone(), // Include original user message with screenshot if applicable
                            message.clone(),
                        ];
                        
                        // Add tool results
                        for tool_call in &tool_calls {
                            messages.push(serde_json::json!({
                                "role": "tool",
                                "tool_call_id": tool_call.get("id"),
                                "content": tool_call.get("result").map(|r| r.to_string()).unwrap_or_default()
                            }));
                        }
                        
                        // Final call
                        let final_response = client
                            .post(OPENROUTER_API_URL)
                            .header("Authorization", format!("Bearer {}", openrouter_key))
                            .header("HTTP-Referer", "https://github.com/yourusername/t2t")
                            .header("X-Title", "t2t")
                            .json(&serde_json::json!({
                                "model": model,
                                "messages": messages,
                                "tools": openai_tools,
                            }))
                            .timeout(std::time::Duration::from_secs(60))
                            .send()
                            .map_err(|e| format!("Final OpenRouter request failed: {e}"))?;
                        
                        if final_response.status().is_success() {
                            if let Ok(final_resp) = final_response.json::<serde_json::Value>() {
                                if let Some(choices) = final_resp.get("choices").and_then(|c| c.as_array()) {
                                    if let Some(choice) = choices.first() {
                                        if let Some(msg) = choice.get("message") {
                                            final_text = msg.get("content").and_then(|v| v.as_str()).map(|s| s.to_string());
                                        }
                                    }
                                }
                            }
                        }
                    }
                } else {
                    // No tool calls, just text response
                    final_text = message.get("content").and_then(|v| v.as_str()).map(|s| s.to_string());
                }
            }
        }
    }
    
    let result = MCPAgentResponse {
        success: true,
        text: final_text.clone(),
        tool_calls: if tool_calls.is_empty() { None } else { Some(tool_calls.clone()) },
        error: None,
    };
    
    // Log to history
    if let Some(app_handle) = app {
        let screenshot_thumbnail = screenshot.as_ref()
            .and_then(|s| create_thumbnail(s).ok().flatten());
        if let Err(e) = save_history_entry(
            app_handle.clone(),
            "agent".to_string(),
            serde_json::json!({
                "transcript": transcript,
                "model": model,
                "request": request_json,
                "response": openrouter_resp,
                "toolCalls": result.tool_calls,
                "screenshotThumbnail": screenshot_thumbnail,
                "success": true
            })
        ) {
            log_line(&format!("Failed to save MCP agent history entry: {}", e));
        } else {
            log_line("Successfully saved MCP agent history entry");
        }
    } else {
        log_line("Warning: No app handle available to save MCP agent history");
    }
    
    Ok(result)
}

// Wrapper for compatibility
fn call_mcp_agent_api(transcript: &str, mcp_servers: Vec<MCPServer>, openrouter_key: String, model: &str, app: Option<&AppHandle>) -> Result<MCPAgentResponse, String> {
    call_mcp_agent_local(transcript, mcp_servers, openrouter_key, model, app)
}

fn get_mcp_config(app: &AppHandle) -> Option<(Vec<MCPServer>, String)> {
    // Try to get OpenRouter key from store, fallback to env var
    let key = if let Ok(key_store) = app.store("openrouter-key") {
        key_store.get("key")
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .filter(|k| !k.is_empty())
    } else {
        log_line("get_mcp_config: failed to open openrouter-key store");
        None
    };
    
    let key = key.or_else(|| {
        log_line("get_mcp_config: trying OPENROUTER_API_KEY env var");
        std::env::var("OPENROUTER_API_KEY").ok()
    }).filter(|k| !k.is_empty());
    
    let key = match key {
        Some(k) => {
            log_line(&format!("get_mcp_config: found OpenRouter key (len={})", k.len()));
            k
        },
        None => {
            log_line("get_mcp_config: no OpenRouter key found");
            return None;
        }
    };
    
    // Get MCP servers from store
    let servers_store = match app.store("mcp-servers.json") {
        Ok(store) => store,
        Err(e) => {
            log_line(&format!("get_mcp_config: failed to open mcp-servers.json store: {:?}", e));
            return None;
        }
    };
    
    let servers_data: Vec<serde_json::Value> = match servers_store.get("servers") {
        Some(v) => {
            match v.as_array() {
                Some(arr) => {
                    log_line(&format!("get_mcp_config: found {} servers in store", arr.len()));
                    arr.clone()
                },
                None => {
                    log_line("get_mcp_config: servers field is not an array");
                    return None;
                }
            }
        },
        None => {
            log_line("get_mcp_config: no 'servers' field in store");
            return None;
        }
    };
    
    if servers_data.is_empty() {
        log_line("get_mcp_config: servers array is empty");
        return None;
    }
    
    let servers: Result<Vec<MCPServer>, _> = servers_data
        .into_iter()
        .map(|v| serde_json::from_value(v))
        .collect();
    
    match servers {
        Ok(s) => {
            let total_count = s.len();
            // Filter to only enabled servers (default to enabled=true if not specified)
            let enabled: Vec<MCPServer> = s.into_iter()
                .filter(|server| server.enabled.unwrap_or(true))
                .collect();
            
            log_line(&format!("get_mcp_config: successfully loaded {} servers ({} enabled)", total_count, enabled.len()));
            
            if enabled.is_empty() {
                log_line("get_mcp_config: no enabled servers");
                return None;
            }
            
            Some((enabled, key))
        },
        Err(e) => {
            log_line(&format!("get_mcp_config: failed to deserialize servers: {:?}", e));
            None
        }
    }
}

#[cfg(target_os = "macos")]
fn execute_applescript(script: &str) -> Result<String, String> {
    use std::process::Command;
    let output = Command::new("osascript")
        .arg("-e")
        .arg(script)
        .output()
        .map_err(|e| format!("Failed to run osascript: {e}"))?;
    
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

#[cfg(target_os = "macos")]
fn show_notification(title: &str, message: &str) {
    let script = format!(
        r#"display notification "{}" with title "{}""#,
        message.replace('"', "\\\""),
        title.replace('"', "\\\"")
    );
    let _ = execute_applescript(&script);
}

fn log_line(msg: &str) {
    // Best-effort persistent log to help debug Finder vs Terminal launch differences.
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    let line = format!("[{ts:.3}] {msg}\n");
    eprint!("{line}");

    #[cfg(target_os = "macos")]
    {
        if let Ok(home) = std::env::var("HOME") {
            let path = std::path::Path::new(&home)
                .join("Library")
                .join("Logs")
                .join("t2t.log");
            let _ = std::fs::create_dir_all(path.parent().unwrap());
            if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
                use std::io::Write;
                let _ = f.write_all(line.as_bytes());
            }
        }
    }
}

fn update_stats(app: AppHandle, text: String, dur_ms: f64) {
    let word_count = text.split_whitespace().count();
    if word_count == 0 {
        return;
    }
    
    let dur_seconds = dur_ms / 1000.0;
    let wpm = if dur_seconds > 0.0 {
        (word_count as f64) / (dur_seconds / 60.0)
    } else {
        0.0
    };
    
    let now_hour = (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() / 3600) as i64;
    
    let app_clone = app.clone();
    let _ = app.run_on_main_thread(move || {
        if let Ok(store) = app_clone.store("stats.json") {
            let total_words: f64 = store.get("total_words")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .unwrap_or(0.0);
            let total_seconds: f64 = store.get("total_seconds")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .unwrap_or(0.0);
            let session_count: f64 = store.get("session_count")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .unwrap_or(0.0);
            let session_wpm_sum: f64 = store.get("session_wpm_sum")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .unwrap_or(0.0);
            
            let mut activity_hourly: Vec<(i64, f64)> = store
                .get("activity_hourly")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .unwrap_or_default();
            
            let _ = store.set("total_words".to_string(), serde_json::json!(total_words + word_count as f64));
            let _ = store.set("total_seconds".to_string(), serde_json::json!(total_seconds + dur_seconds));
            let _ = store.set("session_count".to_string(), serde_json::json!(session_count + 1.0));
            let _ = store.set("session_wpm_sum".to_string(), serde_json::json!(session_wpm_sum + wpm));
            
            let hour_idx = activity_hourly.iter().position(|(h, _)| *h == now_hour);
            if let Some(idx) = hour_idx {
                activity_hourly[idx].1 += word_count as f64;
            } else {
                activity_hourly.push((now_hour, word_count as f64));
            }
            let _ = store.set("activity_hourly".to_string(), serde_json::json!(activity_hourly));
            
            if let Err(e) = store.save() {
                log_line(&format!("Failed to save stats: {e}"));
            }
        }
    });
}

fn create_circular_icon(size: u32) -> Image<'static> {
    // Match the orb color: #4a4a4a = RGB(74, 74, 74)
    let r = 74u8;
    let g = 74u8;
    let b = 74u8;
    let center = (size as f32 / 2.0) - 0.5;
    let radius = (size as f32 / 2.0) - 1.0;
    
    let mut pixels = Vec::with_capacity((size * size * 4) as usize);
    
    for y in 0..size {
        for x in 0..size {
            let dx = x as f32 - center;
            let dy = y as f32 - center;
            let dist = (dx * dx + dy * dy).sqrt();
            
            if dist <= radius {
                pixels.push(r);
                pixels.push(g);
                pixels.push(b);
                pixels.push(0xff);
            } else {
                pixels.push(0);
                pixels.push(0);
                pixels.push(0);
                pixels.push(0);
            }
        }
    }
    
    Image::new_owned(pixels, size, size)
}

fn get_model_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".cache").join("whisper").join("ggml-base.en.bin")
}

fn ensure_model(path: &PathBuf) -> Result<(), String> {
    if path.exists() {
        return Ok(());
    }
    
    std::fs::create_dir_all(path.parent().unwrap()).map_err(|e| e.to_string())?;
    
    log_line("Downloading Whisper model (~150MB)...");
    let url = "https://huggingface.co/ggerganov/whisper.cpp/resolve/main/ggml-base.en.bin";
    
    let response = std::process::Command::new("curl")
        .args(["-L", "-o", path.to_str().unwrap(), url])
        .status()
        .map_err(|e| e.to_string())?;
    
    if !response.success() {
        return Err("Failed to download model".to_string());
    }
    
    log_line("Model downloaded!");
    Ok(())
}

fn init_whisper() -> Result<(), String> {
    let path = get_model_path();
    ensure_model(&path)?;
    
    let ctx = WhisperContext::new_with_params(
        path.to_str().unwrap(),
        WhisperContextParameters::default(),
    ).map_err(|e| format!("Failed to load Whisper: {:?}", e))?;
    
    WHISPER.set(Mutex::new(ctx)).map_err(|_| "Already initialized")?;
    log_line("Whisper initialized!");
    Ok(())
}

#[cfg(target_os = "macos")]
mod macos_fn_key {
    use super::*;
    use block::ConcreteBlock;
    use objc::{class, msg_send, sel, sel_impl};
    use objc::runtime::Object;
    use std::ffi::c_void;
    use std::ptr;
    
    // IOKit types
    type IOHIDManagerRef = *mut c_void;
    type IOHIDValueRef = *mut c_void;
    type IOHIDElementRef = *mut c_void;
    type IOReturn = i32;
    type CFAllocatorRef = *const c_void;
    type CFDictionaryRef = *const c_void;
    type CFRunLoopRef = *mut c_void;
    type CFStringRef = *const c_void;
    type CFIndex = isize;
    
    const K_CF_ALLOCATOR_DEFAULT: CFAllocatorRef = ptr::null();
    const K_IO_HID_OPTIONS_TYPE_NONE: u32 = 0;
    const K_IO_RETURN_SUCCESS: IOReturn = 0;
    
    #[link(name = "IOKit", kind = "framework")]
    extern "C" {
        fn IOHIDManagerCreate(allocator: CFAllocatorRef, options: u32) -> IOHIDManagerRef;
        fn IOHIDManagerSetDeviceMatching(manager: IOHIDManagerRef, matching: CFDictionaryRef);
        fn IOHIDManagerRegisterInputValueCallback(
            manager: IOHIDManagerRef,
            callback: Option<unsafe extern "C" fn(*mut c_void, IOReturn, *mut c_void, IOHIDValueRef)>,
            context: *mut c_void,
        );
        fn IOHIDManagerScheduleWithRunLoop(
            manager: IOHIDManagerRef,
            run_loop: CFRunLoopRef,
            run_loop_mode: CFStringRef,
        );
        fn IOHIDManagerOpen(manager: IOHIDManagerRef, options: u32) -> IOReturn;
        fn IOHIDValueGetElement(value: IOHIDValueRef) -> IOHIDElementRef;
        fn IOHIDValueGetIntegerValue(value: IOHIDValueRef) -> CFIndex;
        fn IOHIDElementGetUsagePage(element: IOHIDElementRef) -> u32;
        fn IOHIDElementGetUsage(element: IOHIDElementRef) -> u32;
    }
    
    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        fn CFRunLoopGetCurrent() -> CFRunLoopRef;
        fn CFRunLoopRun();
        static kCFRunLoopDefaultMode: CFStringRef;
        fn CFDictionaryCreate(
            allocator: *const c_void,
            keys: *const *const c_void,
            values: *const *const c_void,
            num_values: isize,
            key_callbacks: *const c_void,
            value_callbacks: *const c_void,
        ) -> CFDictionaryRef;
        static kCFBooleanTrue: *const c_void;
        fn CFRetain(cf: *const c_void) -> *const c_void;
        fn CFRelease(cf: *const c_void);
        fn CFStringCreateWithCString(alloc: *const c_void, c_str: *const i8, encoding: u32) -> *const c_void;
        fn CFStringGetLength(the_string: *const c_void) -> CFIndex;
        fn CFStringGetMaximumSizeForEncoding(length: CFIndex, encoding: u32) -> CFIndex;
        fn CFStringGetCString(the_string: *const c_void, buffer: *mut i8, buffer_size: CFIndex, encoding: u32) -> bool;
    }

    const K_CF_STRING_ENCODING_UTF8: u32 = 0x08000100;

    fn cfstr(s: &'static str) -> *const c_void {
        // Create a CFStringRef. Caller must CFRelease.
        let c = std::ffi::CString::new(s).unwrap();
        unsafe { CFStringCreateWithCString(ptr::null(), c.as_ptr(), K_CF_STRING_ENCODING_UTF8) }
    }
    
    // Accessibility permission check / prompt
    #[link(name = "ApplicationServices", kind = "framework")]
    extern "C" {
        fn AXIsProcessTrusted() -> bool;
        fn AXIsProcessTrustedWithOptions(options: CFDictionaryRef) -> bool;
        static kAXTrustedCheckOptionPrompt: *const c_void;

        fn AXUIElementCreateSystemWide() -> *mut c_void;
        fn AXUIElementGetPid(element: *mut c_void, pid: *mut i32) -> i32;
        fn AXUIElementCopyAttributeValue(
            element: *mut c_void,
            attribute: *const c_void,
            value: *mut *mut c_void,
        ) -> i32;
    }

    // For polling current modifier flags state (to detect Fn-up even if release event is missed)
    #[link(name = "ApplicationServices", kind = "framework")]
    extern "C" {
        fn CGEventSourceFlagsState(state_id: i32) -> u64;
    }

    const K_CG_EVENT_SOURCE_STATE_COMBINED_SESSION_STATE: i32 = 0;
    const K_CG_EVENT_FLAG_MASK_SECONDARY_FN: u64 = 1u64 << 23;

    // Capture/restore frontmost app so paste always targets the app you were using on Fn-down.
    fn capture_frontmost_pid() -> i32 {
        unsafe {
            // NSWorkspace.sharedWorkspace.frontmostApplication.processIdentifier
            let ws: *mut Object = msg_send![class!(NSWorkspace), sharedWorkspace];
            if ws.is_null() {
                return 0;
            }
            let app: *mut Object = msg_send![ws, frontmostApplication];
            if app.is_null() {
                return 0;
            }
            let pid: i32 = msg_send![app, processIdentifier];
            pid
        }
    }

    fn capture_focused_ax_element() -> Option<usize> {
        unsafe {
            let sys = AXUIElementCreateSystemWide();
            if sys.is_null() {
                return None;
            }
            let mut out: *mut c_void = ptr::null_mut();
            let attr = cfstr("AXFocusedUIElement");
            let err = AXUIElementCopyAttributeValue(sys, attr, &mut out);
            CFRelease(attr);
            if err != 0 || out.is_null() {
                return None;
            }
            let retained = CFRetain(out as *const c_void) as *mut c_void;
            Some(retained as usize)
        }
    }

    fn cfstring_to_string(s: *const c_void) -> Option<String> {
        if s.is_null() {
            return None;
        }
        unsafe {
            let len = CFStringGetLength(s);
            let max = CFStringGetMaximumSizeForEncoding(len, K_CF_STRING_ENCODING_UTF8) + 1;
            if max <= 0 {
                return None;
            }
            let mut buf = vec![0u8; max as usize];
            let ok = CFStringGetCString(
                s,
                buf.as_mut_ptr() as *mut i8,
                max,
                K_CF_STRING_ENCODING_UTF8,
            );
            if !ok {
                return None;
            }
            let cstr = std::ffi::CStr::from_ptr(buf.as_ptr() as *const i8);
            Some(cstr.to_string_lossy().to_string())
        }
    }

    fn ax_attr_string(elem: *mut c_void, attr_name: &'static str) -> Option<String> {
        unsafe {
            let attr = cfstr(attr_name);
            let mut out: *mut c_void = ptr::null_mut();
            let err = AXUIElementCopyAttributeValue(elem, attr, &mut out);
            CFRelease(attr);
            if err != 0 || out.is_null() {
                return None;
            }
            let s = cfstring_to_string(out as *const c_void);
            CFRelease(out as *const c_void);
            s
        }
    }

    fn focused_fingerprint(elem: *mut c_void) -> Option<String> {
        // Stable-ish across Electron pointer churn; usually differs between chat/editor.
        let role = ax_attr_string(elem, "AXRole")?;
        let subrole = ax_attr_string(elem, "AXSubrole").unwrap_or_default();
        let desc = ax_attr_string(elem, "AXRoleDescription").unwrap_or_default();
        Some(format!("{role}|{subrole}|{desc}"))
    }

    #[allow(dead_code)]
    fn is_text_input(elem: *mut c_void) -> bool {
        let role = ax_attr_string(elem, "AXRole").unwrap_or_default();
        let subrole = ax_attr_string(elem, "AXSubrole").unwrap_or_default();
        
        log_line(&format!("is_text_input check: role='{}' subrole='{}'", role, subrole));
        
        // Standard text input roles
        if matches!(
            role.as_str(),
            "AXTextField" | "AXTextArea" | "AXComboBox" | "AXSearchField"
        ) {
            log_line("  -> text input (standard role)");
            return true;
        }
        
        // For web content (Electron apps, browsers), check if it's a web area
        // with an editable focused element inside
        if role == "AXWebArea" || role == "AXGroup" {
            // Check AXFocusedUIElement of this element for text input
            unsafe {
                let attr = cfstr("AXFocusedUIElement");
                let mut child: *mut c_void = ptr::null_mut();
                let err = AXUIElementCopyAttributeValue(elem, attr, &mut child);
                CFRelease(attr);
                if err == 0 && !child.is_null() {
                    let child_role = ax_attr_string(child, "AXRole").unwrap_or_default();
                    log_line(&format!("  -> child role='{}'", child_role));
                    CFRelease(child as *const c_void);
                    // Web text inputs often show as AXTextField, AXTextArea, or AXStaticText (contenteditable)
                    if matches!(child_role.as_str(), "AXTextField" | "AXTextArea" | "AXStaticText") {
                        log_line("  -> text input (web child)");
                        return true;
                    }
                }
            }
        }
        
        log_line("  -> NOT text input");
        false
    }

    fn strict_focus_ok(app: &AppHandle) -> bool {
        // Safety gate: only block paste when we're confident focus moved to a different target.
        // If we can't reliably fingerprint the focused element (common on some apps), we still allow paste
        // as long as the frontmost PID matches what was captured on Fn-down.
        let expected_pid = FRONTMOST_PID.load(Ordering::SeqCst);
        let expected_fp = FOCUSED_AX_FINGERPRINT
            .get()
            .and_then(|cell| cell.lock().ok().and_then(|g| g.clone()));

        let (tx, rx) = mpsc::channel::<bool>();
        let _ = app.run_on_main_thread(move || {
            let cur_pid = capture_frontmost_pid();
            let cur_elem = capture_focused_ax_element().map(|u| u as *mut c_void);

            let mut ok = cur_pid == expected_pid;
            let mut cur_fp_match: Option<bool> = None;

            if let Some(elem) = cur_elem {
                let mut ax_pid: i32 = 0;
                let ax_err = unsafe { AXUIElementGetPid(elem, &mut ax_pid as *mut i32) };
                if ax_err != 0 || ax_pid != expected_pid {
                    ok = false;
                }
                // Only enforce fingerprint match if we successfully captured both expected + current fingerprints.
                if let (Some(expected_fp), Some(fp)) = (expected_fp.as_ref(), focused_fingerprint(elem)) {
                    let matches = fp == *expected_fp;
                    cur_fp_match = Some(matches);
                    if !matches {
                        ok = false;
                    }
                }
                unsafe { CFRelease(elem as *const c_void) };
            } else {
                // Can't read focused element; fall back to PID-only.
            }

            if !ok {
                log_line(&format!(
                    "paste preflight failed: cur_pid={cur_pid} expected_pid={expected_pid} fp_match={cur_fp_match:?}"
                ));
            } else if expected_fp.is_none() {
                log_line("paste preflight: no stored AX fingerprint; allowing pid-only");
            } else if cur_fp_match.is_none() {
                log_line("paste preflight: no current AX fingerprint; allowing pid-only");
            }

            let _ = tx.send(ok);
        });

        rx.recv_timeout(std::time::Duration::from_millis(250)).unwrap_or(false)
    }

    fn env_truthy(key: &str) -> bool {
        std::env::var(key)
            .map(|v| {
                let v = v.trim().to_ascii_lowercase();
                v == "1" || v == "true" || v == "yes" || v == "on"
            })
            .unwrap_or(false)
    }

    /// Force macOS to show the Accessibility prompt (when possible).
    /// Returns current trusted state.
    pub fn request_accessibility_prompt() -> bool {
        unsafe {
            let keys: [*const c_void; 1] = [kAXTrustedCheckOptionPrompt as *const c_void];
            let values: [*const c_void; 1] = [kCFBooleanTrue as *const c_void];
            let dict = CFDictionaryCreate(
                ptr::null(),
                keys.as_ptr(),
                values.as_ptr(),
                1,
                ptr::null(),
                ptr::null(),
            );
            AXIsProcessTrustedWithOptions(dict)
        }
    }
    
    pub fn start_fn_listener() {
        std::thread::spawn(|| {
            log_line("Starting Fn key listener via IOHIDManager...");
            
            // If launched via Finder, macOS often won't auto-prompt unless we ask explicitly.
            let mut trusted = unsafe { AXIsProcessTrusted() };
            if !trusted {
                log_line("Accessibility permission: DENIED (requesting prompt)");
                trusted = request_accessibility_prompt();
            }

            // Wait a bit for the user to grant permission (they may still need to relaunch).
            if !trusted {
                for _ in 0..30 {
                    std::thread::sleep(std::time::Duration::from_millis(500));
                    trusted = unsafe { AXIsProcessTrusted() };
                    if trusted {
                        break;
                    }
                }
            }

            log_line(&format!(
                "Accessibility permission: {}",
                if trusted { "GRANTED" } else { "DENIED" }
            ));

            if !trusted {
                log_line("ERROR: Accessibility permission not granted. Enable t2t in System Settings > Privacy & Security > Accessibility");
                // Don't start IOHIDManager without trust; it will appear 'dead' when launched by Finder.
                return;
            }
            
            unsafe {
                let manager = IOHIDManagerCreate(K_CF_ALLOCATOR_DEFAULT, K_IO_HID_OPTIONS_TYPE_NONE);
                if manager.is_null() {
                    log_line("ERROR: Failed to create IOHIDManager");
                    return;
                }
                
                // Match all HID devices (we'll filter in callback)
                IOHIDManagerSetDeviceMatching(manager, ptr::null());
                
                // Register callback
                IOHIDManagerRegisterInputValueCallback(
                    manager,
                    Some(hid_callback),
                    ptr::null_mut(),
                );
                
                // Schedule with run loop
                let run_loop = CFRunLoopGetCurrent();
                IOHIDManagerScheduleWithRunLoop(manager, run_loop, kCFRunLoopDefaultMode);
                
                // Open manager
                let result = IOHIDManagerOpen(manager, K_IO_HID_OPTIONS_TYPE_NONE);
                if result != K_IO_RETURN_SUCCESS {
                    log_line(&format!("ERROR: IOHIDManagerOpen failed: {result}"));
                    log_line("Falling back to NSEvent global flagsChanged monitor (no IOHID).");
                    start_nsevent_fn_monitor();
                    // Keep thread alive so app doesn't exit; monitor runs on main thread.
                    return;
                }
                
                log_line("IOHIDManager active! Hold Fn to record.");
                
                CFRunLoopRun();
            }
        });
    }

    fn start_nsevent_fn_monitor() {
        // Install a global monitor for flagsChanged events, and detect Fn via keyCode==63.
        // This is a best-effort fallback if IOHID is denied for Finder-launched apps.
        let Some(app) = APP_HANDLE.get().cloned() else {
            log_line("NSEvent fallback: APP_HANDLE not set");
            return;
        };

        let _ = app.run_on_main_thread(|| unsafe {
            // NSEventMaskFlagsChanged = 1 << 12
            let mask: u64 = 1u64 << 12;
            // NSEventModifierFlagFunction is typically 1 << 23
            let fn_flag: u64 = 1u64 << 23;

            let handler = ConcreteBlock::new(move |event: *mut Object| {
                if event.is_null() {
                    return;
                }

                let key_code: u16 = msg_send![event, keyCode];
                let flags: u64 = msg_send![event, modifierFlags];

                // Fn key reports as flagsChanged with keyCode 63 on Apple keyboards.
                if key_code != 63 {
                    return;
                }

                let pressed = (flags & fn_flag) != 0;
                // Check if Control is held
                let control_flag: u64 = 1u64 << 18; // kCGEventFlagMaskControl
                let control_held = (flags & control_flag) != 0;
                // Avoid duplicate transitions
                let was_recording = IS_RECORDING.load(Ordering::SeqCst);
                if pressed && !was_recording {
                    handle_fn_key(true, control_held);
                } else if !pressed && was_recording {
                    handle_fn_key(false, false);
                }
            })
            .copy();

            let ns_event: *mut Object = msg_send![class!(NSEvent), addGlobalMonitorForEventsMatchingMask:mask handler:&*handler];
            let _ = ns_event;
            log_line("NSEvent fallback monitor installed (flagsChanged).");
        });
    }
    
    unsafe extern "C" fn hid_callback(
        _context: *mut c_void,
        _result: IOReturn,
        _sender: *mut c_void,
        value: IOHIDValueRef,
    ) {
        if value.is_null() {
            return;
        }
        
        let element = IOHIDValueGetElement(value);
        if element.is_null() {
            return;
        }
        
        let usage_page = IOHIDElementGetUsagePage(element);
        let usage = IOHIDElementGetUsage(element);
        let int_value = IOHIDValueGetIntegerValue(value);
        
        // Debug: log all HID events to find Fn key (enable with T2T_DEBUG_HID=1)
        if env_truthy("T2T_DEBUG_HID") && int_value != 0 {
            log_line(&format!("HID: page={:#x} usage={:#x} value={}", usage_page, usage, int_value));
        }
        
        // Fn key on Apple keyboards - check multiple possible codes
        let is_fn_key = 
            (usage_page == 0xFF && usage == 0x03) ||  // Apple vendor Fn
            (usage_page == 0xFF && usage == 0x05) ||  // Alt Apple Fn
            (usage_page == 0x01 && usage == 0x06) ||  // Generic desktop
            (usage_page == 0x07 && usage == 0x00) ||  // Keyboard page
            (usage_page == 0x0C && usage == 0x00);    // Consumer page
        
        if is_fn_key {
            let pressed = int_value != 0;
            // Check if Control key is held for agent mode
            let flags = unsafe { CGEventSourceFlagsState(K_CG_EVENT_SOURCE_STATE_COMBINED_SESSION_STATE) };
            let control_held = (flags & (1u64 << 18)) != 0; // kCGEventFlagMaskControl
            handle_fn_key(pressed, control_held);
        }
    }
    
    fn handle_fn_key(pressed: bool, _control_held: bool) {
        let was_recording = IS_RECORDING.load(Ordering::SeqCst);
        
        if pressed && !was_recording {
            IS_RECORDING.store(true, Ordering::SeqCst);
            
            // Remember where the user was typing so we can restore focus before pasting.
            let pid = capture_frontmost_pid();
            FRONTMOST_PID.store(pid, Ordering::SeqCst);
            log_line(&format!("Captured frontmost pid={pid}"));

            // Capture the focused UI element (critical for apps like Cursor where PID isn't enough).
            if let Some(app) = APP_HANDLE.get().cloned() {
                let app_clone = app.clone();
                let _ = app.run_on_main_thread(move || {
                    let cell = FOCUSED_AX_ELEM.get_or_init(|| Mutex::new(None));
                    let fp_cell = FOCUSED_AX_FINGERPRINT.get_or_init(|| Mutex::new(None));
                    // Release old
                    if let Ok(mut g) = cell.lock() {
                        if let Some(old) = *g {
                            unsafe { CFRelease(old as *const c_void) };
                        }
                        *g = capture_focused_ax_element();
                    }
                    
                    if let Ok(mut fp) = fp_cell.lock() {
                        *fp = cell
                            .lock()
                            .ok()
                            .and_then(|g| g.map(|u| u as *mut c_void))
                            .and_then(|e| focused_fingerprint(e));
                    }
                    
                    // Start in "pending" state - frontend shows neutral color
                    if let Some(w) = app_clone.get_webview_window("main") {
                        let _ = w.eval("window.__setMode && window.__setMode('typing')");
                    }
                    
                    log_line("Captured AX focused element (best effort)");
                });
            }
            log_line("Fn pressed - start recording");
            
            // Reset to typing mode at start of each recording
            IS_TEXT_INPUT_MODE.store(true, Ordering::SeqCst);
            
            // Immediately set mode to typing (red bar) - don't wait for async
            if let Some(app) = APP_HANDLE.get().cloned() {
                let app_clone = app.clone();
                let _ = app.run_on_main_thread(move || {
                    if let Some(w) = app_clone.get_webview_window("main") {
                        let _ = w.eval("window.__setMode && window.__setMode('typing')");
                    }
                });
            }

            // Watchdog: monitor for Ctrl (switch to agent) and Fn release
            std::thread::spawn(|| {
                let max_ms = 60_000u64; // 60 seconds max recording
                let start = std::time::Instant::now();
                let control_flag: u64 = 1u64 << 18;
                
                loop {
                    std::thread::sleep(std::time::Duration::from_millis(25));
                    if !IS_RECORDING.load(Ordering::SeqCst) {
                        break;
                    }
                    
                    let elapsed_ms = start.elapsed().as_millis() as u64;
                    let flags = unsafe { CGEventSourceFlagsState(K_CG_EVENT_SOURCE_STATE_COMBINED_SESSION_STATE) };
                    let fn_down = (flags & K_CG_EVENT_FLAG_MASK_SECONDARY_FN) != 0;
                    let control_down = (flags & control_flag) != 0;
                    
                    // Switch to agent mode while Ctrl is held
                    if control_down && IS_TEXT_INPUT_MODE.load(Ordering::SeqCst) {
                        IS_TEXT_INPUT_MODE.store(false, Ordering::SeqCst);
                        log_line("Control pressed -> agent mode");
                        
                        // Update frontend
                        if let Some(app) = APP_HANDLE.get().cloned() {
                            let app_clone = app.clone();
                            let _ = app.run_on_main_thread(move || {
                                if let Some(w) = app_clone.get_webview_window("main") {
                                    let _ = w.eval("window.__setMode && window.__setMode('agent')");
                                }
                            });
                        }
                    }
                    
                    if !fn_down {
                        // Force stop (idempotent)
                        handle_fn_key(false, false);
                        break;
                    }
                    if elapsed_ms > max_ms {
                        log_line("Fn watchdog timeout - forcing stop");
                        handle_fn_key(false, false);
                        break;
                    }
                }
            });

            // Update UI immediately, and start native capture.
            trigger_window_action("startRecording");
            if let Some(app) = APP_HANDLE.get().cloned() {
                let app2 = app.clone();
                let _ = app.run_on_main_thread(move || {
                    if let Some(w) = app2.get_webview_window("main") {
                        let _ = w.eval("window.__setProcessing && window.__setProcessing(false)");
                    }
                });
            }
            if let Err(e) = start_native_recording() {
                log_line(&format!("ERROR: start_native_recording: {e}"));
            }
        } else if !pressed && was_recording {
            IS_RECORDING.store(false, Ordering::SeqCst);
            log_line("Fn released - stop recording");
            // Stop capture and run transcription off-thread.
            trigger_window_action("stopRecording");
            if let Some(app) = APP_HANDLE.get().cloned() {
                let app2 = app.clone();
                let _ = app.run_on_main_thread(move || {
                    if let Some(w) = app2.get_webview_window("main") {
                        let _ = w.eval("window.__setProcessing && window.__setProcessing(true)");
                    }
                });
            }
            // Reset cancellation flag when starting new processing
            IS_CANCELLING.store(false, Ordering::SeqCst);
            
            let app = APP_HANDLE.get().cloned();
            std::thread::spawn(move || {
                // Always clear processing on exit, even if we early-return.
                struct ClearProcessing(Option<AppHandle>);
                impl Drop for ClearProcessing {
                    fn drop(&mut self) {
                        if let Some(app) = self.0.take() {
                            let app2 = app.clone();
                            let _ = app.run_on_main_thread(move || {
                                if let Some(w) = app2.get_webview_window("main") {
                                    let _ = w.eval("window.__setProcessing && window.__setProcessing(false)");
                                }
                            });
                        }
                        // Reset cancellation flag when processing ends
                        IS_CANCELLING.store(false, Ordering::SeqCst);
                    }
                }

                let _clear = ClearProcessing(app.clone());

                let (samples, in_rate) = match stop_native_recording_blocking() {
                    Ok(v) => v,
                    Err(e) => {
                        log_line(&format!("ERROR: stop_native_recording: {e}"));
                        return;
                    }
                };
                // Basic gate: skip very short recordings
                let dur_ms = (samples.len() as f64) * 1000.0 / (in_rate as f64);
                log_line(&format!("Captured audio: {} samples @{}Hz ({dur_ms:.0}ms)", samples.len(), in_rate));
                if dur_ms < 350.0 {
                    log_line("Skipping transcription: too short");
                    return;
                }

                let samples_16k = normalize_audio(resample_to_16k_linear(&samples, in_rate));
                let (rms, peak) = audio_stats(&samples_16k);
                if rms < 0.006 && peak < 0.04 {
                    log_line("Skipping transcription: too quiet (likely silence)");
                    return;
                }
                let text = match transcribe_samples(&samples_16k) {
                    Ok(t) => t,
                    Err(e) => {
                        log_line(&format!("ERROR: transcribe_samples: {e}"));
                        String::new()
                    }
                };
                let text = text.trim().to_string();
                if text.is_empty() || text.contains("[BLANK") {
                    log_line("Skipping paste (blank transcription)");
                } else {
                    #[cfg(target_os = "macos")]
                    {
                        let Some(app_unwrapped) = app.clone() else {
                            log_line("Skipping paste: no app handle");
                            return;
                        };

                        if !strict_focus_ok(&app_unwrapped) {
                            // Critical: do NOT touch clipboard, do NOT paste, do NOT try to restore focus.
                            log_line("Skipping paste: focus moved");
                            return;
                        }
                        
                        if IS_TEXT_INPUT_MODE.load(Ordering::SeqCst) {
                            // Typing mode: save clipboard, paste, restore
                            let original = get_clipboard_macos();
                            let text_with_space = format!("{text} ");
                            set_clipboard_macos(&text_with_space);
                            paste_text();
                            std::thread::sleep(std::time::Duration::from_millis(80));
                            if let Some(orig) = original {
                                set_clipboard_macos(&orig);
                            }
                            log_line(&format!("Pasted native text len={} (clipboard preserved)", text.len()));
                            update_stats(app_unwrapped.clone(), text.clone(), dur_ms);
                            
                            // Log transcription to history
                            let _ = save_history_entry(
                                app_unwrapped.clone(),
                                "transcription".to_string(),
                                serde_json::json!({
                                    "text": text,
                                    "mode": "typing"
                                })
                            );
                        } else {
                            // Agent mode: check for MCP servers first
                            log_line(&format!("Agent mode: calling API with '{}'", text));
                            
                            // Check if cancelled before starting
                            if IS_CANCELLING.load(Ordering::SeqCst) {
                                log_line("Processing cancelled before API call");
                                return;
                            }
                            
                            let selected_model = get_selected_model(&app_unwrapped);
                            let mcp_result = if let Some((servers, key)) = get_mcp_config(&app_unwrapped) {
                                log_line(&format!("MCP servers configured ({}), using MCP agent", servers.len()));
                                Some(call_mcp_agent_api(&text, servers, key, &selected_model, Some(&app_unwrapped)))
                            } else {
                                log_line("No MCP servers configured, falling back to AppleScript agent");
                                None
                            };
                            
                            // Check if cancelled after API call
                            if IS_CANCELLING.load(Ordering::SeqCst) {
                                log_line("Processing cancelled after API call");
                                return;
                            }
                            
                            match mcp_result {
                                Some(Ok(response)) => {
                                    // Check if cancelled after API response
                                    if IS_CANCELLING.load(Ordering::SeqCst) {
                                        log_line("Processing cancelled after API response - skipping result");
                                        return;
                                    }
                                    
                                    if response.success {
                                        // Log tool calls if any
                                        if let Some(tool_calls) = &response.tool_calls {
                                            if !tool_calls.is_empty() {
                                                log_line(&format!("MCP Agent: {} tool(s) executed", tool_calls.len()));
                                                for (i, call) in tool_calls.iter().enumerate() {
                                                    if let Some(tool_name) = call.get("toolName").and_then(|v| v.as_str()) {
                                                        log_line(&format!("  Tool {}: {}", i + 1, tool_name));
                                                    }
                                                }
                                            }
                                        }
                                        
                                        if let Some(response_text) = response.text {
                                            log_line(&format!("MCP Agent response: {}", response_text));
                                            
                                            // Build notification message with tool info
                                            let mut msg = String::new();
                                            if let Some(tool_calls) = &response.tool_calls {
                                                if !tool_calls.is_empty() {
                                                    let tool_names: Vec<String> = tool_calls.iter()
                                                        .filter_map(|call| call.get("toolName").and_then(|v| v.as_str()).map(|s| s.to_string()))
                                                        .collect();
                                                    if !tool_names.is_empty() {
                                                        msg.push_str(&format!("Used: {}. ", tool_names.join(", ")));
                                                    }
                                                }
                                            }
                                            
                                            // Always paste the response
                                            let original = get_clipboard_macos();
                                            set_clipboard_macos(&response_text);
                                            paste_text();
                                            std::thread::sleep(std::time::Duration::from_millis(80));
                                            if let Some(orig) = original {
                                                set_clipboard_macos(&orig);
                                            }
                                            
                                            // Show notification with tool info
                                            if msg.is_empty() {
                                                show_notification("t2t", "Result pasted");
                                            } else {
                                                show_notification("t2t", &format!("{}Result pasted", msg));
                                            }
                                        } else if let Some(tool_calls) = &response.tool_calls {
                                            if !tool_calls.is_empty() {
                                                let tool_names: Vec<String> = tool_calls.iter()
                                                    .filter_map(|call| call.get("toolName").and_then(|v| v.as_str()).map(|s| s.to_string()))
                                                    .collect();
                                                show_notification("t2t", &format!("Executed: {}", tool_names.join(", ")));
                                            }
                                        }
                                        update_stats(app_unwrapped.clone(), text.clone(), dur_ms);
                                    } else {
                                        let err = response.error.unwrap_or_else(|| "Unknown error".to_string());
                                        log_line(&format!("MCP Agent: API error: {}", err));
                                        show_notification("t2t", &format!("Error: {}", err));
                                    }
                                }
                                Some(Err(e)) => {
                                    log_line(&format!("MCP Agent: API call failed: {}", e));
                                    show_notification("t2t", &format!("API error: {}", e));
                                }
                                None => {
                                    // Fallback to local AppleScript agent
                                    log_line("No MCP servers configured, using local AppleScript agent");
                                    
                                    // Get OpenRouter key for AppleScript generation
                                    let openrouter_key = if let Ok(key_store) = app_unwrapped.store("openrouter-key") {
                                        key_store.get("key")
                                            .and_then(|v| v.as_str().map(|s| s.to_string()))
                                            .filter(|k| !k.is_empty())
                                    } else {
                                        None
                                    };
                                    
                                    let openrouter_key = openrouter_key.or_else(|| {
                                        std::env::var("OPENROUTER_API_KEY").ok()
                                    }).filter(|k| !k.is_empty());
                                    
                                    // Check if cancelled before AppleScript agent call
                                    if IS_CANCELLING.load(Ordering::SeqCst) {
                                        log_line("Processing cancelled before AppleScript agent call");
                                        return;
                                    }
                                    
                                    let selected_model = get_selected_model(&app_unwrapped);
                                    match openrouter_key {
                                        Some(key) => {
                                            match call_applescript_agent_local(&text, &key, &selected_model, Some(&app_unwrapped)) {
                                                Ok(response) => {
                                                    // Check if cancelled after AppleScript agent call
                                                    if IS_CANCELLING.load(Ordering::SeqCst) {
                                                        log_line("Processing cancelled after AppleScript agent call - skipping execution");
                                                        return;
                                                    }
                                                    
                                                    if response.success {
                                                        if let Some(script) = response.script {
                                                            // Check again before executing script
                                                            if IS_CANCELLING.load(Ordering::SeqCst) {
                                                                log_line("Processing cancelled before script execution");
                                                                return;
                                                            }
                                                            log_line(&format!("Agent: executing script: {}", script));
                                                            match execute_applescript(&script) {
                                                                Ok(output) => {
                                                                    log_line(&format!("Agent: script succeeded: {}", output));
                                                                    show_notification("t2t", "Done");
                                                                }
                                                                Err(e) => {
                                                                    log_line(&format!("Agent: script failed: {}", e));
                                                                    show_notification("t2t", &format!("Script error: {}", e));
                                                                }
                                                            }
                                                        }
                                                        update_stats(app_unwrapped.clone(), text.clone(), dur_ms);
                                                    } else if response.blocked == Some(true) {
                                                        log_line("Agent: script blocked by safety filter");
                                                        show_notification("t2t", "Action blocked for safety");
                                                    } else {
                                                        let err = response.error.unwrap_or_else(|| "Unknown error".to_string());
                                                        log_line(&format!("Agent: error: {}", err));
                                                        show_notification("t2t", &format!("Error: {}", err));
                                                    }
                                                }
                                                Err(e) => {
                                                    log_line(&format!("Agent: AppleScript generation failed: {}", e));
                                                    show_notification("t2t", &format!("Error: {}", e));
                                                }
                                            }
                                        }
                                        None => {
                                            log_line("Agent: No OpenRouter API key found");
                                            show_notification("t2t", "OpenRouter API key required for agent mode");
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            });
        }
    }
    
    fn trigger_window_action(action: &str) {
        if let Some(app) = APP_HANDLE.get() {
            let app = app.clone();
            let app2 = app.clone();
            let js = format!("window.__{} && window.__{}()", action, action);
            let _ = app.run_on_main_thread(move || {
                if let Some(window) = app2.get_webview_window("main") {
                    // Do NOT steal focus. We want the user's current app/field to keep focus.
                    match window.eval(&js) {
                        Ok(_) => log_line(&format!("eval ok: {js}")),
                        Err(e) => log_line(&format!("eval ERROR: {e} (js={js})")),
                    }
                } else {
                    log_line("eval skipped: main window not found");
                }
            });
        }
    }
}

fn resample_to_16k_linear(input: &[f32], in_rate: u32) -> Vec<f32> {
    if in_rate == 16_000 {
        return input.to_vec();
    }
    let out_rate = 16_000u32;
    let ratio = out_rate as f64 / in_rate as f64;
    let out_len = ((input.len() as f64) * ratio).round().max(1.0) as usize;
    let mut out = Vec::with_capacity(out_len);
    for i in 0..out_len {
        let src_pos = (i as f64) / ratio;
        let idx = src_pos.floor() as usize;
        let frac = src_pos - (idx as f64);
        let s0 = input.get(idx).copied().unwrap_or(0.0);
        let s1 = input.get(idx + 1).copied().unwrap_or(s0);
        out.push((s0 as f64 + ((s1 - s0) as f64 * frac)) as f32);
    }
    out
}

fn init_audio_thread() -> Result<(), String> {
    if AUDIO_TX.get().is_some() {
        return Ok(());
    }

    let (tx, rx) = mpsc::channel::<AudioCmd>();
    AUDIO_TX
        .set(tx)
        .map_err(|_| "AUDIO_TX already initialized".to_string())?;

    // Channel for volume levels (from audio callback to throttled sender)
    let (vol_tx, vol_rx) = mpsc::channel::<f32>();
    VOLUME_LEVEL_TX
        .set(vol_tx)
        .map_err(|_| "VOLUME_LEVEL_TX already initialized".to_string())?;

    // Throttled sender thread: sends volume updates to frontend at ~25Hz
    let app_handle_for_vol = APP_HANDLE.get().cloned();
    std::thread::spawn(move || {
        let mut last_send = std::time::Instant::now();
        let min_interval = std::time::Duration::from_millis(40); // ~25Hz max
        let mut last_level = 0.0f32;

        for level in vol_rx.iter() {
            let now = std::time::Instant::now();
            if now.duration_since(last_send) >= min_interval {
                // Only send if level changed meaningfully (avoid spam)
                if (level - last_level).abs() > 0.005 {
                    if let Some(app) = app_handle_for_vol.as_ref() {
                        let app = app.clone();
                        let app2 = app.clone();
                        let level_val = level;
                        let _ = app.run_on_main_thread(move || {
                            if let Some(w) = app2.get_webview_window("main") {
                                let js = format!("window.__setLevel && window.__setLevel({})", level_val);
                                let _ = w.eval(&js);
                            }
                        });
                    }
                    last_level = level;
                    last_send = now;
                }
            }
        }
    });

    std::thread::spawn(move || {
        let host = cpal::default_host();
        
        // Helper to find an available input device
        let find_input_device = || -> Option<cpal::Device> {
            // Try default first
            if let Some(dev) = host.default_input_device() {
                if dev.default_input_config().is_ok() {
                    return Some(dev);
                }
            }
            // Fallback: enumerate all input devices
            if let Ok(devices) = host.input_devices() {
                for device in devices {
                    if device.default_input_config().is_ok() {
                        return Some(device);
                    }
                }
            }
            None
        };

        let mut device = match find_input_device() {
            Some(d) => d,
            None => {
                log_line("ERROR: No available input device (cpal)");
                return;
            }
        };

        let mut input_cfg = match device.default_input_config() {
            Ok(c) => c,
            Err(e) => {
                log_line(&format!("ERROR: default_input_config: {e}"));
                return;
            }
        };

        let mut channels = input_cfg.channels();
        let mut sample_rate = input_cfg.sample_rate().0;
        let mut sample_format = input_cfg.sample_format();

        log_line(&format!(
            "Audio thread ready: device='{}' rate={} channels={} fmt={:?}",
            device.name().unwrap_or_else(|_| "<unknown>".into()),
            sample_rate,
            channels,
            sample_format
        ));

        let samples_mono: Arc<Mutex<Vec<f32>>> = Arc::new(Mutex::new(Vec::new()));
        // Rolling buffer for volume metering (~100ms at typical sample rates)
        let volume_buffer: Arc<Mutex<Vec<f32>>> = Arc::new(Mutex::new(Vec::new()));
        let mut stream: Option<cpal::Stream> = None;

        let err_fn = |err| log_line(&format!("cpal stream error: {err}"));

        for cmd in rx.iter() {
            match cmd {
                AudioCmd::Start => {
                    // Stop any existing stream.
                    stream.take();
                    {
                        let mut buf = samples_mono.lock().unwrap();
                        buf.clear();
                    }
                    {
                        let mut vol_buf = volume_buffer.lock().unwrap();
                        vol_buf.clear();
                    }

                    // Try to refresh device if current one fails
                    let mut device_updated = false;
                    match device.default_input_config() {
                        Ok(c) => {
                            sample_rate = c.sample_rate().0;
                        }
                        Err(_) => {
                            // Current device is invalid, try to find a new one
                            if let Some(new_device) = find_input_device() {
                                if let Ok(new_cfg) = new_device.default_input_config() {
                                    device = new_device;
                                    input_cfg = new_cfg;
                                    channels = input_cfg.channels();
                                    sample_rate = input_cfg.sample_rate().0;
                                    sample_format = input_cfg.sample_format();
                                    device_updated = true;
                                    log_line(&format!(
                                        "Switched to new audio device: '{}'",
                                        device.name().unwrap_or_else(|_| "<unknown>".into())
                                    ));
                                }
                            }
                        }
                    }

                    let cfg: cpal::StreamConfig = input_cfg.clone().into();
                    let samples_cb = samples_mono.clone();
                    let vol_buf_cb = volume_buffer.clone();
                    // Get volume channel sender (must be initialized by now)
                    let vol_tx_cb = VOLUME_LEVEL_TX.get().cloned().expect("VOLUME_LEVEL_TX not initialized");
                    // Target ~100ms window for RMS (adjust based on sample rate)
                    let window_samples = (sample_rate as f64 * 0.1).ceil() as usize;

                    let built = match sample_format {
                        cpal::SampleFormat::I16 => device.build_input_stream(
                            &cfg,
                            move |data: &[i16], _| {
                                let mut out = samples_cb.lock().unwrap();
                                let mut vol_buf = vol_buf_cb.lock().unwrap();
                                
                                // Convert to mono f32 and accumulate
                                let mut mono_samples = Vec::with_capacity(data.len() / channels as usize);
                                if channels == 1 {
                                    for &s in data {
                                        let sample = (s as f32) / 32768.0;
                                        out.push(sample);
                                        mono_samples.push(sample);
                                    }
                                } else {
                                    for frame in data.chunks_exact(channels as usize) {
                                        let sum: i32 = frame.iter().map(|&v| v as i32).sum();
                                        let avg = (sum as f32) / (channels as f32);
                                        let sample = avg / 32768.0;
                                        out.push(sample);
                                        mono_samples.push(sample);
                                    }
                                }
                                
                                // Update rolling volume buffer
                                vol_buf.extend(mono_samples);
                                if vol_buf.len() > window_samples {
                                    let excess = vol_buf.len() - window_samples;
                                    vol_buf.drain(0..excess);
                                }
                                
                                // Compute RMS over rolling window
                                if !vol_buf.is_empty() {
                                    let sum_sq: f64 = vol_buf.iter().map(|&s| (s as f64) * (s as f64)).sum();
                                    let rms = (sum_sq / vol_buf.len() as f64).sqrt() as f32;
                                    // Normalize: map RMS to [0,1] with reasonable scaling
                                    // Make it punchier: curve + higher gain so quiet speech visibly moves the bar.
                                    // level ~= sqrt(clamp(rms * gain, 0..1))
                                    let normalized = ((rms * 10.0).min(1.0)).sqrt();
                                    let _ = vol_tx_cb.send(normalized);
                                }
                            },
                            err_fn,
                            None,
                        ),
                        cpal::SampleFormat::F32 => device.build_input_stream(
                            &cfg,
                            move |data: &[f32], _| {
                                let mut out = samples_cb.lock().unwrap();
                                let mut vol_buf = vol_buf_cb.lock().unwrap();
                                
                                // Convert to mono and accumulate
                                let mut mono_samples = Vec::with_capacity(data.len() / channels as usize);
                                if channels == 1 {
                                    out.extend_from_slice(data);
                                    mono_samples.extend_from_slice(data);
                                } else {
                                    for frame in data.chunks_exact(channels as usize) {
                                        let sum: f32 = frame.iter().copied().sum();
                                        let sample = sum / (channels as f32);
                                        out.push(sample);
                                        mono_samples.push(sample);
                                    }
                                }
                                
                                // Update rolling volume buffer
                                vol_buf.extend(mono_samples);
                                if vol_buf.len() > window_samples {
                                    let excess = vol_buf.len() - window_samples;
                                    vol_buf.drain(0..excess);
                                }
                                
                                // Compute RMS over rolling window
                                if !vol_buf.is_empty() {
                                    let sum_sq: f64 = vol_buf.iter().map(|&s| (s as f64) * (s as f64)).sum();
                                    let rms = (sum_sq / vol_buf.len() as f64).sqrt() as f32;
                                    // Make it punchier: curve + higher gain so quiet speech visibly moves the bar.
                                    let normalized = ((rms * 10.0).min(1.0)).sqrt();
                                    let _ = vol_tx_cb.send(normalized);
                                }
                            },
                            err_fn,
                            None,
                        ),
                        fmt => {
                            log_line(&format!("ERROR: Unsupported sample format: {fmt:?}"));
                            continue;
                        }
                    };

                    match built {
                        Ok(s) => {
                            if let Err(e) = s.play() {
                                log_line(&format!("ERROR: stream.play: {e}"));
                            } else {
                                log_line("Native mic recording started");
                            }
                            stream = Some(s);
                        }
                        Err(e) => {
                            log_line(&format!("ERROR: build_input_stream: {e}"));
                            // Device disconnected, try to find a new one and retry
                            if !device_updated {
                                if let Some(new_device) = find_input_device() {
                                    if let Ok(new_cfg) = new_device.default_input_config() {
                                        device = new_device;
                                        input_cfg = new_cfg;
                                        channels = input_cfg.channels();
                                        sample_rate = input_cfg.sample_rate().0;
                                        sample_format = input_cfg.sample_format();
                                        log_line(&format!(
                                            "Reconnected to audio device: '{}', retrying...",
                                            device.name().unwrap_or_else(|_| "<unknown>".into())
                                        ));
                                        
                                        // Retry building stream with new device
                                        let retry_cfg: cpal::StreamConfig = input_cfg.clone().into();
                                        let retry_samples_cb = samples_mono.clone();
                                        let retry_vol_buf_cb = volume_buffer.clone();
                                        let retry_vol_tx_cb = VOLUME_LEVEL_TX.get().cloned().expect("VOLUME_LEVEL_TX not initialized");
                                        let retry_window_samples = (sample_rate as f64 * 0.1).ceil() as usize;
                                        
                                        let retry_built = match sample_format {
                                            cpal::SampleFormat::I16 => device.build_input_stream(
                                                &retry_cfg,
                                                move |data: &[i16], _| {
                                                    let mut out = retry_samples_cb.lock().unwrap();
                                                    let mut vol_buf = retry_vol_buf_cb.lock().unwrap();
                                                    let mut mono_samples = Vec::with_capacity(data.len() / channels as usize);
                                                    if channels == 1 {
                                                        for &s in data {
                                                            let sample = (s as f32) / 32768.0;
                                                            out.push(sample);
                                                            mono_samples.push(sample);
                                                        }
                                                    } else {
                                                        for frame in data.chunks_exact(channels as usize) {
                                                            let sum: i32 = frame.iter().map(|&v| v as i32).sum();
                                                            let avg = (sum as f32) / (channels as f32);
                                                            let sample = avg / 32768.0;
                                                            out.push(sample);
                                                            mono_samples.push(sample);
                                                        }
                                                    }
                                                    vol_buf.extend(mono_samples);
                                                    if vol_buf.len() > retry_window_samples {
                                                        let excess = vol_buf.len() - retry_window_samples;
                                                        vol_buf.drain(0..excess);
                                                    }
                                                    if !vol_buf.is_empty() {
                                                        let sum_sq: f64 = vol_buf.iter().map(|&s| (s as f64) * (s as f64)).sum();
                                                        let rms = (sum_sq / vol_buf.len() as f64).sqrt() as f32;
                                                        let normalized = ((rms * 10.0).min(1.0)).sqrt();
                                                        let _ = retry_vol_tx_cb.send(normalized);
                                                    }
                                                },
                                                err_fn,
                                                None,
                                            ),
                                            cpal::SampleFormat::F32 => device.build_input_stream(
                                                &retry_cfg,
                                                move |data: &[f32], _| {
                                                    let mut out = retry_samples_cb.lock().unwrap();
                                                    let mut vol_buf = retry_vol_buf_cb.lock().unwrap();
                                                    let mut mono_samples = Vec::with_capacity(data.len() / channels as usize);
                                                    if channels == 1 {
                                                        out.extend_from_slice(data);
                                                        mono_samples.extend_from_slice(data);
                                                    } else {
                                                        for frame in data.chunks_exact(channels as usize) {
                                                            let sum: f32 = frame.iter().copied().sum();
                                                            let sample = sum / (channels as f32);
                                                            out.push(sample);
                                                            mono_samples.push(sample);
                                                        }
                                                    }
                                                    vol_buf.extend(mono_samples);
                                                    if vol_buf.len() > retry_window_samples {
                                                        let excess = vol_buf.len() - retry_window_samples;
                                                        vol_buf.drain(0..excess);
                                                    }
                                                    if !vol_buf.is_empty() {
                                                        let sum_sq: f64 = vol_buf.iter().map(|&s| (s as f64) * (s as f64)).sum();
                                                        let rms = (sum_sq / vol_buf.len() as f64).sqrt() as f32;
                                                        let normalized = ((rms * 10.0).min(1.0)).sqrt();
                                                        let _ = retry_vol_tx_cb.send(normalized);
                                                    }
                                                },
                                                err_fn,
                                                None,
                                            ),
                                            _ => {
                                                log_line(&format!("ERROR: Unsupported sample format for retry: {sample_format:?}"));
                                                continue;
                                            }
                                        };
                                        
                                        match retry_built {
                                            Ok(s) => {
                                                if let Err(e) = s.play() {
                                                    log_line(&format!("ERROR: retry stream.play: {e}"));
                                                } else {
                                                    log_line("Native mic recording started (after reconnection)");
                                                }
                                                stream = Some(s);
                                            }
                                            Err(e) => {
                                                log_line(&format!("ERROR: retry build_input_stream failed: {e}"));
                                            }
                                        }
                                    }
                                } else {
                                    log_line("ERROR: No available input devices found");
                                }
                            }
                        }
                    }
                }
                AudioCmd::Stop { reply } => {
                    stream.take(); // drop to stop capture
                    {
                        let mut vol_buf = volume_buffer.lock().unwrap();
                        vol_buf.clear();
                    }
                    // Send zero level to reset UI
                    if let Some(tx) = VOLUME_LEVEL_TX.get() {
                        let _ = tx.send(0.0);
                    }
                    let samples = samples_mono.lock().unwrap().clone();
                    let _ = reply.send(Ok((samples, sample_rate)));
                    log_line("Native mic recording stopped");
                }
            }
        }
    });

    Ok(())
}

fn start_native_recording() -> Result<(), String> {
    let tx = AUDIO_TX.get().ok_or("Audio thread not initialized")?.clone();
    tx.send(AudioCmd::Start).map_err(|e| e.to_string())
}

fn stop_native_recording_blocking() -> Result<(Vec<f32>, u32), String> {
    let tx = AUDIO_TX.get().ok_or("Audio thread not initialized")?.clone();
    let (reply_tx, reply_rx) = mpsc::channel();
    tx.send(AudioCmd::Stop { reply: reply_tx })
        .map_err(|e| e.to_string())?;
    reply_rx.recv().map_err(|e| e.to_string())?
}

fn audio_stats(samples: &[f32]) -> (f32, f32) {
    // returns (rms, peak)
    if samples.is_empty() {
        return (0.0, 0.0);
    }
    let mut sum_sq: f64 = 0.0;
    let mut peak: f32 = 0.0;
    for &s in samples {
        let a = s.abs();
        if a > peak {
            peak = a;
        }
        sum_sq += (s as f64) * (s as f64);
    }
    let rms = (sum_sq / (samples.len() as f64)).sqrt() as f32;
    (rms, peak)
}

fn normalize_audio(mut samples: Vec<f32>) -> Vec<f32> {
    // Gentle auto-gain so whisper gets consistent input. Clamp to avoid blowing up noise.
    let (rms, peak) = audio_stats(&samples);
    log_line(&format!("Audio stats pre-norm: rms={rms:.5} peak={peak:.5}"));
    if rms <= 1e-6 {
        return samples;
    }
    let target_rms = 0.08f32;
    let mut gain = target_rms / rms;
    if gain.is_nan() || !gain.is_finite() {
        gain = 1.0;
    }
    gain = gain.clamp(0.5, 8.0);
    for s in &mut samples {
        *s = (*s * gain).clamp(-1.0, 1.0);
    }
    let (rms2, peak2) = audio_stats(&samples);
    log_line(&format!(
        "Audio stats post-norm: gain={gain:.3} rms={rms2:.5} peak={peak2:.5}"
    ));
    samples
}

fn transcribe_samples(samples_16k: &[f32]) -> Result<String, String> {
    if samples_16k.is_empty() {
        return Err("No samples".to_string());
    }
    let whisper = WHISPER.get().ok_or("Whisper not initialized")?;
    let ctx = whisper.lock().map_err(|e| e.to_string())?;

    let mut params = FullParams::new(SamplingStrategy::Greedy { best_of: 1 });
    params.set_print_special(false);
    params.set_print_progress(false);
    params.set_print_realtime(false);
    params.set_print_timestamps(false);
    params.set_language(Some("en"));
    params.set_n_threads(4);
    // Reduce hallucinations on low-signal audio
    params.set_no_context(true);
    params.set_suppress_blank(true);
    params.set_suppress_nst(true);
    params.set_logprob_thold(-0.8);
    params.set_no_speech_thold(0.6);

    let mut state = ctx.create_state().map_err(|e| format!("State error: {:?}", e))?;
    log_line(&format!("Running Whisper (native) on {} samples...", samples_16k.len()));
    state.full(params, samples_16k).map_err(|e| {
        log_line(&format!("Transcribe(native) error: {:?}", e));
        format!("Transcribe error: {:?}", e)
    })?;

    let num_segments = state.full_n_segments().map_err(|e| format!("Segment error: {:?}", e))?;
    let mut text = String::new();
    for i in 0..num_segments {
        if let Ok(segment) = state.full_get_segment_text(i) {
            text.push_str(&segment);
        }
    }
    let out = text.trim().to_string();
    log_line(&format!("Whisper(native) result: '{out}'"));
    Ok(out)
}

#[tauri::command]
fn transcribe(audio_data: Vec<u8>) -> Result<String, String> {
    log_line(&format!("Transcribe called with {} bytes", audio_data.len()));
    
    if audio_data.len() < 44 {
        return Err("WAV too short".to_string());
    }
    
    let pcm_data = &audio_data[44..];
    let samples: Vec<f32> = pcm_data
        .chunks_exact(2)
        .map(|b| i16::from_le_bytes([b[0], b[1]]) as f32 / 32768.0)
        .collect();
    
    log_line(&format!("Parsed {} samples from WAV", samples.len()));
    
    if samples.is_empty() {
        return Err("No audio samples".to_string());
    }
    
    let whisper = WHISPER.get().ok_or("Whisper not initialized")?;
    let ctx = whisper.lock().map_err(|e| e.to_string())?;
    
    let mut params = FullParams::new(SamplingStrategy::Greedy { best_of: 1 });
    params.set_print_special(false);
    params.set_print_progress(false);
    params.set_print_realtime(false);
    params.set_print_timestamps(false);
    params.set_language(Some("en"));
    params.set_n_threads(4);
    
    let mut state = ctx.create_state().map_err(|e| format!("State error: {:?}", e))?;
    log_line(&format!("Running Whisper on {} samples...", samples.len()));
    state.full(params, &samples).map_err(|e| {
        log_line(&format!("Transcribe error: {:?}", e));
        format!("Transcribe error: {:?}", e)
    })?;
    
    let num_segments = state.full_n_segments().map_err(|e| format!("Segment error: {:?}", e))?;
    let mut text = String::new();
    for i in 0..num_segments {
        if let Ok(segment) = state.full_get_segment_text(i) {
            text.push_str(&segment);
        }
    }
    
    log_line(&format!("Transcribed: '{}'", text.trim()));
    Ok(text.trim().to_string())
}

#[tauri::command]
fn paste_text() {
    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        Command::new("osascript")
            .args(["-e", r#"tell application "System Events" to keystroke "v" using command down"#])
            .output()
            .ok();
    }
}

#[cfg(target_os = "macos")]
fn get_clipboard_macos() -> Option<String> {
    use std::process::Command;
    Command::new("pbpaste")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
}

#[cfg(target_os = "macos")]
fn set_clipboard_macos(text: &str) {
    use std::io::Write;
    use std::process::{Command, Stdio};
    if let Ok(mut child) = Command::new("pbcopy").stdin(Stdio::piped()).spawn() {
        if let Some(stdin) = child.stdin.as_mut() {
            let _ = stdin.write_all(text.as_bytes());
        }
        let _ = child.wait();
    }
}
// Fetch available models from OpenRouter
#[tauri::command]
async fn fetch_openrouter_models(openrouter_key: String) -> Result<serde_json::Value, String> {
    let client = reqwest::Client::new();
    let response = client
        .get(OPENROUTER_MODELS_URL)
        .header("Authorization", format!("Bearer {}", openrouter_key))
        .header("HTTP-Referer", "https://github.com/acoyfellow/t2t")
        .header("X-Title", "t2t")
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| format!("Failed to fetch models: {e}"))?;
    
    if !response.status().is_success() {
        let status = response.status();
        let error_body = response.text().await.unwrap_or_else(|_| "Could not read error body".to_string());
        return Err(format!("OpenRouter returned {}: {}", status, error_body));
    }
    
    response.json::<serde_json::Value>()
        .await
        .map_err(|e| format!("Failed to parse models response: {e}"))
}

// Get OpenRouter key from store or env var
#[tauri::command]
fn get_openrouter_key(app: AppHandle) -> Option<String> {
    // Try store first
    if let Ok(key_store) = app.store("openrouter-key") {
        if let Some(key_val) = key_store.get("key") {
            if let Some(key_str) = key_val.as_str() {
                if !key_str.is_empty() {
                    return Some(key_str.to_string());
                }
            }
        }
    }
    
    // Fallback to env var
    std::env::var("OPENROUTER_API_KEY").ok().filter(|k| !k.is_empty())
}

// Set OpenRouter key in store
#[tauri::command]
fn set_openrouter_key(app: AppHandle, key: String) -> Result<(), String> {
    let store = app.store("openrouter-key")
        .map_err(|e| format!("Failed to open store: {e}"))?;
    store.set("key", key);
    store.save()
        .map_err(|e| format!("Failed to save store: {e}"))?;
    Ok(())
}

// Get theme from store, defaults to "system"
#[tauri::command]
fn get_theme(app: AppHandle) -> String {
    if let Ok(store) = app.store("theme") {
        if let Some(theme_val) = store.get("theme") {
            if let Some(theme_str) = theme_val.as_str() {
                if !theme_str.is_empty() {
                    return theme_str.to_string();
                }
            }
        }
    }
    "system".to_string()
}

// Set theme in store
#[tauri::command]
fn set_theme(app: AppHandle, theme: String) -> Result<(), String> {
    let store = app.store("theme")
        .map_err(|e| format!("Failed to open store: {e}"))?;
    store.set("theme", theme);
    store.save()
        .map_err(|e| format!("Failed to save store: {e}"))?;
    Ok(())
}

// Cancel ongoing processing (called when user presses Escape during processing)
#[tauri::command]
fn cancel_processing() {
    IS_CANCELLING.store(true, Ordering::SeqCst);
    log_line("Processing cancellation requested (Escape key pressed)");
}

// Save a history entry
#[tauri::command]
fn save_history_entry(app: AppHandle, entry_type: String, data: serde_json::Value) -> Result<(), String> {
    let store = app.store("history.json")
        .map_err(|e| format!("Failed to open history store: {e}"))?;
    
    // Get existing entries
    let mut entries: Vec<HistoryEntry> = if let Some(entries_val) = store.get("entries") {
        serde_json::from_value(entries_val.clone())
            .unwrap_or_else(|_| Vec::new())
    } else {
        Vec::new()
    };
    
    // Create new entry
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let id = now.as_millis().to_string();
    // Format timestamp as ISO 8601
    let timestamp = chrono::DateTime::<chrono::Utc>::from_timestamp(now.as_secs() as i64, now.subsec_nanos())
        .unwrap_or_else(|| chrono::Utc::now())
        .to_rfc3339();
    
    let entry = HistoryEntry {
        id: id.clone(),
        timestamp,
        entry_type: entry_type.clone(),
        data,
    };
    
    entries.push(entry);
    
    // Get limit from env var (default 1000)
    let limit: usize = std::env::var("T2T_HISTORY_LIMIT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1000);
    
    // Prune oldest entries if over limit
    if entries.len() > limit {
        entries.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
        entries.drain(0..(entries.len() - limit));
    }
    
    // Sort by timestamp (newest first) for display
    entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    
    // Save back to store
    store.set("entries", serde_json::to_value(&entries)
        .map_err(|e| format!("Failed to serialize entries: {e}"))?);
    store.save()
        .map_err(|e| format!("Failed to save history: {e}"))?;
    
    // Emit event to notify frontend of new history entry
    let _ = app.emit("history-updated", ());
    
    Ok(())
}

// Get all history entries
#[tauri::command]
fn get_history(app: AppHandle) -> Result<HistoryResponse, String> {
    let store = app.store("history.json")
        .map_err(|e| format!("Failed to open history store: {e}"))?;
    
    let entries: Vec<HistoryEntry> = if let Some(entries_val) = store.get("entries") {
        serde_json::from_value(entries_val.clone())
            .unwrap_or_else(|_| Vec::new())
    } else {
        Vec::new()
    };
    
    // Sort by timestamp (newest first)
    let mut sorted_entries = entries;
    sorted_entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    
    Ok(HistoryResponse {
        total: sorted_entries.len(),
        entries: sorted_entries,
    })
}

// Search history entries
#[tauri::command]
fn search_history(app: AppHandle, query: String) -> Result<HistoryResponse, String> {
    let store = app.store("history.json")
        .map_err(|e| format!("Failed to open history store: {e}"))?;
    
    let entries: Vec<HistoryEntry> = if let Some(entries_val) = store.get("entries") {
        serde_json::from_value(entries_val.clone())
            .unwrap_or_else(|_| Vec::new())
    } else {
        Vec::new()
    };
    
    let query_lower = query.to_lowercase();
    
    // Filter entries by search query
    let filtered: Vec<HistoryEntry> = entries.into_iter()
        .filter(|entry| {
            // Search in transcript/text fields
            if let Some(text) = entry.data.get("text").and_then(|v| v.as_str()) {
                if text.to_lowercase().contains(&query_lower) {
                    return true;
                }
            }
            if let Some(transcript) = entry.data.get("transcript").and_then(|v| v.as_str()) {
                if transcript.to_lowercase().contains(&query_lower) {
                    return true;
                }
            }
            // Search in model name
            if let Some(model) = entry.data.get("model").and_then(|v| v.as_str()) {
                if model.to_lowercase().contains(&query_lower) {
                    return true;
                }
            }
            false
        })
        .collect();
    
    // Sort by timestamp (newest first)
    let mut sorted_entries = filtered;
    sorted_entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    
    Ok(HistoryResponse {
        total: sorted_entries.len(),
        entries: sorted_entries,
    })
}

// Get system theme preference (macOS)
#[tauri::command]
fn get_system_theme() -> String {
    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        let output = Command::new("osascript")
            .args(["-e", r#"tell application "System Events" to tell appearance preferences to get dark mode"#])
            .output()
            .ok();
        
        if let Some(output) = output {
            if output.status.success() {
                if let Ok(result) = String::from_utf8(output.stdout) {
                    let trimmed = result.trim().to_lowercase();
                    if trimmed == "true" {
                        return "dark".to_string();
                    }
                }
            }
        }
    }
    "light".to_string()
}

/// Capture screenshot on macOS using screencapture command
/// 
/// This function captures the current screen and returns it as a base64-encoded PNG image
/// suitable for inclusion in OpenAI-compatible API requests. The screenshot is captured
/// to a temporary file, read into memory, then deleted.
/// 
/// # Returns
/// `Ok(String)` containing base64-encoded PNG data URI (format: "data:image/png;base64,...")
/// `Err(String)` if capture fails (e.g., permission denied, command not found)
/// 
/// # Requirements
/// - macOS screen recording permission (may prompt user on first use)
/// - `screencapture` command available (built into macOS)
#[cfg(target_os = "macos")]
fn capture_screenshot() -> Result<String, String> {
    use std::process::Command;
    use std::io::Read;
    
    // Create temporary file path
    let temp_path = std::env::temp_dir().join(format!("t2t_screenshot_{}.png", 
        SystemTime::now().duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()));
    
    let temp_path_str = temp_path.to_str()
        .ok_or("Failed to create temp path")?;
    
    // Capture screenshot to temp file (-x = no sound, -t png = PNG format)
    let output = Command::new("screencapture")
        .args(&["-x", "-t", "png", temp_path_str])
        .output()
        .map_err(|e| format!("Failed to execute screencapture: {e}"))?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("screencapture failed: {stderr}"));
    }
    
    // Read the image file (clone temp_path before moving)
    let temp_path_for_read = temp_path.clone();
    let mut file = std::fs::File::open(&temp_path_for_read)
        .map_err(|e| format!("Failed to open screenshot file: {e}"))?;
    
    let mut image_data = Vec::new();
    file.read_to_end(&mut image_data)
        .map_err(|e| format!("Failed to read screenshot: {e}"))?;
    
    // Clean up temp file
    let _ = std::fs::remove_file(temp_path);
    
    // Encode to base64 using Engine trait (base64 0.21+)
    use base64::{Engine as _, engine::general_purpose};
    let base64_data = general_purpose::STANDARD.encode(&image_data);
    
    Ok(format!("data:image/png;base64,{}", base64_data))
}

// Placeholder for non-macOS platforms
#[cfg(not(target_os = "macos"))]
fn capture_screenshot() -> Result<String, String> {
    Err("Screenshot capture not implemented for this platform".to_string())
}

/// Create a thumbnail from a base64-encoded PNG image
/// 
/// Resizes the image to a maximum of 150x150 pixels while maintaining aspect ratio.
/// Returns a base64-encoded data URI suitable for storage in history.
/// 
/// # Arguments
/// * `base64_data_uri` - Base64-encoded PNG data URI (format: "data:image/png;base64,...")
/// 
/// # Returns
/// `Ok(Some(String))` containing thumbnail as base64 data URI, or `Ok(None)` if processing fails
fn create_thumbnail(base64_data_uri: &str) -> Result<Option<String>, String> {
    // Extract base64 data from data URI
    let base64_data = if base64_data_uri.starts_with("data:image/png;base64,") {
        &base64_data_uri[22..]
    } else {
        base64_data_uri
    };
    
    // Decode base64
    use base64::{Engine as _, engine::general_purpose};
    let image_bytes = general_purpose::STANDARD.decode(base64_data)
        .map_err(|e| format!("Failed to decode base64: {e}"))?;
    
    // Decode PNG
    let img = image::load_from_memory(&image_bytes)
        .map_err(|e| format!("Failed to decode image: {e}"))?;
    
    // Resize to max 150x150 maintaining aspect ratio
    let thumbnail = img.thumbnail(150, 150);
    
    // Encode back to PNG
    let mut thumbnail_bytes = Vec::new();
    {
        let encoder = image::codecs::png::PngEncoder::new(&mut thumbnail_bytes);
        #[allow(deprecated)]
        encoder.encode(
            thumbnail.as_bytes(),
            thumbnail.width(),
            thumbnail.height(),
            thumbnail.color(),
        ).map_err(|e| format!("Failed to encode thumbnail: {e}"))?;
    }
    
    // Encode to base64 data URI
    let thumbnail_base64 = general_purpose::STANDARD.encode(&thumbnail_bytes);
    Ok(Some(format!("data:image/png;base64,{}", thumbnail_base64)))
}

// Get selected model from store, env var, or default
fn get_selected_model(app: &AppHandle) -> String {
    // Try store first
    if let Ok(store) = app.store("model") {
        if let Some(model_val) = store.get("model") {
            if let Some(model_str) = model_val.as_str() {
                if !model_str.is_empty() {
                    return model_str.to_string();
                }
            }
        }
    }
    
    // Try env var
    if let Ok(model) = std::env::var("OPENROUTER_MODEL") {
        if !model.is_empty() {
            return model;
        }
    }
    
    // Default
    "openai/gpt-5-nano".to_string()
}

// MCP Tools Discovery: Runs locally in Tauri
// Why local? stdio transport spawns processes (e.g., `npx @modelcontextprotocol/server-cloudflare-docs`)
// This is impossible in Cloudflare Workers, so we implement JSON-RPC client in Rust
// Works in both dev and production builds since it's native code
async fn fetch_mcp_tools_stdio(
    command: &str,
    args: &[String],
) -> Result<MCPToolsResponse, String> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::process::Command as TokioCommand;

    let mut child = TokioCommand::new(command)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn process: {e}"))?;

    let mut stdin = child.stdin.take().ok_or("Failed to open stdin")?;
    let stdout = child.stdout.take().ok_or("Failed to open stdout")?;
    let mut reader = BufReader::new(stdout);

    // Initialize MCP connection
    let init_request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "t2t",
                "version": "0.2.5"
            }
        }
    });

    stdin
        .write_all(format!("{}\n", init_request).as_bytes())
        .await
        .map_err(|e| format!("Failed to write init: {e}"))?;
    stdin.flush().await.map_err(|e| format!("Failed to flush: {e}"))?;

    // Read initialize response
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .await
        .map_err(|e| format!("Failed to read init response: {e}"))?;

    let init_response: serde_json::Value = serde_json::from_str(&line)
        .map_err(|e| format!("Invalid init response: {e}"))?;

    if init_response.get("error").is_some() {
        return Err(format!("Initialize error: {}", init_response["error"]));
    }

    // Send initialized notification
    let initialized_notification = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    });
    stdin
        .write_all(format!("{}\n", initialized_notification).as_bytes())
        .await
        .map_err(|e| format!("Failed to write initialized: {e}"))?;
    stdin.flush().await.map_err(|e| format!("Failed to flush: {e}"))?;

    // Call tools/list
    let tools_request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list"
    });
    stdin
        .write_all(format!("{}\n", tools_request).as_bytes())
        .await
        .map_err(|e| format!("Failed to write tools/list: {e}"))?;
    stdin.flush().await.map_err(|e| format!("Failed to flush: {e}"))?;

    line.clear();
    reader
        .read_line(&mut line)
        .await
        .map_err(|e| format!("Failed to read tools response: {e}"))?;

    let tools_response: serde_json::Value = serde_json::from_str(&line)
        .map_err(|e| format!("Invalid tools response: {e}"))?;

    let mut tools = Vec::new();
    let mut prompts = Vec::new();
    let mut prompts_count = 0;
    let mut resources_count = 0;

    if let Some(result) = tools_response.get("result") {
        if let Some(tools_obj) = result.get("tools") {
            // MCP returns tools as an array
            if let Some(tools_array) = tools_obj.as_array() {
                for tool_def in tools_array {
                    tools.push(MCPTool {
                        name: tool_def
                            .get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        description: tool_def
                            .get("description")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        input_schema: tool_def.get("inputSchema").cloned().unwrap_or_default(),
                    });
                }
            }
        }
    }

    // Try to get prompts
    let prompts_request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "prompts/list"
    });
    stdin
        .write_all(format!("{}\n", prompts_request).as_bytes())
        .await
        .ok();
    stdin.flush().await.ok();
    line.clear();
    if reader.read_line(&mut line).await.is_ok() {
        if let Ok(prompts_response) = serde_json::from_str::<serde_json::Value>(&line) {
            if let Some(result) = prompts_response.get("result") {
                if let Some(prompts_obj) = result.get("prompts") {
                    // Prompts can be array or object
                    if let Some(prompts_array) = prompts_obj.as_array() {
                        prompts_count = prompts_array.len();
                        for prompt_def in prompts_array {
                            prompts.push(MCPPrompt {
                                name: prompt_def
                                    .get("name")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string(),
                                description: prompt_def
                                    .get("description")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string(),
                                arguments: prompt_def
                                    .get("arguments")
                                    .and_then(|v| v.as_array())
                                    .cloned()
                                    .unwrap_or_default(),
                            });
                        }
                    } else if let Some(prompts_map) = prompts_obj.as_object() {
                        prompts_count = prompts_map.len();
                        for (name, prompt_def) in prompts_map {
                            prompts.push(MCPPrompt {
                                name: name.clone(),
                                description: prompt_def
                                    .get("description")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string(),
                                arguments: prompt_def
                                    .get("arguments")
                                    .and_then(|v| v.as_array())
                                    .cloned()
                                    .unwrap_or_default(),
                            });
                        }
                    }
                }
            }
        }
    }

    // Try to get resources count
    let resources_request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "resources/list"
    });
    stdin
        .write_all(format!("{}\n", resources_request).as_bytes())
        .await
        .ok();
    stdin.flush().await.ok();
    line.clear();
    if reader.read_line(&mut line).await.is_ok() {
        if let Ok(resources_response) = serde_json::from_str::<serde_json::Value>(&line) {
            if let Some(result) = resources_response.get("result") {
                if let Some(resources) = result.get("resources") {
                    resources_count = if resources.is_array() {
                        resources.as_array().map(|a| a.len()).unwrap_or(0)
                    } else if resources.is_object() {
                        resources.as_object().map(|o| o.len()).unwrap_or(0)
                    } else {
                        0
                    };
                }
            }
        }
    }

    // Cleanup
    let _ = child.kill().await;

    let tools_count = tools.len();
    Ok(MCPToolsResponse {
        success: true,
        tools,
        prompts,
        tools_count,
        prompts_count,
        resources_count,
        error: None,
    })
}

async fn fetch_mcp_tools_http(url: &str) -> Result<MCPToolsResponse, String> {
    let client = reqwest::Client::new();

    // Initialize
    let init_request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "t2t",
                "version": "0.2.5"
            }
        }
    });

    let init_response: serde_json::Value = client
        .post(url)
        .json(&init_request)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| format!("HTTP request failed: {e}"))?
        .json()
        .await
        .map_err(|e| format!("Failed to parse init response: {e}"))?;

    if init_response.get("error").is_some() {
        return Err(format!("Initialize error: {}", init_response["error"]));
    }

    // Call tools/list
    let tools_request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list"
    });

    let tools_response: serde_json::Value = client
        .post(url)
        .json(&tools_request)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| format!("HTTP request failed: {e}"))?
        .json()
        .await
        .map_err(|e| format!("Failed to parse tools response: {e}"))?;

    let mut tools = Vec::new();
    let mut prompts = Vec::new();
    let mut prompts_count = 0;
    let mut resources_count = 0;

    if let Some(result) = tools_response.get("result") {
        if let Some(tools_obj) = result.get("tools") {
            // MCP returns tools as an array
            if let Some(tools_array) = tools_obj.as_array() {
                for tool_def in tools_array {
                    tools.push(MCPTool {
                        name: tool_def
                            .get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        description: tool_def
                            .get("description")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        input_schema: tool_def.get("inputSchema").cloned().unwrap_or_default(),
                    });
                }
            }
        }
    }

    // Try prompts/list
    let prompts_request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "prompts/list"
    });
    if let Ok(prompts_response) = client
        .post(url)
        .json(&prompts_request)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
    {
        if let Ok(prompts_json) = prompts_response.json::<serde_json::Value>().await {
            if let Some(result) = prompts_json.get("result") {
                if let Some(prompts_obj) = result.get("prompts") {
                    // Prompts can be array or object
                    if let Some(prompts_array) = prompts_obj.as_array() {
                        prompts_count = prompts_array.len();
                        for prompt_def in prompts_array {
                            prompts.push(MCPPrompt {
                                name: prompt_def
                                    .get("name")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string(),
                                description: prompt_def
                                    .get("description")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string(),
                                arguments: prompt_def
                                    .get("arguments")
                                    .and_then(|v| v.as_array())
                                    .cloned()
                                    .unwrap_or_default(),
                            });
                        }
                    } else if let Some(prompts_map) = prompts_obj.as_object() {
                        prompts_count = prompts_map.len();
                        for (name, prompt_def) in prompts_map {
                            prompts.push(MCPPrompt {
                                name: name.clone(),
                                description: prompt_def
                                    .get("description")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string(),
                                arguments: prompt_def
                                    .get("arguments")
                                    .and_then(|v| v.as_array())
                                    .cloned()
                                    .unwrap_or_default(),
                            });
                        }
                    }
                }
            }
        }
    }

    // Try resources/list
    let resources_request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "resources/list"
    });
    if let Ok(resources_response) = client
        .post(url)
        .json(&resources_request)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
    {
        if let Ok(resources_json) = resources_response.json::<serde_json::Value>().await {
            if let Some(result) = resources_json.get("result") {
                if let Some(resources) = result.get("resources") {
                    resources_count = if resources.is_array() {
                        resources.as_array().map(|a| a.len()).unwrap_or(0)
                    } else if resources.is_object() {
                        resources.as_object().map(|o| o.len()).unwrap_or(0)
                    } else {
                        0
                    };
                }
            }
        }
    }

    let tools_count = tools.len();
    Ok(MCPToolsResponse {
        success: true,
        tools,
        prompts,
        tools_count,
        prompts_count,
        resources_count,
        error: None,
    })
}

// Tauri command: Fetch tools/prompts/resources from an MCP server
// Called by the frontend settings page to discover available capabilities
// Runs locally - MCP servers execute on the user's machine
#[tauri::command]
async fn fetch_mcp_tools(server: MCPServer) -> Result<MCPToolsResponse, String> {
    match server.transport.as_str() {
        "stdio" => {
            let command = server
                .command
                .ok_or("Missing command for stdio transport")?;
            let args = server.args.unwrap_or_default();
            fetch_mcp_tools_stdio(&command, &args).await
        }
        "http" | "sse" => {
            let url = server.url.ok_or("Missing URL for http/sse transport")?;
            fetch_mcp_tools_http(&url).await
        }
        _ => Err(format!("Unknown transport: {}", server.transport)),
    }
}

#[tauri::command]
fn log_event(message: String) {
    log_line(&format!("FE: {message}"));
}

fn main() {
    // Load .env file if it exists
    let _ = dotenv::dotenv();
    
    std::thread::spawn(|| {
        if let Err(e) = init_whisper() {
            log_line(&format!("Whisper init error: {}", e));
        }
    });

    tauri::Builder::default()
        .plugin(
            Builder::new()
                .targets([
                    Target::new(TargetKind::Stdout),
                    Target::new(TargetKind::LogDir { file_name: Some("t2t.log".into()) }),
                    Target::new(TargetKind::Webview),
                ])
                .level(log::LevelFilter::Info)
                .build(),
        )
        .plugin(tauri_plugin_single_instance::init(|_app, _args, _cwd| {
            println!("Another instance tried to start - ignoring");
        }))
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_store::Builder::default().build())
        .invoke_handler(tauri::generate_handler![paste_text, transcribe, log_event, fetch_mcp_tools, fetch_openrouter_models, get_openrouter_key, set_openrouter_key, get_theme, set_theme, get_system_theme, cancel_processing, save_history_entry, get_history, search_history])
        .setup(|app| {
            let _ = APP_HANDLE.set(app.handle().clone());

            if let Err(e) = init_audio_thread() {
                log_line(&format!("ERROR: init_audio_thread: {e}"));
            }
            
            #[cfg(target_os = "macos")]
            {
                // Try to force the Accessibility prompt on first run (Finder launch).
                // This is what makes it behave like Wispr.
                let _ = macos_fn_key::request_accessibility_prompt();
                macos_fn_key::start_fn_listener();
            }

            if let Some(window) = app.get_webview_window("main") {
                window.set_ignore_cursor_events(true).ok();
                // Prevent our UI window from ever taking keyboard focus (so paste targets stay correct).
                let _ = window.set_focusable(false);
                
                if let Ok(Some(monitor)) = window.primary_monitor() {
                    let size = monitor.size();
                    let scale = monitor.scale_factor();
                    let (screen_w, screen_h) = (size.width as f64 / scale, size.height as f64 / scale);
                    // Give the webview enough height so CSS glow/height animations aren't clipped.
                    // The visible "bar" stays pinned to the bottom via CSS; the extra height is just headroom.
                    let (win_w, win_h) = (screen_w, 24.0);
                    use tauri::LogicalPosition;
                    use tauri::LogicalSize;
                    window.set_size(LogicalSize::new(win_w, win_h)).ok();
                    window.set_position(LogicalPosition::new(
                        0.0,
                        screen_h - win_h,
                    )).ok();
                }
            }

            let settings = MenuItem::with_id(app, "settings", "View Settings", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&settings, &quit])?;
            
            // Load tray icon from file - need to decode PNG to RGBA
            fn load_png_as_image(path: &std::path::Path) -> Option<Image<'static>> {
                let data = std::fs::read(path).ok()?;
                let decoder = png::Decoder::new(std::io::Cursor::new(data));
                let mut reader = decoder.read_info().ok()?;
                let mut buf = vec![0; reader.output_buffer_size()];
                let info = reader.next_frame(&mut buf).ok()?;
                let bytes = &buf[..info.buffer_size()];
                
                // Convert to RGBA if needed
                let rgba = match info.color_type {
                    png::ColorType::Rgba => bytes.to_vec(),
                    png::ColorType::Rgb => {
                        let mut rgba = Vec::with_capacity(bytes.len() / 3 * 4);
                        for chunk in bytes.chunks(3) {
                            rgba.extend_from_slice(chunk);
                            rgba.push(255);
                        }
                        rgba
                    }
                    png::ColorType::GrayscaleAlpha => {
                        let mut rgba = Vec::with_capacity(bytes.len() * 2);
                        for chunk in bytes.chunks(2) {
                            rgba.extend_from_slice(&[chunk[0], chunk[0], chunk[0], chunk[1]]);
                        }
                        rgba
                    }
                    png::ColorType::Grayscale => {
                        let mut rgba = Vec::with_capacity(bytes.len() * 4);
                        for &g in bytes {
                            rgba.extend_from_slice(&[g, g, g, 255]);
                        }
                        rgba
                    }
                    _ => return None,
                };
                Some(Image::new_owned(rgba, info.width, info.height))
            }
            
            let icon = {
                // Try multiple paths for the tray icon
                let paths = [
                    std::path::PathBuf::from("icons/tray-icon.png"),
                    app.path().resource_dir().ok().map(|p| p.join("icons/tray-icon.png")).unwrap_or_default(),
                    std::env::current_exe().ok().and_then(|p| p.parent().map(|p| p.join("../Resources/icons/tray-icon.png"))).unwrap_or_default(),
                ];
                paths.iter()
                    .filter(|p| p.exists())
                    .find_map(|p| load_png_as_image(p))
                    .unwrap_or_else(|| create_circular_icon(32))
            };

            TrayIconBuilder::new()
                .icon(icon)
                .menu(&menu)
                .tooltip("t2t - Hold Fn")
                .on_menu_event(|app, event| {
                    match event.id.as_ref() {
                        "settings" => {
                            // Change activation policy to Regular so it appears in Command+Tab
                            let _ = app.set_activation_policy(tauri::ActivationPolicy::Regular);
                            
                            // Show the settings window and bring to front
                            let w = app.get_webview_window("settings").or_else(|| {
                                tauri::WebviewWindowBuilder::new(
                                    app,
                                    "settings",
                                    tauri::WebviewUrl::App("/settings".into())
                                )
                                .title("Settings")
                                .inner_size(900.0, 700.0)
                                .center()
                                .skip_taskbar(false)
                                .build()
                                .ok()
                            });
                            if let Some(w) = w {
                                let _ = w.set_skip_taskbar(false);
                                let _ = w.show();
                                let _ = w.unminimize();
                                let _ = w.set_always_on_top(true);
                                let _ = w.set_always_on_top(false);
                                let _ = w.set_focus();
                                log_line("tray: view settings");
                            }
                        }
                        "quit" => app.exit(0),
                        _ => {}
                    }
                })
                .build(app)?;

            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Accessory);

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error running app");
}
