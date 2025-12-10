#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use once_cell::sync::OnceCell;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use tauri::{
    AppHandle, Manager,
    image::Image,
    menu::{Menu, MenuItem},
    tray::TrayIconBuilder,
};
use whisper_rs::{FullParams, SamplingStrategy, WhisperContext, WhisperContextParameters};

static WHISPER: OnceCell<Mutex<WhisperContext>> = OnceCell::new();
static APP_HANDLE: OnceCell<AppHandle> = OnceCell::new();
static IS_RECORDING: AtomicBool = AtomicBool::new(false);

fn get_model_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".cache").join("whisper").join("ggml-base.en.bin")
}

fn ensure_model(path: &PathBuf) -> Result<(), String> {
    if path.exists() {
        return Ok(());
    }
    
    std::fs::create_dir_all(path.parent().unwrap()).map_err(|e| e.to_string())?;
    
    println!("Downloading Whisper model (~150MB)...");
    let url = "https://huggingface.co/ggerganov/whisper.cpp/resolve/main/ggml-base.en.bin";
    
    let response = std::process::Command::new("curl")
        .args(["-L", "-o", path.to_str().unwrap(), url])
        .status()
        .map_err(|e| e.to_string())?;
    
    if !response.success() {
        return Err("Failed to download model".to_string());
    }
    
    println!("Model downloaded!");
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
    println!("Whisper initialized!");
    Ok(())
}

#[cfg(target_os = "macos")]
mod macos_fn_key {
    use super::*;
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
    }
    
    pub fn start_fn_listener() {
        std::thread::spawn(|| {
            println!("Starting Fn key listener via IOHIDManager...");
            println!("Requires Accessibility permission in System Settings");
            
            unsafe {
                let manager = IOHIDManagerCreate(K_CF_ALLOCATOR_DEFAULT, K_IO_HID_OPTIONS_TYPE_NONE);
                if manager.is_null() {
                    eprintln!("Failed to create IOHIDManager");
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
                    eprintln!("Failed to open IOHIDManager: {}", result);
                    eprintln!("Please grant Accessibility permission and restart");
                    return;
                }
                
                println!("IOHIDManager active! Hold Fn to record.");
                
                CFRunLoopRun();
            }
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
        
        // Debug: uncomment to see all HID events
        // println!("HID: page={:#x} usage={:#x} value={}", usage_page, usage, int_value);
        
        // Fn key on Apple keyboards can appear as:
        // - Usage page 0xFF (vendor-specific Apple), usage 0x03
        // - Usage page 0x07 (keyboard), usage 0x00 with the Fn modifier
        // - Sometimes as page 0x01, usage varies
        
        let is_fn_key = 
            (usage_page == 0xFF && usage == 0x03) ||  // Apple vendor Fn
            (usage_page == 0x07 && usage == 0x00);    // Keyboard with Fn modifier
        
        if is_fn_key {
            let pressed = int_value != 0;
            handle_fn_key(pressed);
        }
    }
    
    fn handle_fn_key(pressed: bool) {
        let was_recording = IS_RECORDING.load(Ordering::SeqCst);
        
        if pressed && !was_recording {
            IS_RECORDING.store(true, Ordering::SeqCst);
            println!("Fn pressed - start recording");
            trigger_window_action("startRecording");
        } else if !pressed && was_recording {
            IS_RECORDING.store(false, Ordering::SeqCst);
            println!("Fn released - stop recording");
            trigger_window_action("stopRecording");
        }
    }
    
    fn trigger_window_action(action: &str) {
        if let Some(app) = APP_HANDLE.get() {
            let app = app.clone();
            let js = format!("window.__{} && window.__{}()", action, action);
            let _ = app.run_on_main_thread(move || {
                if let Some(window) = app.get_webview_window("main") {
                    window.eval(&js).ok();
                }
            });
        }
    }
}

#[tauri::command]
fn transcribe(audio_data: Vec<u8>) -> Result<String, String> {
    println!("Transcribe called with {} bytes", audio_data.len());
    
    if audio_data.len() < 44 {
        return Err("WAV too short".to_string());
    }
    
    let pcm_data = &audio_data[44..];
    let samples: Vec<f32> = pcm_data
        .chunks_exact(2)
        .map(|b| i16::from_le_bytes([b[0], b[1]]) as f32 / 32768.0)
        .collect();
    
    println!("Parsed {} samples from WAV", samples.len());
    
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
    println!("Running Whisper on {} samples...", samples.len());
    state.full(params, &samples).map_err(|e| {
        println!("Transcribe error: {:?}", e);
        format!("Transcribe error: {:?}", e)
    })?;
    
    let num_segments = state.full_n_segments().map_err(|e| format!("Segment error: {:?}", e))?;
    let mut text = String::new();
    for i in 0..num_segments {
        if let Ok(segment) = state.full_get_segment_text(i) {
            text.push_str(&segment);
        }
    }
    
    println!("Transcribed: '{}'", text.trim());
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

fn main() {
    std::thread::spawn(|| {
        if let Err(e) = init_whisper() {
            eprintln!("Whisper init error: {}", e);
        }
    });

    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|_app, _args, _cwd| {
            println!("Another instance tried to start - ignoring");
        }))
        .plugin(tauri_plugin_clipboard_manager::init())
        .invoke_handler(tauri::generate_handler![paste_text, transcribe])
        .setup(|app| {
            let _ = APP_HANDLE.set(app.handle().clone());
            
            #[cfg(target_os = "macos")]
            macos_fn_key::start_fn_listener();

            if let Some(window) = app.get_webview_window("main") {
                window.set_ignore_cursor_events(true).ok();
                
                if let Ok(Some(monitor)) = window.primary_monitor() {
                    let size = monitor.size();
                    let scale = monitor.scale_factor();
                    let (screen_w, screen_h) = (size.width as f64 / scale, size.height as f64 / scale);
                    let (win_w, win_h) = (80.0, 80.0);
                    use tauri::LogicalPosition;
                    window.set_position(LogicalPosition::new(
                        (screen_w - win_w) / 2.0,
                        screen_h - win_h - 60.0,
                    )).ok();
                }
            }

            let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&quit])?;
            let icon = Image::new_owned(vec![0x50, 0x50, 0x50, 0xff].repeat(1024), 32, 32);

            TrayIconBuilder::new()
                .icon(icon)
                .menu(&menu)
                .tooltip("t2t - Hold Fn")
                .on_menu_event(|app, event| {
                    if event.id.as_ref() == "quit" {
                        app.exit(0);
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
