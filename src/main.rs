#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use once_cell::sync::OnceCell;
use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::sync::atomic::AtomicI32;
use std::sync::mpsc;
use std::time::{SystemTime, UNIX_EPOCH};
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
static FRONTMOST_PID: AtomicI32 = AtomicI32::new(0);
static FOCUSED_AX_ELEM: OnceCell<Mutex<Option<usize>>> = OnceCell::new();

enum AudioCmd {
    Start,
    Stop {
        reply: mpsc::Sender<Result<(Vec<f32>, u32), String>>,
    },
}

static AUDIO_TX: OnceCell<mpsc::Sender<AudioCmd>> = OnceCell::new();

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
        fn AXUIElementCopyAttributeValue(
            element: *mut c_void,
            attribute: *const c_void,
            value: *mut *mut c_void,
        ) -> i32;
        fn AXUIElementSetAttributeValue(
            element: *mut c_void,
            attribute: *const c_void,
            value: *const c_void,
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

    fn activate_pid(pid: i32) {
        if pid <= 0 {
            return;
        }
        unsafe {
            // NSRunningApplication.runningApplicationWithProcessIdentifier(pid).activateWithOptions(NSApplicationActivateIgnoringOtherApps)
            let running: *mut Object = msg_send![class!(NSRunningApplication), runningApplicationWithProcessIdentifier:pid];
            if running.is_null() {
                return;
            }
            // NSApplicationActivateIgnoringOtherApps = 1 << 1
            let opts: u64 = 1u64 << 1;
            let _: bool = msg_send![running, activateWithOptions:opts];
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

    fn restore_focused_ax_element() {
        let Some(cell) = FOCUSED_AX_ELEM.get() else { return; };
        let stored = cell.lock().ok().and_then(|g| *g);
        let Some(ptr_usize) = stored else { return; };
        let elem = ptr_usize as *mut c_void;
        if elem.is_null() {
            return;
        }
        unsafe {
            let attr = cfstr("AXFocused");
            let err = AXUIElementSetAttributeValue(elem, attr, kCFBooleanTrue);
            CFRelease(attr);
            log_line(&format!("AX restore focus result={err}"));
        }
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

                let key_code: u16 = unsafe { msg_send![event, keyCode] };
                let flags: u64 = unsafe { msg_send![event, modifierFlags] };

                // Fn key reports as flagsChanged with keyCode 63 on Apple keyboards.
                if key_code != 63 {
                    return;
                }

                let pressed = (flags & fn_flag) != 0;
                // Avoid duplicate transitions
                let was_recording = IS_RECORDING.load(Ordering::SeqCst);
                if pressed && !was_recording {
                    handle_fn_key(true);
                } else if !pressed && was_recording {
                    handle_fn_key(false);
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
            handle_fn_key(pressed);
        }
    }
    
    fn handle_fn_key(pressed: bool) {
        let was_recording = IS_RECORDING.load(Ordering::SeqCst);
        
        if pressed && !was_recording {
            IS_RECORDING.store(true, Ordering::SeqCst);
            // Remember where the user was typing so we can restore focus before pasting.
            let pid = capture_frontmost_pid();
            FRONTMOST_PID.store(pid, Ordering::SeqCst);
            log_line(&format!("Captured frontmost pid={pid}"));

            // Capture the focused UI element (critical for apps like Cursor where PID isn't enough).
            if let Some(app) = APP_HANDLE.get().cloned() {
                let _ = app.run_on_main_thread(|| {
                    let cell = FOCUSED_AX_ELEM.get_or_init(|| Mutex::new(None));
                    // Release old
                    if let Ok(mut g) = cell.lock() {
                        if let Some(old) = *g {
                            unsafe { CFRelease(old as *const c_void) };
                        }
                        *g = capture_focused_ax_element();
                    }
                    log_line("Captured AX focused element (best effort)");
                });
            }
            log_line("Fn pressed - start recording");
            // Dismiss emoji picker if it pops up (best effort).
            std::thread::spawn(|| {
                std::thread::sleep(std::time::Duration::from_millis(50));
                #[cfg(target_os = "macos")]
                {
                    let _ = std::process::Command::new("osascript")
                        .args(["-e", r#"tell application "System Events" to key code 53"#])
                        .output();
                }
            });

            // Watchdog: if macOS steals focus and we miss release, poll modifier flags until Fn-up.
            std::thread::spawn(|| {
                // hard cap so we never get stuck forever
                let max_ms = 15_000u64;
                let start = std::time::Instant::now();
                loop {
                    std::thread::sleep(std::time::Duration::from_millis(25));
                    if !IS_RECORDING.load(Ordering::SeqCst) {
                        break;
                    }
                    let flags = unsafe { CGEventSourceFlagsState(K_CG_EVENT_SOURCE_STATE_COMBINED_SESSION_STATE) };
                    let fn_down = (flags & K_CG_EVENT_FLAG_MASK_SECONDARY_FN) != 0;
                    if !fn_down {
                        // Force stop (idempotent)
                        handle_fn_key(false);
                        break;
                    }
                    if start.elapsed().as_millis() as u64 > max_ms {
                        log_line("Fn watchdog timeout - forcing stop");
                        handle_fn_key(false);
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
                    // Restore focus to the app the user was using when they started holding Fn.
                    #[cfg(target_os = "macos")]
                    {
                        let pid = FRONTMOST_PID.load(Ordering::SeqCst);
                        log_line(&format!("Restoring focus to pid={pid}"));
                        activate_pid(pid);
                        // If the target is inside the same app (e.g. Cursor chat vs editor),
                        // restore the exact focused UI element captured on Fn-down.
                        restore_focused_ax_element();
                        // small delay to let focus settle
                        std::thread::sleep(std::time::Duration::from_millis(30));
                    }
                    #[cfg(target_os = "macos")]
                    {
                        set_clipboard_macos(&text);
                    }
                    paste_text();
                    log_line(&format!("Pasted native text len={}", text.len()));
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

    std::thread::spawn(move || {
        let host = cpal::default_host();
        let device = match host.default_input_device() {
            Some(d) => d,
            None => {
                log_line("ERROR: No default input device (cpal)");
                return;
            }
        };

        let input_cfg = match device.default_input_config() {
            Ok(c) => c,
            Err(e) => {
                log_line(&format!("ERROR: default_input_config: {e}"));
                return;
            }
        };

        let channels = input_cfg.channels();
        let mut sample_rate = input_cfg.sample_rate().0;
        let sample_format = input_cfg.sample_format();

        log_line(&format!(
            "Audio thread ready: device='{}' rate={} channels={} fmt={:?}",
            device.name().unwrap_or_else(|_| "<unknown>".into()),
            sample_rate,
            channels,
            sample_format
        ));

        let samples_mono: Arc<Mutex<Vec<f32>>> = Arc::new(Mutex::new(Vec::new()));
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

                    // (Re)read config to reflect system changes.
                    match device.default_input_config() {
                        Ok(c) => {
                            sample_rate = c.sample_rate().0;
                        }
                        Err(_) => {}
                    }

                    let cfg: cpal::StreamConfig = input_cfg.clone().into();
                    let samples_cb = samples_mono.clone();

                    let built = match sample_format {
                        cpal::SampleFormat::I16 => device.build_input_stream(
                            &cfg,
                            move |data: &[i16], _| {
                                let mut out = samples_cb.lock().unwrap();
                                if channels == 1 {
                                    out.extend(data.iter().map(|&s| (s as f32) / 32768.0));
                                } else {
                                    for frame in data.chunks_exact(channels as usize) {
                                        let sum: i32 = frame.iter().map(|&v| v as i32).sum();
                                        let avg = (sum as f32) / (channels as f32);
                                        out.push(avg / 32768.0);
                                    }
                                }
                            },
                            err_fn,
                            None,
                        ),
                        cpal::SampleFormat::F32 => device.build_input_stream(
                            &cfg,
                            move |data: &[f32], _| {
                                let mut out = samples_cb.lock().unwrap();
                                if channels == 1 {
                                    out.extend_from_slice(data);
                                } else {
                                    for frame in data.chunks_exact(channels as usize) {
                                        let sum: f32 = frame.iter().copied().sum();
                                        out.push(sum / (channels as f32));
                                    }
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
                        Err(e) => log_line(&format!("ERROR: build_input_stream: {e}")),
                    }
                }
                AudioCmd::Stop { reply } => {
                    stream.take(); // drop to stop capture
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
#[tauri::command]
fn log_event(message: String) {
    log_line(&format!("FE: {message}"));
}

fn main() {
    std::thread::spawn(|| {
        if let Err(e) = init_whisper() {
            log_line(&format!("Whisper init error: {}", e));
        }
    });

    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|_app, _args, _cwd| {
            println!("Another instance tried to start - ignoring");
        }))
        .plugin(tauri_plugin_clipboard_manager::init())
        .invoke_handler(tauri::generate_handler![paste_text, transcribe, log_event])
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
                    let (win_w, win_h) = (80.0, 80.0);
                    use tauri::LogicalPosition;
                    window.set_position(LogicalPosition::new(
                        (screen_w - win_w) / 2.0,
                        screen_h - win_h - 60.0,
                    )).ok();
                }
            }

            // Debug controls so we can validate mic/recording even if Fn capture fails.
            let start = MenuItem::with_id(app, "start", "Start recording", true, None::<&str>)?;
            let stop = MenuItem::with_id(app, "stop", "Stop recording", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&start, &stop, &quit])?;
            let icon = create_circular_icon(32);

            TrayIconBuilder::new()
                .icon(icon)
                .menu(&menu)
                .tooltip("t2t - Hold Fn")
                .on_menu_event(|app, event| {
                    match event.id.as_ref() {
                        "start" => {
                            if let Some(w) = app.get_webview_window("main") {
                                let _ = w.eval("window.__startRecording && window.__startRecording()");
                                log_line("tray: start recording");
                            } else {
                                log_line("tray: start recording but main window not found");
                            }
                        }
                        "stop" => {
                            if let Some(w) = app.get_webview_window("main") {
                                let _ = w.eval("window.__stopRecording && window.__stopRecording()");
                                log_line("tray: stop recording");
                            } else {
                                log_line("tray: stop recording but main window not found");
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
