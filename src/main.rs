#[cfg(not(windows))]
compile_error!("This binary can only be built on windows");

use log::*;
use ntapi::ntrtl::RtlGetVersion;
use regex::Regex;
use serde::Deserialize;
use std::{
    collections::HashSet,
    ffi::OsString,
    mem::{size_of, size_of_val},
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::{
    fs,
    sync::{broadcast::Sender, mpsc::UnboundedReceiver},
    time::interval,
};
use tray_item::TrayItem;
use winapi::{
    shared::{minwindef::DWORD, windef::DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2},
    um::{
        processthreadsapi::ProcessIdToSessionId,
        winnt::OSVERSIONINFOW,
        winuser::{SetProcessDpiAwarenessContext, EVENT_SYSTEM_FOREGROUND},
    },
};
use windows::{
    core::PWSTR,
    Win32::{
        Foundation::{
            CloseHandle, GetLastError, BOOL, ERROR_INSUFFICIENT_BUFFER, HANDLE, HWND, LPARAM,
        },
        System::{
            Console::GetConsoleWindow,
            ProcessStatus::K32EnumProcesses,
            Threading::{
                OpenProcess, ProcessPowerThrottling, QueryFullProcessImageNameW, SetPriorityClass,
                SetProcessInformation, IDLE_PRIORITY_CLASS, NORMAL_PRIORITY_CLASS,
                PROCESS_NAME_WIN32, PROCESS_POWER_THROTTLING_CURRENT_VERSION,
                PROCESS_POWER_THROTTLING_EXECUTION_SPEED, PROCESS_POWER_THROTTLING_STATE,
                PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SET_INFORMATION,
            },
        },
        UI::WindowsAndMessaging::{
            EnumChildWindows, GetGUIThreadInfo, GetWindowThreadProcessId, ShowWindow,
            GUITHREADINFO, SW_HIDE,
        },
    },
};
use wineventhook::{EventFilter, WindowEventHook};

const THROTTLING_ON: PROCESS_POWER_THROTTLING_STATE = PROCESS_POWER_THROTTLING_STATE {
    Version: PROCESS_POWER_THROTTLING_CURRENT_VERSION,
    ControlMask: PROCESS_POWER_THROTTLING_EXECUTION_SPEED,
    StateMask: PROCESS_POWER_THROTTLING_EXECUTION_SPEED,
};

const THROTTLING_OFF: PROCESS_POWER_THROTTLING_STATE = PROCESS_POWER_THROTTLING_STATE {
    Version: PROCESS_POWER_THROTTLING_CURRENT_VERSION,
    ControlMask: PROCESS_POWER_THROTTLING_EXECUTION_SPEED,
    StateMask: 0,
};

#[derive(Deserialize, Default)]
struct Config {
    filter: Option<String>,
    white_list: WhiteList,
    debug: bool,
}

#[derive(Deserialize, Default)]
struct WhiteList(Vec<PathBuf>);

#[derive(Clone)]
struct Rule {
    regex: Option<Regex>,
    white_list: HashSet<PathBuf>,
}

#[derive(Debug)]
enum Event {
    Foreground,
    TimerTick,
    Quit,
}

impl Rule {
    fn matched<P: AsRef<Path>>(&self, name: P) -> bool {
        if self.white_list.contains(name.as_ref()) {
            debug!("bypass {} due to white list", name.as_ref().display());
            true
        } else if let Some(regex) = self.regex.as_ref() {
            let s = name.as_ref().to_str().unwrap_or_default();
            if regex.is_match(s) {
                debug!("bypass {} due to regex", name.as_ref().display());
                true
            } else {
                false
            }
        } else {
            false
        }
    }
    fn create(config: &Config) -> Self {
        let Config {
            filter, white_list, ..
        } = config;
        let regex = filter.as_ref().map(|x| {
            Regex::new(x.as_str()).unwrap_or_else(|err| {
                warn!("unable to build filter regex {}", err);
                // reject anything
                Regex::new(r"(?-u)^\b$").unwrap()
            })
        });
        let white_list = HashSet::from_iter(white_list.0.iter().cloned());
        Rule { regex, white_list }
    }
}

async fn hide_console_window(config: &Config) {
    if !config.debug {
        debug!("hide console window");
        let window = unsafe { GetConsoleWindow() };
        if window.0 != 0 {
            unsafe {
                ShowWindow(window, SW_HIDE);
            }
        }
    }
}

async fn check_windows_version() -> DWORD {
    let mut osv: OSVERSIONINFOW = Default::default();
    unsafe { RtlGetVersion(&mut osv) };
    osv.dwBuildNumber
}

async fn toggle_efficiency_mode(proc: HANDLE, enable: bool) {
    unsafe {
        SetProcessInformation(
            proc,
            ProcessPowerThrottling,
            if enable {
                &THROTTLING_ON as *const _ as *mut _
            } else {
                &THROTTLING_OFF as *const _ as *mut _
            },
            size_of::<PROCESS_POWER_THROTTLING_STATE>() as u32,
        );
        SetPriorityClass(
            proc,
            if enable {
                IDLE_PRIORITY_CLASS
            } else {
                NORMAL_PRIORITY_CLASS
            },
        );
    };
}

#[repr(C)]
#[derive(Default)]
struct EnumChildWindowsCallbackInfo {
    child_handle: HANDLE,
    parent_proc: u32,
    child_proc: u32,
    found: BOOL,
}

unsafe extern "system" fn enum_child_windows_callback(hwnd: HWND, lparam: LPARAM) -> BOOL {
    let mut proc: u32 = 0;

    let thread = GetWindowThreadProcessId(hwnd, &mut proc);
    if thread == 0 || proc == 0 {
        debug!("failed to GetWindowThreadProcessId: {:?}", GetLastError());
        return true.into();
    }

    let info = lparam.0 as *mut EnumChildWindowsCallbackInfo;

    if proc == (*info).parent_proc {
        return true.into();
    }

    let res = OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_INFORMATION,
        false,
        proc,
    );

    if res.is_err() {
        return true.into();
    }

    (*info).child_handle = res.unwrap();
    (*info).child_proc = proc;
    (*info).found = true.into();

    false.into()
}

async fn get_process_handle_by_id(proc: u32) -> Result<(u32, HANDLE), ()> {
    let res = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_INFORMATION,
            false,
            proc,
        )
    };

    res.map_err(|_| {
        debug!("failed to OpenProcess: {:?}", unsafe { GetLastError() });
    })
    .map(|h| (proc, h))
}

async fn get_process_handle_by_hwnd(hwnd: HWND) -> Result<(u32, HANDLE), ()> {
    let mut proc: u32 = 0;
    if hwnd.0 == 0 {
        debug!("HWND is 0");
        return Err(());
    }

    let thread = unsafe { GetWindowThreadProcessId(hwnd, &mut proc) };
    if thread == 0 || proc == 0 {
        debug!("failed to GetWindowThreadProcessId: {:?}", unsafe {
            GetLastError()
        });
        return Err(());
    }

    get_process_handle_by_id(proc).await
}

async fn get_process_image_path(handle: HANDLE) -> Result<PathBuf, ()> {
    let mut cap = 1024;
    let mut buf = Vec::with_capacity(cap);
    let mut size;
    let mut name;

    loop {
        buf.reserve(cap);
        name = PWSTR(buf.as_mut_ptr());
        size = cap as u32;

        if unsafe { QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, name, &mut size) }
            == false
        {
            if cap >= 65536 {
                debug!("full process image name is too long");
            }

            if unsafe { GetLastError() } == ERROR_INSUFFICIENT_BUFFER {
                cap *= 2;
                continue;
            }

            debug!("failed to QueryFullProcessImageNameW: {:?}", unsafe {
                GetLastError()
            });
            return Err(());
        } else {
            break;
        }
    }

    let name = unsafe { name.to_string() }.unwrap_or_default();
    let name = PathBuf::from(name.as_str());
    Ok(name)
}

async fn toggle_mode_by_hwnd(
    hwnd: HWND,
    rule: &Rule,
    prev: &mut (u32, OsString),
) -> Result<(), ()> {
    let (mut proc, mut handle) = get_process_handle_by_hwnd(hwnd).await?;
    let mut path = get_process_image_path(handle).await.map_err(|_| unsafe {
        CloseHandle(handle);
    })?;

    if let Some(name) = path.file_name() {
        if name == "ApplicationFrameHost.exe" {
            let mut info = EnumChildWindowsCallbackInfo {
                parent_proc: proc,
                ..Default::default()
            };

            unsafe {
                EnumChildWindows(
                    hwnd,
                    Some(enum_child_windows_callback),
                    LPARAM((&mut info) as *mut _ as isize),
                )
            };
            if info.found.as_bool() {
                unsafe { CloseHandle(handle) };
                handle = info.child_handle;
                proc = info.child_proc;
                path = get_process_image_path(handle).await.map_err(|_| unsafe {
                    CloseHandle(handle);
                })?;
            }
        }
    }
    let mut bypassed = false;
    if let Some(name) = path.file_name() {
        bypassed = rule.matched(name);
    }

    if prev.0 != 0 && prev.0 != proc {
        let (_, handle) = get_process_handle_by_id(prev.0).await.map_err(|_| unsafe {
            CloseHandle(handle);
        })?;
        toggle_efficiency_mode(handle, true).await;
        info!(
            "{} runs slower now",
            Path::new(prev.1.as_os_str()).display()
        );
        unsafe { CloseHandle(handle) };
        prev.0 = 0;
        prev.1 = OsString::default();
    }

    if !bypassed {
        toggle_efficiency_mode(handle, false).await;
        info!(
            "{} runs faster now",
            Path::new(path.file_name().unwrap_or_default()).display()
        );
        prev.0 = proc;
        prev.1 = path.file_name().unwrap_or_default().to_os_string();
    }

    unsafe { CloseHandle(handle) };
    Ok(())
}

async fn toggle_all_processes(prev: Option<&(u32, OsString)>, rule: &Rule, enabled: bool) {
    let mut cap = 4096;
    let mut buf = Vec::with_capacity(cap);
    let mut size;

    loop {
        buf.reserve(cap);
        size = cap as u32;
        if unsafe {
            K32EnumProcesses(
                buf.as_mut_ptr(),
                cap as u32 * std::mem::size_of::<u32>() as u32,
                &mut size,
            )
        } == false
        {
            if cap >= 16 * 1024 * 1024 {
                debug!("process list is too large");
            }

            if unsafe { GetLastError() } == ERROR_INSUFFICIENT_BUFFER || size == cap as u32 {
                cap *= 2;
                continue;
            }

            debug!("failed to K32EnumProcesses: {:?}", unsafe {
                GetLastError()
            });
        }

        break;
    }

    unsafe { buf.set_len((size / std::mem::size_of::<u32>() as u32) as usize) };
    let my_pid = std::process::id();
    let mut my_sid = 0;
    unsafe {
        ProcessIdToSessionId(my_pid, &mut my_sid);
    }
    if my_sid == 0 {
        debug!("can't get the session id of the current process");
        return;
    }

    let n = if let Some(prev) = prev { prev.0 } else { 0 };
    let mut count = 0;
    for proc in buf.into_iter().filter(|&x| x != my_pid && x != n) {
        let mut sid = 0;
        if unsafe { ProcessIdToSessionId(proc, &mut sid) } != false.into() && sid == my_sid {
            let (_, handle) = get_process_handle_by_id(proc).await.unwrap_or_default();
            let path = get_process_image_path(handle)
                .await
                .map_err(|_| unsafe {
                    CloseHandle(handle);
                })
                .unwrap_or_default();
            if let Some(name) = path.file_name() {
                if !rule.matched(name) {
                    toggle_efficiency_mode(handle, enabled).await;
                    count += 1;
                }
            }
        }
    }

    info!(
        "toggle {} processes efficiency mode state into {}",
        count, enabled
    );
}

async fn toggle_mode(rule: &Rule, prev: &mut (u32, OsString)) {
    let mut info: GUITHREADINFO = Default::default();

    info.cbSize = size_of_val(&info) as u32;

    if unsafe { GetGUIThreadInfo(0, &mut info) } == false {
        debug!("failed to GetGUIThreadInfo: {:?}", unsafe {
            GetLastError()
        });
        return;
    }

    let hwnd = info.hwndActive.0;

    toggle_mode_by_hwnd(HWND(hwnd), rule, prev)
        .await
        .unwrap_or_else(|_| {
            debug!("toggle mode by hwnd failed");
        });
}

async fn handle_event(mut event_rx: UnboundedReceiver<Event>, close_tx: Sender<bool>, rule: Rule) {
    let mut prev: (u32, OsString) = Default::default();
    while let Some(event) = event_rx.recv().await {
        match event {
            Event::Foreground => toggle_mode(&rule, &mut prev).await,
            Event::TimerTick => {
                toggle_all_processes(Some(&prev), &rule, true).await;
            }
            Event::Quit => {
                close_tx.send(true).unwrap();
                toggle_all_processes(None, &rule, false).await;
                info!("exiting ...");
                break;
            }
        }
    }
}

#[tokio::main]
async fn main() {
    env_logger::init();

    if check_windows_version().await < 22000 {
        error!("this program requires windows build version higher than 22000");
        return;
    }

    unsafe {
        SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    }

    let config = fs::read_to_string("./battery-savior.toml").await;

    let s = if let Ok(s) = &config {
        s.as_str()
    } else {
        warn!("can't read configure {}", config.err().unwrap());
        include_str!("../battery-savior.toml")
    };

    let config = toml::from_str(s).unwrap_or_else(|err| {
        error!("can't parse configure {}", err);
        Default::default()
    });

    hide_console_window(&config).await;
    let rule = Rule::create(&config);
    let mut tray = TrayItem::new("Battery Savior", "battery").unwrap();

    let (win_event_tx, mut win_event_rx) = tokio::sync::mpsc::unbounded_channel();
    let (event_tx, event_rx) = tokio::sync::mpsc::unbounded_channel();
    let (close_tx, mut close_rx) = tokio::sync::broadcast::channel(2);
    let tx = event_tx.clone();
    let tx2 = event_tx.clone();
    let tx3 = event_tx.clone();
    let tx4 = close_tx.clone();

    tray.add_menu_item("exit", move || {
        tx.send(Event::Quit).unwrap();
        debug!("exit command received");
    })
    .unwrap();

    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.unwrap();
        tx2.send(Event::Quit).unwrap();
        debug!("ctrl-c signal received");
    });

    tokio::spawn(async move {
        handle_event(event_rx, tx4, rule).await;
        debug!("event loop ended");
    });

    tokio::spawn(async move {
        let mut close_rx = close_tx.subscribe();
        let timer_task = async {
            let mut interval = interval(Duration::from_secs(60));
            loop {
                tx3.send(Event::TimerTick).unwrap();
                interval.tick().await;
            }
        };
        tokio::select! {
            biased;
            Ok(true) = close_rx.recv() => {
                debug!("close event in the timer loop");
            }
            _ = timer_task => {}
        };
        debug!("timer stopped");
    });

    let hook = WindowEventHook::hook(
        EventFilter::default()
            .event(EVENT_SYSTEM_FOREGROUND as i32)
            .skip_own_process(true),
        win_event_tx,
    )
    .await
    .unwrap();

    let forward_event = async {
        while (win_event_rx.recv().await).is_some() {
            event_tx.send(Event::Foreground).unwrap();
        }
    };

    // Wait and print events
    tokio::select! {
        biased;
        Ok(true) = close_rx.recv() => {
            debug!("close event in the main loop");
        }
        _ = forward_event => {}
    };

    // Unhook the hook
    hook.unhook().await.unwrap();
    debug!("unhook windows events");
}
