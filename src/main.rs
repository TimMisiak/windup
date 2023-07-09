use windows::{Win32::System::{Threading::{PROCESS_CREATION_FLAGS, CreateProcessW, STARTUPINFOEXW, PROCESS_INFORMATION, WaitForSingleObject, INFINITE}, Environment::GetCommandLineW}, core::PWSTR};
use std::{path::Path, ffi::OsString, os::windows::{ffi::OsStrExt, prelude::OsStringExt}};

mod range_reader;
mod install;
use install::*;

unsafe fn wcslen(ptr: *const u16) -> usize {
    let mut len = 0;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    len
}

fn parse_command_line() -> Vec<u16> {
    let cmd_line = unsafe {
        // As far as I can tell, standard rust command line argument parsing won't preserve spaces. So we'll call
        // the win32 api directly and then parse it out.
        let p = GetCommandLineW();
        let len = wcslen(p.0);
        std::slice::from_raw_parts(p.0, len + 1)
    };

    let mut cmd_line_iter = cmd_line.iter().copied();

    let first = cmd_line_iter.next();

    let first = match first {
        Some(x) => x,
        None => return vec![0u16; 0]
    };

    // If the first character is a quote, we need to find a matching end quote. Otherwise, the first space.
    let end_char = (if first == '"' as u16 { '"' } else { ' ' }) as u16;

    loop {
        let next = cmd_line_iter.next();
        let next = match next {
            Some(x) => x,
            None => return vec![0u16; 0]
        };

        if next == end_char {
            break;
        }
    }

    // Now we need to skip any whitespace
    let cmd_line_iter = cmd_line_iter.skip_while(|x| x == &(' ' as u16));

    cmd_line_iter.collect()
}

fn run_dbgx_shell(version_install_dir: &Path) {
    let mut command_line = parse_command_line();
    let mut si: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let dbgx_path = version_install_dir.join("DbgX.Shell.exe");
    let mut dbgx_command_line = vec![0u16; 0];
    dbgx_command_line.push('"' as u16);
    let mut dbgx_path: Vec<u16> = dbgx_path.as_os_str().encode_wide().collect();
    dbgx_command_line.append(&mut dbgx_path);
    dbgx_command_line.push('"' as u16);
    dbgx_command_line.push(' ' as u16);
    dbgx_command_line.append(&mut command_line);
    dbgx_command_line.push(0u16);

    println!("Executing command line: {}", OsString::from_wide(&dbgx_command_line).to_string_lossy());
    let ret = unsafe {
        CreateProcessW(
            None,
            PWSTR::from_raw(dbgx_command_line.as_mut_ptr()),
            None,
            None,
            true,
            PROCESS_CREATION_FLAGS::default(),
            None,
            None,
            &mut si.StartupInfo,
            &mut pi,
        )
    };

    if ret.as_bool() {
        unsafe { WaitForSingleObject(pi.hProcess, INFINITE) };
    } else {
        println!("Could not launch DbgX.Shell.exe");
    }
}

fn main() {
    let current_exe = std::env::current_exe().unwrap();
    let exe_path = current_exe.parent().unwrap().to_owned();
    let install_dir = exe_path;

    let current_version = get_installed_version(&install_dir);

    if let Some(version) = &current_version {
        let version_path = install_dir.join(version);
        let thread = std::thread::spawn(move || {
            run_dbgx_shell(&version_path);
        });

        // Check for new versions in the background
        check_for_new_version(&install_dir, current_version);

        thread.join().unwrap();
    } else {
        let new_version = check_for_new_version(&install_dir, current_version);

        if let Some(new_version) = new_version {
            let version_install_dir = install_dir.join(&new_version);
            // Now that we're installed, run DbgX.Shell.exe with the given parameters
            run_dbgx_shell(&version_install_dir);    
        }
    }
}
