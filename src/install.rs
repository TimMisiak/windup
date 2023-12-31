use tokio::*;
use windows::{Win32::{System::{Threading::{IsWow64Process2, GetCurrentProcess}, SystemInformation::{IMAGE_FILE_MACHINE, IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_I386, IMAGE_FILE_MACHINE_ARM64}}, Security::WinTrust::{WINTRUST_DATA, WTD_UI_NONE, WTD_REVOKE_NONE, WINTRUST_FILE_INFO, WINTRUST_ACTION_GENERIC_VERIFY_V2, WTD_CHOICE_FILE, WTD_STATEACTION_VERIFY, WinVerifyTrust}, Foundation::ERROR_SUCCESS}, core::{PCWSTR, HSTRING}};
use core::panic;
use std::{error::Error, io::{Read, Seek, Write}, path::Path, fs::File};
use reqwest::blocking::get;
use roxmltree::Document;
use rc_zip::{*, reader::{ArchiveReaderResult, ArchiveReader, sync::{EntryReader, SyncArchive}}};
use rc_zip::prelude::*;

use crate::range_reader::{HttpRangeReader, HttpRangeCursor};


#[derive(Debug)]
struct StrError {
    msg: String
}

impl core::fmt::Display for StrError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{}", self.msg)?;
        Ok(())
    }
}

impl Error for StrError {
}

impl StrError {
    pub fn make<T>(msg: &str) -> Result<T, Box<dyn Error>> {
        Err(Box::new(StrError{msg: msg.to_string()}))
    }
}

// Returns (uri, version)
fn get_bundle_uri() -> Result<(String, String), Box<dyn Error>> {
    let url = "https://aka.ms/windbg/download";
    let resp = get(url)?.text()?;
    
    let doc = Document::parse(&resp)?;
    for node in doc.descendants() {
        if node.has_tag_name("AppInstaller") {
            for child in node.children() {
                if child.has_tag_name("MainBundle") {
                    if let Some(uri) = child.attribute("Uri") {
                        if let Some(version) = node.attribute("Version") {
                            return Ok((uri.to_string(), version.to_string()));
                        }
                    }
                }
            }
        }
    };
    Err(Box::new(StrError{msg: "Could not find attribute".to_string()}))
}

struct StreamInfo { entry_name: String, offset: u64 }

fn get_filename_for_architecture_from_bundle_manifest(manifest: &str, arch: &str) -> Result<StreamInfo, Box<dyn Error>> {
    let doc = Document::parse(manifest)?;
    for node in doc.descendants() {
        if node.has_tag_name("Package") {
            if let Some(package_arch) = node.attribute("Architecture") {
                if package_arch.eq(arch) {
                    if let Some(offset) = node.attribute("Offset") {
                        let offset: u64 = offset.parse()?;
                        return match node.attribute("FileName") {
                            Some(file) => Ok(StreamInfo { entry_name: file.to_string(), offset }),
                            None => StrError::make("FileName attribute missing on package")
                        };
                    } else {
                        return StrError::make("Found package for architecture but it had no 'Offset' attribute");
                    }                    
                }
            }
        }
    };
    Err(Box::new(StrError{msg: "Could not find package for architecture".to_string()}))
}

fn get_archive(reader: &mut ArchiveReader, http_source: &mut HttpRangeReader) -> Archive {
    loop {
        match reader.process().unwrap() {
            ArchiveReaderResult::Continue => {
                if let Some(addr) = reader.wants_read() {
                    http_source.seek(io::SeekFrom::Start(addr)).unwrap();
                    reader.read(http_source).unwrap();
                }
            },
            ArchiveReaderResult::Done(archive) => { return archive; }
        }
    }
}

fn read_file_from_entry<'a>(entry: &'a StoredEntry, http_source: &'a HttpRangeReader) -> EntryReader<'a, HttpRangeCursor> {
    EntryReader::new(entry, |offset| {
        http_source.cursor_at(offset)
    })
}

fn extract_archive(archive: SyncArchive<'_, File>, dest_dir: &Path) {
    println!("Downloading and extracting archive");
    for entry in archive.entries() {
        let name = (*entry).name();
        if name.contains("..") {
            panic!("The '..' sequence was found");
        }
        println!("Extracting {}", name);
        let mut file_reader = entry.reader();
        let dest_path = dest_dir.join(name);
        if !dest_path.as_path().exists() {
            if let Some(parent) = dest_path.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            let mut dest_file = File::create(dest_path).unwrap();
            std::io::copy(&mut file_reader, &mut dest_file).unwrap();
        }
    }
}


// There's a catalog file inside the msix, but maybe this is already what's used for verifying
// the archive itself if you use WinVerifyTrust on it.
//fn verify_files(dir: &Path) -> bool {
//    let mut wintrust_data = WINTRUST_DATA::default();
//    wintrust_data.cbStruct = std::mem::size_of::<WINTRUST_DATA>() as u32;
//    wintrust_data.dwUIChoice = WTD_UI_NONE;
//    wintrust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
//    wintrust_data.dwUnionChoice = WTD_CHOICE_CATALOG;
//
//    let mut catalog_info = WINTRUST_CATALOG_INFO::default();
//    catalog_info.cbStruct = std::mem::size_of::<WINTRUST_CATALOG_INFO>() as u32;
//    let cat_path = dir.join("AppxMetadata/CodeIntegrity.cat");
//}

fn verify_archive(file: &Path) -> bool {
    let mut file_data = WINTRUST_FILE_INFO::default();
    file_data.cbStruct = std::mem::size_of::<WINTRUST_FILE_INFO>() as u32;
    //let file_os_path = file.as_os_str().to_os_string();
    let file_string = HSTRING::from(file);
    file_data.pcwszFilePath = PCWSTR::from_raw(file_string.as_ptr());
    let mut policy_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    
    let mut wintrust_data = WINTRUST_DATA::default();
    wintrust_data.cbStruct = std::mem::size_of::<WINTRUST_DATA>() as u32;
    wintrust_data.dwUIChoice = WTD_UI_NONE;
    wintrust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
    wintrust_data.dwUnionChoice = WTD_CHOICE_FILE;
    wintrust_data.dwStateAction = WTD_STATEACTION_VERIFY;
    wintrust_data.Anonymous.pFile = &mut file_data;

    let status = unsafe { WinVerifyTrust(None, &mut policy_guid, (&mut wintrust_data) as *mut _ as *mut core::ffi::c_void) };

    drop(file_data);
    drop(file_string);

    if status == ERROR_SUCCESS.0 as i32 {
        println!("Signature verified!");
        true
    } else {
        println!("Signature failed verification, error: {:x}", status);
        false
    }
}


pub fn get_installed_version(install_dir: &Path) -> Option<String> {
    let file = File::open(install_dir.join("version.txt"));
    let mut file = match file {
        Ok(file) => file,
        Err(_) => return None
    };
    let mut contents = String::new();
    let result = file.read_to_string(&mut contents);
    if result.is_err() {
        None
    } else {
        Some(contents)
    }
}

pub fn set_installed_version(install_dir: &Path, version: &str) -> io::Result<()> {
    let mut file = File::create(install_dir.join("version.txt"))?;
    file.write_all(version.as_bytes())?;
    Ok(())
}

pub fn check_for_new_version(install_dir: &Path, current_version: Option<String>) -> Option<String> {

    let (bundle_uri, version) = get_bundle_uri().unwrap();

    if let Some(current_version) = current_version {
        if current_version == version {
            println!("No new version available");
            return Some(version);
        }
    }

    let start_everything = std::time::Instant::now();

    let mut process_machine: IMAGE_FILE_MACHINE = IMAGE_FILE_MACHINE::default();
    let mut native_machine: IMAGE_FILE_MACHINE = IMAGE_FILE_MACHINE::default();
    unsafe { IsWow64Process2(GetCurrentProcess(), &mut process_machine, Some(&mut native_machine)) };

    let install_arch = match native_machine {
        IMAGE_FILE_MACHINE_AMD64 => "x64",
        IMAGE_FILE_MACHINE_I386 => "x86",
        IMAGE_FILE_MACHINE_ARM64 => "arm64",
        _ => panic!("Unrecognized machine architecture"),
    };

    let version_install_dir = install_dir.join(&version);

    println!("Found version: {}, bundle URI is: {}", version, bundle_uri);

    let mut http_source = HttpRangeReader::new(&bundle_uri).unwrap();

    let mut reader = rc_zip::reader::ArchiveReader::new(http_source.len());

    let archive = get_archive(&mut reader, &mut http_source);

    // First, we find the name of the msix for the architecture we're looking for
    let mut msix_info: Option<StreamInfo> = None;

    for entry in archive.entries() {
        println!("{}", (*entry).name());
        if entry.name().eq("AppxMetadata/AppxBundleManifest.xml") {
            let mut manifest_reader = read_file_from_entry(entry, &http_source);
            let mut manifest_buffer = String::new();
            manifest_reader.read_to_string(&mut manifest_buffer).unwrap();
            msix_info = Some(get_filename_for_architecture_from_bundle_manifest(&manifest_buffer, install_arch).unwrap());
            break;
        }
    }

    // Find the entry for the msix file and then extract it to the installation directory.
    let msix_info = msix_info.unwrap();
    for entry in archive.entries() {
        if entry.name().eq(&msix_info.entry_name) {
            // TODO: Check name for '..'
            println!("Found package for architecture: {}", msix_info.entry_name);
            if entry.entry.method == Method::Store {
                println!("Found entry: {} - {}", msix_info.offset, entry.header_offset);
                let mut msix_stream = http_source.make_slice_reader(msix_info.offset, entry.compressed_size);

                let dest_path = version_install_dir.join(&msix_info.entry_name);

                if let Some(parent) = dest_path.parent() {
                    std::fs::create_dir_all(parent).unwrap();
                }
                let mut dest_file = File::create(&dest_path).unwrap();

                let mut req_stream = msix_stream.get_stream().unwrap();

                println!("Copying msix locally");
                let start = std::time::Instant::now();
                std::io::copy(&mut req_stream, &mut dest_file).unwrap();
                let elapsed = start.elapsed();
                println!("Time to download: {:?}", elapsed);

                drop(dest_file);

                println!("Verifying certificates on {}", dest_path.as_path().to_str().unwrap());
                let start = std::time::Instant::now();
                if !verify_archive(dest_path.as_path()) {
                    return None;
                }
                let elapsed = start.elapsed();
                println!("Time to verify: {:?}", elapsed);

                let src_file = File::open(dest_path).unwrap();
                let archive = src_file.read_zip().unwrap();
                println!("Extracting msix");
                let start = std::time::Instant::now();
                extract_archive(archive, version_install_dir.as_path());
                let elapsed = start.elapsed();
                println!("Time to extract msix: {:?}", elapsed);
            } else {
                println!("NYI: the embedded zip file was compressed, instead of being stored directly.");
            }
        }
    }

    let elapsed = start_everything.elapsed();
    println!("Installed successfully. Time to install: {:?}", elapsed);

    if set_installed_version(&install_dir, &version).is_err() {
        println!("Could not update installed version");
    };

    return Some(version);
}