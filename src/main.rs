use tokio::*;
use core::panic;
use std::{error::Error, io::{Read, Seek}, path::Path, fs::File};
use reqwest::blocking::get;
use roxmltree::Document;
use rc_zip::{*, reader::{ArchiveReaderResult, ArchiveReader, sync::EntryReader}};
use rc_zip::{prelude::*, EntryContents};

mod range_reader;
use range_reader::{HttpRangeReader, HttpRangeCursor};


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

fn extract_archive(archive: Archive, stream: &mut HttpRangeReader, dest_dir: &str) {
    let root = Path::new(dest_dir);
    println!("Downloading and extracting archive");
    for entry in archive.entries() {
        // TODO: Use CRCs to skip files already downloaded from previous versions?
        let name = (*entry).name();
        if name.contains("..") {
            panic!("The '..' sequence was found");
        }
        println!("{} - {}", name, (*entry).crc32);
        let mut file_reader = read_file_from_entry(entry, stream);
        let dest_path = root.join(name);
        if !dest_path.as_path().exists() {
            if let Some(parent) = dest_path.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            let mut dest_file = File::create(dest_path).unwrap();
            std::io::copy(&mut file_reader, &mut dest_file).unwrap();
        }
    }
}

fn main() {
    let (bundle_uri, version) = get_bundle_uri().unwrap();

    // TODO: Check if version is different from existing installed version
    // TODO: Allow configuration of installation directory
    println!("{} - {}", version, bundle_uri);

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
            msix_info = Some(get_filename_for_architecture_from_bundle_manifest(&manifest_buffer, "x64").unwrap());
            break;
        }
    }

    let msix_info = msix_info.unwrap();

    for entry in archive.entries() {
        if entry.name().eq(&msix_info.entry_name) {
            println!("Found package for architecture: {}", msix_info.entry_name);
            if entry.entry.method == Method::Store {
                println!("Found entry: {} - {}", msix_info.offset, entry.header_offset);
                let mut msix_stream = http_source.make_slice_reader(msix_info.offset, entry.compressed_size);
                let mut msix_reader = rc_zip::reader::ArchiveReader::new(msix_stream.len());
                let msix_archive = get_archive(&mut msix_reader, &mut msix_stream);
                extract_archive(msix_archive, &mut msix_stream, "C:\\Debuggers");
            } else {
                println!("NYI: the embedded zip file was compressed, instead of being stored directly.");
            }
        }
    }

    // Now download and extract the msix to the target directory
    
    //let response = reqwest::blocking::get(bundle_uri).unwrap();

    //ZipArchive::new()
    //response.
}
