use std::io::{self, Read, Seek, SeekFrom};
use reqwest::header::RANGE;

pub struct HttpRangeReader {
    url: String,
    client: reqwest::blocking::Client,
    content_length: u64,
    position: u64,
    offset: u64,
}

impl HttpRangeReader {
    pub fn new(url: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let client = reqwest::blocking::Client::new();
        let response = client.head(url).send()?;

        let content_length = response
            .headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse().ok())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Invalid content length"))?;

        Ok(HttpRangeReader {
            url: url.to_string(),
            client,
            content_length,
            position: 0,
            offset: 0,
        })
    }

    pub fn len(&self) -> u64 {
        self.content_length
    }

    pub fn cursor_at(&self, offset: u64) -> HttpRangeCursor {
        HttpRangeCursor
        {
            url: self.url.to_string(),
            client: self.client.clone(),
            content_length: self.content_length - offset,
            position: self.offset + offset,
        }
    }

    pub fn make_slice_reader(&self, offset: u64, length: u64) -> HttpRangeReader {
        HttpRangeReader
        {
            url: self.url.clone(),
            client: self.client.clone(),
            content_length: length,
            position: 0,
            offset: self.offset + offset
        }
    }

    pub fn get_stream(&mut self) -> io::Result<reqwest::blocking::Response> {
        let response = self.client.get(&self.url)
                                  .header(RANGE, format!("bytes={}-{}", self.offset, self.offset + self.content_length - 1))
                                  .send().map_err(map_reqwest_error_to_io_error)?;
        Ok(response)
    }
}

pub struct HttpRangeCursor {
    url: String,
    client: reqwest::blocking::Client,
    content_length: u64,
    position: u64,
}

fn map_reqwest_error_to_io_error(req_err: reqwest::Error) -> io::Error {
    io::Error::new(io::ErrorKind::Other, req_err.to_string())
}

impl Read for HttpRangeReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let data_left = self.content_length - self.position;
        let req_len = buf.len() as u64;
        let req_len = if req_len > data_left { data_left } else { req_len };
        if req_len == 0 {
            return Ok(0);
        }

        let position = self.position + self.offset;
        let mut response = self.client.get(&self.url)
                                  .header(RANGE, format!("bytes={}-{}", position, position + req_len - 1))
                                  .send().map_err(map_reqwest_error_to_io_error)?;
        let req_len = req_len as usize;
        let bytes_read = response.read(&mut buf[0..req_len])?;
        self.position += bytes_read as u64;
        Ok(bytes_read)
    }
}

impl Read for HttpRangeCursor {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let req_len = buf.len() as u64;
        let mut response = self.client.get(&self.url)
                                  .header(RANGE, format!("bytes={}-{}", self.position, self.position + req_len - 1))
                                  .send().map_err(map_reqwest_error_to_io_error)?;
        let bytes_read = response.read(buf)?;
        self.position += bytes_read as u64;
        Ok(bytes_read)
    }
}

impl Seek for HttpRangeReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_position = match pos {
            SeekFrom::Start(offset) => offset,
            SeekFrom::End(offset) => self.content_length.saturating_sub(offset as u64),
            SeekFrom::Current(offset) => self.position.saturating_add(offset as u64),
        };

        if new_position > self.content_length {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid seek position",
            ));
        }

        self.position = new_position;
        Ok(new_position)
    }
}