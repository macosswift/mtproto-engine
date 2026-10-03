use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use mtproto_core::crypto::{AesCtr, SecureRandom, XorShiftRandom, sha256};
use mtproto_core::tl::{Reader, Writer, ids};

pub const UPLOAD_GET_FILE: u32 = 0xbe53_35be;
pub const UPLOAD_GET_CDN_FILE: u32 = 0x395f_69da;
pub const UPLOAD_REUPLOAD_CDN_FILE: u32 = 0x9b27_54a8;
pub const UPLOAD_GET_CDN_FILE_HASHES: u32 = 0x91dc_3f31;
pub const AUTH_EXPORT_AUTHORIZATION: u32 = 0xe5bf_ffcd;
pub const AUTH_IMPORT_AUTHORIZATION: u32 = 0xa57a_7dad;
pub const HELP_GET_CDN_CONFIG: u32 = 0x5202_9342;
pub const HELP_GET_NEAREST_DC: u32 = 0x1fb3_3026;
pub const UPLOAD_SAVE_FILE_PART: u32 = 0xb304_a621;
pub const UPLOAD_SAVE_BIG_FILE_PART: u32 = 0xde7b_673d;

pub const UPLOAD_FILE: u32 = 0x096a_18d5;
pub const UPLOAD_FILE_CDN_REDIRECT: u32 = 0xf18c_da44;
pub const UPLOAD_CDN_FILE: u32 = 0xa99f_ca4f;
pub const UPLOAD_CDN_FILE_REUPLOAD_NEEDED: u32 = 0xeea8_e46e;
pub const FILE_HASH: u32 = 0xf39b_035c;
pub const STORAGE_FILE_PARTIAL: u32 = 0x40bc_6f52;
pub const AUTH_EXPORTED_AUTHORIZATION: u32 = 0xb434_e2b8;
pub const AUTH_AUTHORIZATION: u32 = 0x2ea2_c0d4;
pub const USER_EMPTY: u32 = 0xd3bc_4b7a;
pub const CDN_CONFIG: u32 = 0x5725_e40a;
pub const NEAREST_DC: u32 = 0x8e1a_1775;
pub const INPUT_DOCUMENT_FILE_LOCATION: u32 = 0xbad0_7584;
pub const INPUT_PHOTO_FILE_LOCATION: u32 = 0x4018_1ffe;

pub const MEGABYTE: u64 = 1 << 20;
/// Uploaded files are made of blocks of this size, each starting with its index and the file's tag
/// (`upload_content`).
pub const UPLOAD_BLOCK: usize = 1024;
const UPLOAD_HEADER: usize = 16;
pub const UPLOAD_MAX_PART: usize = 512 * 1024;
const UPLOAD_CONTENT_ID: i64 = 0x5550_4c4f_4144;
pub const CDN_HASH_CHUNK: u64 = 128 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileSpec {
    pub id: i64,
    pub datacenter_id: i32,
    pub size: u64,
    pub cdn: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CdnFault {
    #[default]
    None,
    CorruptData,
    EndlessReupload,
    NoHashes,
    TokenInvalid,
    Truncated,
    BadRedirectKey,
}

impl CdnFault {
    pub const ALL: [CdnFault; 6] = [
        CdnFault::CorruptData,
        CdnFault::EndlessReupload,
        CdnFault::NoHashes,
        CdnFault::TokenInvalid,
        CdnFault::Truncated,
        CdnFault::BadRedirectKey,
    ];

    pub fn name(self) -> &'static str {
        match self {
            CdnFault::None => "none",
            CdnFault::CorruptData => "corrupt-data",
            CdnFault::EndlessReupload => "endless-reupload",
            CdnFault::NoHashes => "no-hashes",
            CdnFault::TokenInvalid => "token-invalid",
            CdnFault::Truncated => "truncated",
            CdnFault::BadRedirectKey => "bad-redirect-key",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorldOptions {
    pub main_datacenter_id: i32,
    pub cdn_datacenter_id: i32,
    pub reupload_needed: bool,
    pub cdn_fault: CdnFault,
}

impl Default for WorldOptions {
    fn default() -> Self {
        Self { main_datacenter_id: 2, cdn_datacenter_id: 203, reupload_needed: true, cdn_fault: CdnFault::None }
    }
}

#[derive(Debug, Default, Clone)]
pub struct ApiStats {
    pub get_file: usize,
    pub get_cdn_file: usize,
    pub cdn_redirects: usize,
    pub reupload_needed: usize,
    pub reuploads: usize,
    pub hash_requests: usize,
    pub exports: usize,
    pub imports: usize,
    pub unauthorized: usize,
    pub invalid_ranges: usize,
    pub bytes_served: u64,
    pub file_requests: HashMap<(i64, u64), usize>,
    pub cdn_requests: HashMap<(i64, u64), usize>,
    pub upload_parts: usize,
    pub upload_bytes: u64,
    /// Parts received again after they were already stored.
    pub upload_duplicates: usize,
    /// Parts whose bytes or position did not match what the client must have sent.
    pub upload_bad_parts: usize,
    pub upload_largest_part: usize,
}

pub enum ApiReply {
    Result(Vec<u8>),
    Error(i32, String),
}

struct CdnToken {
    file_id: i64,
    source_datacenter_id: i32,
    key: [u8; 32],
    iv: [u8; 16],
    uploaded: HashSet<u64>,
    request_tokens: HashMap<Vec<u8>, u64>,
}

struct WorldState {
    files: HashMap<i64, FileSpec>,
    families: HashMap<u64, u64>,
    authorized: HashSet<(i32, u64)>,
    exports: HashMap<i64, (i32, Vec<u8>)>,
    cdn_tokens: HashMap<Vec<u8>, CdnToken>,
    uploads: HashMap<i64, UploadState>,
    rng: XorShiftRandom,
    stats: ApiStats,
}

#[derive(Default)]
struct UploadState {
    /// The part size implied by a part's position, once a part other than the first arrived.
    part_size: Option<u64>,
    /// The file tag every block carries.
    tag: Option<u64>,
    /// Received parts and their lengths.
    parts: HashMap<i32, usize>,
    /// Parts too short to carry a block header, kept until the part size and tag are known.
    short_parts: Vec<(i32, Vec<u8>)>,
    bad: bool,
}

impl UploadState {
    /// The size of every part but the last: implied by a later part's offset, or else part 0's length.
    fn part_size(&self) -> Option<u64> {
        self.part_size
            .or_else(|| self.parts.get(&0).filter(|length| **length >= UPLOAD_HEADER).map(|length| *length as u64))
    }
}

/// One uploaded file as the server holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadedFile {
    pub tag: Option<u64>,
    pub bytes: u64,
    /// Every part from 0 to the last arrived, every part but the last has the part size, and no part was bad.
    pub complete: bool,
}

pub struct ApiWorld {
    options: WorldOptions,
    state: Mutex<WorldState>,
}

impl std::fmt::Debug for ApiWorld {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("ApiWorld").field("options", &self.options).finish_non_exhaustive()
    }
}

pub fn file_word(file_id: i64, word: u64) -> u64 {
    let mut z = (file_id as u64) ^ word.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    z = z.wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

pub fn file_content(file_id: i64, offset: u64, length: usize) -> Vec<u8> {
    let mut data = Vec::with_capacity(length + 16);
    let first_word = offset / 8;
    let skip = (offset % 8) as usize;
    let mut word = first_word;
    while data.len() < length + skip {
        data.extend_from_slice(&file_word(file_id, word).to_le_bytes());
        word += 1;
    }
    data.drain(..skip);
    data.truncate(length);
    data
}

/// The bytes of the upload tagged `tag` from `offset` on: every `UPLOAD_BLOCK` bytes start with the
/// block's index and the tag, so a part says where it belongs whatever the client's part size, and
/// parts of two files cannot be swapped unnoticed.
pub fn upload_content(tag: u64, offset: u64, length: usize) -> Vec<u8> {
    let mut data = Vec::with_capacity(length);
    let mut position = offset;
    while data.len() < length {
        let block = position / UPLOAD_BLOCK as u64;
        let within = (position % UPLOAD_BLOCK as u64) as usize;
        let mut block_bytes = block.to_le_bytes().to_vec();
        block_bytes.extend_from_slice(&tag.to_le_bytes());
        block_bytes.extend_from_slice(&file_content(
            UPLOAD_CONTENT_ID,
            block * UPLOAD_BLOCK as u64 + UPLOAD_HEADER as u64,
            UPLOAD_BLOCK - UPLOAD_HEADER,
        ));
        let take = (UPLOAD_BLOCK - within).min(length - data.len());
        data.extend_from_slice(&block_bytes[within..within + take]);
        position += take as u64;
    }
    data
}

/// Where a received part starts and its file's tag, read from its first block, if its bytes are
/// what `upload_content` makes there.
fn upload_part_offset(bytes: &[u8]) -> Option<(u64, u64)> {
    if bytes.len() < UPLOAD_HEADER {
        return None;
    }
    let block = u64::from_le_bytes(bytes[..8].try_into().ok()?);
    let tag = u64::from_le_bytes(bytes[8..16].try_into().ok()?);
    let offset = block.checked_mul(UPLOAD_BLOCK as u64)?;
    (upload_content(tag, offset, bytes.len()) == bytes).then_some((offset, tag))
}

pub fn cdn_iv(base: &[u8; 16], offset: u64) -> [u8; 16] {
    let mut iv = *base;
    iv[12..16].copy_from_slice(&((offset / 16) as u32).to_be_bytes());
    iv
}

fn write_file_hashes(writer: &mut Writer, file_id: i64, size: u64, offset: u64, span: u64) {
    let start = offset - offset % CDN_HASH_CHUNK;
    let end = (start + span).min(size);
    let mut chunks = Vec::new();
    let mut position = start;
    while position < end {
        let limit = CDN_HASH_CHUNK.min(size - position);
        chunks.push((position, limit));
        position += CDN_HASH_CHUNK;
    }
    writer.write_vector_header(chunks.len());
    for (position, available) in chunks {
        writer.write_u32(FILE_HASH);
        writer.write_i64(position as i64);
        writer.write_i32(CDN_HASH_CHUNK as i32);
        writer.write_bytes(&sha256(&file_content(file_id, position, available as usize)));
    }
}

fn read_location(reader: &mut Reader<'_>) -> Option<(i64, i64)> {
    match reader.read_u32().ok()? {
        INPUT_DOCUMENT_FILE_LOCATION | INPUT_PHOTO_FILE_LOCATION => {
            let id = reader.read_i64().ok()?;
            let access_hash = reader.read_i64().ok()?;
            reader.read_bytes().ok()?;
            reader.read_bytes().ok()?;
            Some((id, access_hash))
        }
        _ => None,
    }
}

fn valid_range(offset: u64, limit: u64, precise: bool) -> bool {
    if limit == 0 || limit > MEGABYTE {
        return false;
    }
    let alignment = if precise { 1024 } else { 4096 };
    if !offset.is_multiple_of(alignment) || !limit.is_multiple_of(alignment) {
        return false;
    }
    if !precise && !MEGABYTE.is_multiple_of(limit) {
        return false;
    }
    offset / MEGABYTE == (offset + limit - 1) / MEGABYTE
}

impl ApiWorld {
    pub fn new(options: WorldOptions, files: &[FileSpec], seed: u64) -> Self {
        Self {
            options,
            state: Mutex::new(WorldState {
                files: files.iter().map(|file| (file.id, *file)).collect(),
                families: HashMap::new(),
                authorized: HashSet::new(),
                exports: HashMap::new(),
                cdn_tokens: HashMap::new(),
                uploads: HashMap::new(),
                rng: XorShiftRandom::new(seed),
                stats: ApiStats::default(),
            }),
        }
    }

    pub fn options(&self) -> WorldOptions {
        self.options
    }

    pub fn register_key(&self, key_id: u64, family: u64) {
        self.state.lock().unwrap().families.insert(key_id, family);
    }

    pub fn revoke_authorization(&self, datacenter_id: i32) {
        self.state.lock().unwrap().authorized.retain(|(dc, _)| *dc != datacenter_id);
    }

    pub fn stats(&self) -> ApiStats {
        self.state.lock().unwrap().stats.clone()
    }

    /// The uploads the server received, by file.
    pub fn uploaded_files(&self) -> Vec<UploadedFile> {
        let state = self.state.lock().unwrap();
        state
            .uploads
            .values()
            .map(|upload| {
                let last = upload.parts.keys().copied().max().unwrap_or(-1);
                let bytes: u64 = upload.parts.values().map(|length| *length as u64).sum();
                let contiguous = (0..=last).all(|part| upload.parts.contains_key(&part));
                let sized = match upload.part_size() {
                    Some(size) => upload.parts.iter().all(|(part, length)| *part == last || *length as u64 == size),
                    None => last == 0,
                };
                UploadedFile {
                    tag: upload.tag,
                    bytes,
                    complete: last >= 0 && contiguous && sized && upload.short_parts.is_empty() && !upload.bad,
                }
            })
            .collect()
    }

    pub fn handles(constructor: u32) -> bool {
        matches!(
            constructor,
            UPLOAD_GET_FILE
                | UPLOAD_GET_CDN_FILE
                | UPLOAD_REUPLOAD_CDN_FILE
                | UPLOAD_GET_CDN_FILE_HASHES
                | AUTH_EXPORT_AUTHORIZATION
                | AUTH_IMPORT_AUTHORIZATION
                | HELP_GET_CDN_CONFIG
                | HELP_GET_NEAREST_DC
                | UPLOAD_SAVE_FILE_PART
                | UPLOAD_SAVE_BIG_FILE_PART
        )
    }

    pub fn handle(&self, datacenter_id: i32, key_id: u64, constructor: u32, body: &[u8]) -> ApiReply {
        let mut state = self.state.lock().unwrap();
        let family = state.families.get(&key_id).copied().unwrap_or(key_id);
        let mut reader = Reader::new(body);
        match constructor {
            UPLOAD_GET_FILE => self.get_file(&mut state, datacenter_id, family, &mut reader),
            UPLOAD_GET_CDN_FILE => self.get_cdn_file(&mut state, datacenter_id, &mut reader),
            UPLOAD_REUPLOAD_CDN_FILE => self.reupload(&mut state, datacenter_id, &mut reader),
            UPLOAD_GET_CDN_FILE_HASHES => self.hashes(&mut state, datacenter_id, &mut reader),
            AUTH_EXPORT_AUTHORIZATION => {
                let Ok(target) = reader.read_i32() else {
                    return ApiReply::Error(400, "INPUT_REQUEST_INVALID".into());
                };
                if datacenter_id != self.options.main_datacenter_id {
                    return ApiReply::Error(400, "DC_ID_INVALID".into());
                }
                state.stats.exports += 1;
                let id = state.rng.next_u64() as i64;
                let mut bytes = vec![0u8; 32];
                state.rng.fill(&mut bytes);
                state.exports.insert(id, (target, bytes.clone()));
                let mut writer = Writer::new();
                writer.write_u32(AUTH_EXPORTED_AUTHORIZATION);
                writer.write_i64(id);
                writer.write_bytes(&bytes);
                ApiReply::Result(writer.into_inner())
            }
            AUTH_IMPORT_AUTHORIZATION => {
                let (Ok(id), Ok(bytes)) = (reader.read_i64(), reader.read_bytes()) else {
                    return ApiReply::Error(400, "INPUT_REQUEST_INVALID".into());
                };
                match state.exports.get(&id) {
                    Some((target, expected)) if *target == datacenter_id && expected == bytes => {
                        state.stats.imports += 1;
                        state.authorized.insert((datacenter_id, family));
                        let mut writer = Writer::new();
                        writer.write_u32(AUTH_AUTHORIZATION);
                        writer.write_i32(0);
                        writer.write_u32(USER_EMPTY);
                        writer.write_i64(1000);
                        ApiReply::Result(writer.into_inner())
                    }
                    _ => ApiReply::Error(400, "AUTH_BYTES_INVALID".into()),
                }
            }
            HELP_GET_CDN_CONFIG => {
                let mut writer = Writer::new();
                writer.write_u32(CDN_CONFIG);
                writer.write_vector_header(0);
                ApiReply::Result(writer.into_inner())
            }
            UPLOAD_SAVE_FILE_PART | UPLOAD_SAVE_BIG_FILE_PART => {
                self.save_file_part(&mut state, datacenter_id, constructor == UPLOAD_SAVE_BIG_FILE_PART, &mut reader)
            }
            HELP_GET_NEAREST_DC => {
                let mut writer = Writer::new();
                writer.write_u32(NEAREST_DC);
                writer.write_bytes(b"NL");
                writer.write_i32(datacenter_id);
                writer.write_i32(datacenter_id);
                ApiReply::Result(writer.into_inner())
            }
            _ => ApiReply::Error(400, "METHOD_INVALID".into()),
        }
    }

    fn save_file_part(
        &self,
        state: &mut WorldState,
        datacenter_id: i32,
        big: bool,
        reader: &mut Reader<'_>,
    ) -> ApiReply {
        let (Ok(file_id), Ok(part)) = (reader.read_i64(), reader.read_i32()) else {
            return ApiReply::Error(400, "INPUT_REQUEST_INVALID".into());
        };
        if big && reader.read_i32().is_err() {
            return ApiReply::Error(400, "INPUT_REQUEST_INVALID".into());
        }
        let Ok(bytes) = reader.read_bytes() else {
            return ApiReply::Error(400, "INPUT_REQUEST_INVALID".into());
        };
        if datacenter_id != self.options.main_datacenter_id {
            return ApiReply::Error(400, "DC_ID_INVALID".into());
        }
        if part < 0 || bytes.is_empty() || bytes.len() > UPLOAD_MAX_PART {
            return ApiReply::Error(400, "FILE_PART_SIZE_INVALID".into());
        }
        state.stats.upload_parts += 1;
        state.stats.upload_bytes += bytes.len() as u64;
        state.stats.upload_largest_part = state.stats.upload_largest_part.max(bytes.len());
        let upload = state.uploads.entry(file_id).or_default();
        if upload.parts.insert(part, bytes.len()).is_some() {
            state.stats.upload_duplicates += 1;
        }
        let mut bad = 0;
        if bytes.len() < UPLOAD_HEADER {
            upload.short_parts.push((part, bytes.to_vec()));
        } else {
            let placed = match upload_part_offset(bytes) {
                Some((offset, tag)) if upload.tag.is_none_or(|known| known == tag) => {
                    upload.tag = Some(tag);
                    if part == 0 {
                        offset == 0
                    } else {
                        let implied = offset / part as u64;
                        let consistent = implied * part as u64 == offset
                            && bytes.len() as u64 <= implied
                            && upload.part_size.is_none_or(|size| size == implied);
                        if consistent {
                            upload.part_size = Some(implied);
                        }
                        consistent
                    }
                }
                _ => false,
            };
            if !placed {
                bad += 1;
            }
        }
        if let (Some(part_size), Some(tag)) = (upload.part_size(), upload.tag) {
            for (short_part, short_bytes) in std::mem::take(&mut upload.short_parts) {
                if upload_content(tag, short_part as u64 * part_size, short_bytes.len()) != short_bytes {
                    bad += 1;
                }
            }
        }
        if bad > 0 {
            upload.bad = true;
            state.stats.upload_bad_parts += bad;
        }
        let mut writer = Writer::new();
        writer.write_u32(ids::BOOL_TRUE);
        ApiReply::Result(writer.into_inner())
    }

    fn is_authorized(&self, state: &WorldState, datacenter_id: i32, family: u64) -> bool {
        datacenter_id == self.options.main_datacenter_id || state.authorized.contains(&(datacenter_id, family))
    }

    fn get_file(&self, state: &mut WorldState, datacenter_id: i32, family: u64, reader: &mut Reader<'_>) -> ApiReply {
        let Ok(flags) = reader.read_i32() else {
            return ApiReply::Error(400, "INPUT_REQUEST_INVALID".into());
        };
        let Some((file_id, _)) = read_location(reader) else {
            return ApiReply::Error(400, "LOCATION_INVALID".into());
        };
        let (Ok(offset), Ok(limit)) = (reader.read_i64(), reader.read_i32()) else {
            return ApiReply::Error(400, "INPUT_REQUEST_INVALID".into());
        };
        if datacenter_id == self.options.cdn_datacenter_id {
            return ApiReply::Error(400, "CDN_METHOD_INVALID".into());
        }
        let Some(file) = state.files.get(&file_id).copied() else {
            return ApiReply::Error(400, "FILE_ID_INVALID".into());
        };
        if file.datacenter_id != datacenter_id {
            return ApiReply::Error(303, format!("FILE_MIGRATE_{}", file.datacenter_id));
        }
        if !self.is_authorized(state, datacenter_id, family) {
            state.stats.unauthorized += 1;
            return ApiReply::Error(401, "AUTH_KEY_UNREGISTERED".into());
        }
        let (offset, limit) = (offset.max(0) as u64, limit.max(0) as u64);
        if !valid_range(offset, limit, flags & 1 != 0) {
            state.stats.invalid_ranges += 1;
            return ApiReply::Error(400, "LIMIT_INVALID".into());
        }
        state.stats.get_file += 1;
        *state.stats.file_requests.entry((file_id, offset)).or_insert(0) += 1;
        if file.cdn && flags & 2 != 0 {
            state.stats.cdn_redirects += 1;
            let mut token = vec![0u8; 16];
            state.rng.fill(&mut token);
            let key: [u8; 32] = state.rng.array();
            let mut iv: [u8; 16] = state.rng.array();
            iv[12..16].fill(0);
            state.cdn_tokens.insert(
                token.clone(),
                CdnToken {
                    file_id,
                    source_datacenter_id: datacenter_id,
                    key,
                    iv,
                    uploaded: HashSet::new(),
                    request_tokens: HashMap::new(),
                },
            );
            let mut writer = Writer::new();
            writer.write_u32(UPLOAD_FILE_CDN_REDIRECT);
            writer.write_i32(self.options.cdn_datacenter_id);
            writer.write_bytes(&token);
            writer.write_bytes(&key);
            if self.options.cdn_fault == CdnFault::BadRedirectKey {
                writer.write_bytes(&iv[..2]);
            } else {
                writer.write_bytes(&iv);
            }
            write_file_hashes(&mut writer, file.id, file.size, offset, MEGABYTE);
            return ApiReply::Result(writer.into_inner());
        }
        let end = (offset + limit).min(file.size);
        let length = end.saturating_sub(offset) as usize;
        state.stats.bytes_served += length as u64;
        let mut writer = Writer::with_capacity(length + 32);
        writer.write_u32(UPLOAD_FILE);
        writer.write_u32(STORAGE_FILE_PARTIAL);
        writer.write_i32(0);
        writer.write_bytes(&file_content(file.id, offset, length));
        ApiReply::Result(writer.into_inner())
    }

    fn get_cdn_file(&self, state: &mut WorldState, datacenter_id: i32, reader: &mut Reader<'_>) -> ApiReply {
        let (Ok(token), Ok(offset), Ok(limit)) = (reader.read_bytes(), reader.read_i64(), reader.read_i32()) else {
            return ApiReply::Error(400, "INPUT_REQUEST_INVALID".into());
        };
        if datacenter_id != self.options.cdn_datacenter_id {
            return ApiReply::Error(400, "CDN_METHOD_INVALID".into());
        }
        let token = token.to_vec();
        let (offset, limit) = (offset.max(0) as u64, limit.max(0) as u64);
        if limit == 0 || limit > MEGABYTE || offset % 4096 != 0 || limit % 4096 != 0 {
            state.stats.invalid_ranges += 1;
            return ApiReply::Error(400, "LIMIT_INVALID".into());
        }
        if self.options.cdn_fault == CdnFault::TokenInvalid {
            return ApiReply::Error(400, "FILE_TOKEN_INVALID".into());
        }
        let reupload_needed = self.options.reupload_needed;
        let request_token: Vec<u8> = state.rng.array::<16>().to_vec();
        let files = &state.files;
        let Some(entry) = state.cdn_tokens.get_mut(&token) else {
            return ApiReply::Error(400, "FILE_TOKEN_INVALID".into());
        };
        let Some(file) = files.get(&entry.file_id).copied() else {
            return ApiReply::Error(400, "FILE_TOKEN_INVALID".into());
        };
        let block = offset / MEGABYTE;
        if reupload_needed && (!entry.uploaded.contains(&block) || self.options.cdn_fault == CdnFault::EndlessReupload)
        {
            entry.request_tokens.insert(request_token.clone(), block);
            state.stats.reupload_needed += 1;
            let mut writer = Writer::new();
            writer.write_u32(UPLOAD_CDN_FILE_REUPLOAD_NEEDED);
            writer.write_bytes(&request_token);
            return ApiReply::Result(writer.into_inner());
        }
        let mut end = (offset + limit).min(file.size);
        if self.options.cdn_fault == CdnFault::Truncated {
            end = end.min(MEGABYTE);
        }
        let length = end.saturating_sub(offset) as usize;
        let mut data = file_content(file.id, offset, length);
        if self.options.cdn_fault == CdnFault::CorruptData && length > 0 {
            data[length / 2] ^= 0x5a;
        }
        AesCtr::new(&entry.key, &cdn_iv(&entry.iv, offset)).apply(&mut data);
        state.stats.get_cdn_file += 1;
        state.stats.bytes_served += length as u64;
        *state.stats.cdn_requests.entry((file.id, offset)).or_insert(0) += 1;
        let mut writer = Writer::with_capacity(length + 16);
        writer.write_u32(UPLOAD_CDN_FILE);
        writer.write_bytes(&data);
        ApiReply::Result(writer.into_inner())
    }

    fn reupload(&self, state: &mut WorldState, datacenter_id: i32, reader: &mut Reader<'_>) -> ApiReply {
        let (Ok(token), Ok(request_token)) = (reader.read_bytes(), reader.read_bytes()) else {
            return ApiReply::Error(400, "INPUT_REQUEST_INVALID".into());
        };
        let files = &state.files;
        let Some(entry) = state.cdn_tokens.get_mut(token) else {
            return ApiReply::Error(400, "FILE_TOKEN_INVALID".into());
        };
        if entry.source_datacenter_id != datacenter_id {
            return ApiReply::Error(400, "CDN_METHOD_INVALID".into());
        }
        let Some(block) = entry.request_tokens.remove(request_token) else {
            return ApiReply::Error(400, "REQUEST_TOKEN_INVALID".into());
        };
        let Some(file) = files.get(&entry.file_id).copied() else {
            return ApiReply::Error(400, "FILE_TOKEN_INVALID".into());
        };
        entry.uploaded.insert(block);
        state.stats.reuploads += 1;
        let mut writer = Writer::new();
        if self.options.cdn_fault == CdnFault::NoHashes {
            writer.write_vector_header(0);
            return ApiReply::Result(writer.into_inner());
        }
        write_file_hashes(&mut writer, file.id, file.size, block * MEGABYTE, MEGABYTE);
        ApiReply::Result(writer.into_inner())
    }

    fn hashes(&self, state: &mut WorldState, datacenter_id: i32, reader: &mut Reader<'_>) -> ApiReply {
        let (Ok(token), Ok(offset)) = (reader.read_bytes(), reader.read_i64()) else {
            return ApiReply::Error(400, "INPUT_REQUEST_INVALID".into());
        };
        let Some(entry) = state.cdn_tokens.get(token) else {
            return ApiReply::Error(400, "FILE_TOKEN_INVALID".into());
        };
        if entry.source_datacenter_id != datacenter_id {
            return ApiReply::Error(400, "CDN_METHOD_INVALID".into());
        }
        let Some(file) = state.files.get(&entry.file_id).copied() else {
            return ApiReply::Error(400, "FILE_TOKEN_INVALID".into());
        };
        state.stats.hash_requests += 1;
        let mut writer = Writer::new();
        if self.options.cdn_fault == CdnFault::NoHashes {
            writer.write_vector_header(0);
            return ApiReply::Result(writer.into_inner());
        }
        write_file_hashes(&mut writer, file.id, file.size, offset.max(0) as u64, MEGABYTE);
        ApiReply::Result(writer.into_inner())
    }
}

pub fn parse_vector_header(reader: &mut Reader<'_>) -> Option<usize> {
    (reader.read_u32().ok()? == ids::VECTOR).then(|| reader.read_i32().ok().map(|count| count as usize)).flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn world(reupload: bool) -> ApiWorld {
        let files = [
            FileSpec { id: 1, datacenter_id: 2, size: 300_000, cdn: false },
            FileSpec { id: 2, datacenter_id: 4, size: 3 * MEGABYTE + 77, cdn: false },
            FileSpec { id: 3, datacenter_id: 4, size: 2 * MEGABYTE + 5000, cdn: true },
        ];
        ApiWorld::new(WorldOptions { reupload_needed: reupload, ..WorldOptions::default() }, &files, 7)
    }

    fn get_file(file_id: i64, offset: i64, limit: i32) -> Vec<u8> {
        get_file_with_flags(0, file_id, offset, limit)
    }

    fn get_file_with_flags(flags: i32, file_id: i64, offset: i64, limit: i32) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.write_i32(flags);
        writer.write_u32(INPUT_DOCUMENT_FILE_LOCATION);
        writer.write_i64(file_id);
        writer.write_i64(42);
        writer.write_bytes(b"ref");
        writer.write_bytes(b"");
        writer.write_i64(offset);
        writer.write_i32(limit);
        writer.into_inner()
    }

    fn result(reply: ApiReply) -> Vec<u8> {
        match reply {
            ApiReply::Result(body) => body,
            ApiReply::Error(code, text) => panic!("unexpected error {code} {text}"),
        }
    }

    fn error(reply: ApiReply) -> (i32, String) {
        match reply {
            ApiReply::Result(_) => panic!("expected an error"),
            ApiReply::Error(code, text) => (code, text),
        }
    }

    #[test]
    fn content_is_deterministic_and_offset_consistent() {
        let whole = file_content(9, 0, 1000);
        assert_eq!(file_content(9, 13, 100), whole[13..113]);
        assert_ne!(file_content(10, 0, 64), whole[..64]);
    }

    fn save_part(file_id: i64, part: i32, bytes: &[u8], big: bool) -> (u32, Vec<u8>) {
        let mut writer = Writer::new();
        writer.write_i64(file_id);
        writer.write_i32(part);
        if big {
            writer.write_i32(-1);
        }
        writer.write_bytes(bytes);
        (if big { UPLOAD_SAVE_BIG_FILE_PART } else { UPLOAD_SAVE_FILE_PART }, writer.into_inner())
    }

    #[test]
    fn uploads_with_gaps_short_parts_swaps_or_tiny_tails_are_caught() {
        let world = world(true);
        let part = 16_384usize;
        let content = upload_content(1, 0, 3 * part + 3);
        for (index, range) in
            [(0usize, 0..part), (1, part..2 * part), (2, 2 * part..3 * part), (3, 3 * part..3 * part + 3)]
        {
            let (constructor, body) = save_part(11, index as i32, &content[range], false);
            result(world.handle(2, 1, constructor, &body));
        }
        let other = upload_content(2, 0, 2 * part);
        let (constructor, body) = save_part(12, 0, &other[..part], false);
        result(world.handle(2, 1, constructor, &body));
        let (constructor, body) = save_part(12, 1, &content[part..2 * part], false);
        result(world.handle(2, 1, constructor, &body));
        let (constructor, body) = save_part(13, 0, &content[..part], false);
        result(world.handle(2, 1, constructor, &body));
        let (constructor, body) = save_part(13, 1, &content[part..part + 100], false);
        result(world.handle(2, 1, constructor, &body));
        let (constructor, body) = save_part(13, 3, &content[3 * part..3 * part + 3], false);
        result(world.handle(2, 1, constructor, &body));
        let two = upload_content(3, 0, part + 5);
        let (constructor, body) = save_part(14, 1, &two[part..], false);
        result(world.handle(2, 1, constructor, &body));
        let (constructor, body) = save_part(14, 0, &two[..part], false);
        result(world.handle(2, 1, constructor, &body));
        let mut files = world.uploaded_files();
        files.sort_by_key(|file| file.bytes);
        let complete: Vec<u64> = files.iter().filter(|file| file.complete).map(|file| file.bytes).collect();
        assert_eq!(
            complete,
            vec![part as u64 + 5, 3 * part as u64 + 3],
            "a tiny tail is verified once the part size is known, from part 0 in a two-part file; {files:?}"
        );
        assert_eq!(world.stats().upload_bad_parts, 1, "the part swapped in from another file");
        assert_eq!(files.len(), 4);
    }

    #[test]
    fn upload_content_names_its_blocks_and_file() {
        let whole = upload_content(9, 0, 5000);
        assert_eq!(upload_content(9, 1024, 3000), whole[1024..4024]);
        assert_eq!(u64::from_le_bytes(whole[2048..2056].try_into().unwrap()), 2);
        assert_eq!(u64::from_le_bytes(whole[2056..2064].try_into().unwrap()), 9);
        assert_eq!(upload_part_offset(&whole[3072..]), Some((3072, 9)));
        assert_ne!(upload_content(10, 0, 64), whole[..64]);
        let mut corrupt = whole[1024..2048].to_vec();
        corrupt[500] ^= 1;
        assert_eq!(upload_part_offset(&corrupt), None);
    }

    #[test]
    fn uploads_verify_bytes_positions_and_duplicates() {
        let world = world(true);
        let size = 300_000usize;
        let part_size = 131_072usize;
        let content = upload_content(5, 0, size);
        for part in [2usize, 0, 1] {
            let end = (part * part_size + part_size).min(size);
            let (constructor, body) = save_part(77, part as i32, &content[part * part_size..end], false);
            let reply = result(world.handle(2, 1, constructor, &body));
            assert_eq!(Reader::new(&reply).read_u32().unwrap(), ids::BOOL_TRUE);
        }
        let stats = world.stats();
        assert_eq!(
            (stats.upload_parts, stats.upload_bytes, stats.upload_bad_parts, stats.upload_duplicates),
            (3, size as u64, 0, 0)
        );

        let (constructor, body) = save_part(77, 1, &content[part_size..2 * part_size], false);
        result(world.handle(2, 1, constructor, &body));
        assert_eq!(world.stats().upload_duplicates, 1);

        let (constructor, body) = save_part(78, 1, &content[part_size..2 * part_size], true);
        result(world.handle(2, 1, constructor, &body));
        assert_eq!(world.stats().upload_bad_parts, 0);
        let (constructor, body) = save_part(78, 2, &content[part_size..2 * part_size], true);
        result(world.handle(2, 1, constructor, &body));
        let mut corrupt = content[..part_size].to_vec();
        corrupt[9] ^= 0xff;
        let (constructor, body) = save_part(79, 0, &corrupt, true);
        result(world.handle(2, 1, constructor, &body));
        assert_eq!(world.stats().upload_bad_parts, 2, "a misplaced part and a corrupted part");

        let (constructor, body) = save_part(80, 0, &vec![0u8; UPLOAD_MAX_PART + 1], false);
        assert_eq!(error(world.handle(2, 1, constructor, &body)).1, "FILE_PART_SIZE_INVALID");
        let files = world.uploaded_files();
        assert_eq!(files.iter().filter(|file| file.complete).count(), 1, "{files:?}");
        assert!(files.iter().any(|file| file.complete && file.bytes == size as u64 && file.tag == Some(5)));
        let (constructor, body) = save_part(80, 0, &content[..1024], false);
        assert_eq!(error(world.handle(4, 1, constructor, &body)).1, "DC_ID_INVALID");
    }

    #[test]
    fn get_file_serves_parts_and_short_tail() {
        let world = world(true);
        let body = result(world.handle(2, 1, UPLOAD_GET_FILE, &get_file(1, 262_144, 65_536)));
        let mut reader = Reader::new(&body);
        assert_eq!(reader.read_u32().unwrap(), UPLOAD_FILE);
        assert_eq!(reader.read_u32().unwrap(), STORAGE_FILE_PARTIAL);
        reader.read_i32().unwrap();
        assert_eq!(reader.read_bytes().unwrap(), file_content(1, 262_144, 300_000 - 262_144));
        assert_eq!(error(world.handle(2, 1, UPLOAD_GET_FILE, &get_file(1, 4096, 12_288))).1, "LIMIT_INVALID");
        assert_eq!(error(world.handle(2, 1, UPLOAD_GET_FILE, &get_file(1, 1_040_384, 16_384))).1, "LIMIT_INVALID");
        assert_eq!(error(world.handle(2, 1, UPLOAD_GET_FILE, &get_file(2, 0, 4096))), (303, "FILE_MIGRATE_4".into()));
    }

    #[test]
    fn foreign_datacenter_requires_imported_authorization() {
        let world = world(true);
        world.register_key(50, 5);
        world.register_key(51, 5);
        assert_eq!(error(world.handle(4, 50, UPLOAD_GET_FILE, &get_file(2, 0, 131_072))).0, 401);
        let mut export = Writer::new();
        export.write_i32(4);
        let exported = result(world.handle(2, 99, AUTH_EXPORT_AUTHORIZATION, export.as_slice()));
        let mut reader = Reader::new(&exported);
        assert_eq!(reader.read_u32().unwrap(), AUTH_EXPORTED_AUTHORIZATION);
        let id = reader.read_i64().unwrap();
        let bytes = reader.read_bytes().unwrap().to_vec();
        let mut import = Writer::new();
        import.write_i64(id);
        import.write_bytes(&bytes);
        result(world.handle(4, 51, AUTH_IMPORT_AUTHORIZATION, import.as_slice()));
        result(world.handle(4, 50, UPLOAD_GET_FILE, &get_file(2, 0, 131_072)));
        world.revoke_authorization(4);
        assert_eq!(error(world.handle(4, 50, UPLOAD_GET_FILE, &get_file(2, 0, 131_072))).0, 401);
    }

    #[test]
    fn cdn_redirect_reupload_hashes_and_ctr_decryption() {
        let world = world(true);
        let mut export = Writer::new();
        export.write_i32(4);
        let exported = result(world.handle(2, 1, AUTH_EXPORT_AUTHORIZATION, export.as_slice()));
        let mut reader = Reader::new(&exported);
        reader.read_u32().unwrap();
        let mut import = Writer::new();
        import.write_i64(reader.read_i64().unwrap());
        import.write_bytes(reader.read_bytes().unwrap());
        result(world.handle(4, 1, AUTH_IMPORT_AUTHORIZATION, import.as_slice()));

        let direct = result(world.handle(4, 1, UPLOAD_GET_FILE, &get_file(3, 0, 131_072)));
        assert_ne!(
            u32::from_le_bytes(direct[..4].try_into().unwrap()),
            UPLOAD_FILE_CDN_REDIRECT,
            "a client without cdn_supported is served by the file's DC"
        );
        let redirect = result(world.handle(4, 1, UPLOAD_GET_FILE, &get_file_with_flags(2, 3, 0, 131_072)));
        let mut reader = Reader::new(&redirect);
        assert_eq!(reader.read_u32().unwrap(), UPLOAD_FILE_CDN_REDIRECT);
        assert_eq!(reader.read_i32().unwrap(), 203);
        let token = reader.read_bytes().unwrap().to_vec();
        let key: [u8; 32] = reader.read_bytes().unwrap().try_into().unwrap();
        let iv: [u8; 16] = reader.read_bytes().unwrap().try_into().unwrap();
        assert_eq!(parse_vector_header(&mut reader), Some(8));

        let mut request = Writer::new();
        request.write_bytes(&token);
        request.write_i64(MEGABYTE as i64 + 131_072);
        request.write_i32(131_072);
        let needed = result(world.handle(203, 9, UPLOAD_GET_CDN_FILE, request.as_slice()));
        let mut reader = Reader::new(&needed);
        assert_eq!(reader.read_u32().unwrap(), UPLOAD_CDN_FILE_REUPLOAD_NEEDED);
        let request_token = reader.read_bytes().unwrap().to_vec();

        let mut reupload = Writer::new();
        reupload.write_bytes(&token);
        reupload.write_bytes(&request_token);
        assert_eq!(error(world.handle(203, 9, UPLOAD_REUPLOAD_CDN_FILE, reupload.as_slice())).1, "CDN_METHOD_INVALID");
        let hashes = result(world.handle(4, 1, UPLOAD_REUPLOAD_CDN_FILE, reupload.as_slice()));
        assert_eq!(parse_vector_header(&mut Reader::new(&hashes)), Some(8));

        let encrypted = result(world.handle(203, 9, UPLOAD_GET_CDN_FILE, request.as_slice()));
        let mut reader = Reader::new(&encrypted);
        assert_eq!(reader.read_u32().unwrap(), UPLOAD_CDN_FILE);
        let mut data = reader.read_bytes().unwrap().to_vec();
        let offset = MEGABYTE + 131_072;
        AesCtr::new(&key, &cdn_iv(&iv, offset)).apply(&mut data);
        assert_eq!(data, file_content(3, offset, 131_072));

        let mut hash_request = Writer::new();
        hash_request.write_bytes(&token);
        hash_request.write_i64(offset as i64);
        let hashes = result(world.handle(4, 1, UPLOAD_GET_CDN_FILE_HASHES, hash_request.as_slice()));
        let mut reader = Reader::new(&hashes);
        let count = parse_vector_header(&mut reader).unwrap();
        assert!(count >= 7);
        assert_eq!(reader.read_u32().unwrap(), FILE_HASH);
        assert_eq!(reader.read_i64().unwrap() as u64, offset);
        assert_eq!(reader.read_i32().unwrap(), 131_072);
        assert_eq!(reader.read_bytes().unwrap(), sha256(&data));

        let mut tail = Writer::new();
        tail.write_bytes(&token);
        tail.write_i64(2 * MEGABYTE as i64);
        tail.write_i32(131_072);
        let reupload_again = result(world.handle(203, 9, UPLOAD_GET_CDN_FILE, tail.as_slice()));
        assert_eq!(Reader::new(&reupload_again).read_u32().unwrap(), UPLOAD_CDN_FILE_REUPLOAD_NEEDED);
        let mut unknown = Writer::new();
        unknown.write_bytes(b"nope");
        unknown.write_i64(0);
        unknown.write_i32(131_072);
        assert_eq!(error(world.handle(203, 9, UPLOAD_GET_CDN_FILE, unknown.as_slice())).1, "FILE_TOKEN_INVALID");
    }

    fn redirected(fault: CdnFault) -> (ApiWorld, Vec<u8>, [u8; 32], [u8; 16]) {
        let files = [FileSpec { id: 3, datacenter_id: 4, size: 2 * MEGABYTE + 5000, cdn: true }];
        let world = ApiWorld::new(WorldOptions { cdn_fault: fault, ..WorldOptions::default() }, &files, 7);
        let mut export = Writer::new();
        export.write_i32(4);
        let exported = result(world.handle(2, 1, AUTH_EXPORT_AUTHORIZATION, export.as_slice()));
        let mut reader = Reader::new(&exported);
        reader.read_u32().unwrap();
        let mut import = Writer::new();
        import.write_i64(reader.read_i64().unwrap());
        import.write_bytes(reader.read_bytes().unwrap());
        result(world.handle(4, 1, AUTH_IMPORT_AUTHORIZATION, import.as_slice()));
        let redirect = result(world.handle(4, 1, UPLOAD_GET_FILE, &get_file_with_flags(2, 3, 0, 131_072)));
        let mut reader = Reader::new(&redirect);
        assert_eq!(reader.read_u32().unwrap(), UPLOAD_FILE_CDN_REDIRECT);
        reader.read_i32().unwrap();
        let token = reader.read_bytes().unwrap().to_vec();
        let key: [u8; 32] = reader.read_bytes().unwrap().try_into().unwrap();
        let iv: [u8; 16] = reader.read_bytes().unwrap().try_into().unwrap();
        (world, token, key, iv)
    }

    fn cdn_part(world: &ApiWorld, token: &[u8], offset: u64) -> Vec<u8> {
        let mut request = Writer::new();
        request.write_bytes(token);
        request.write_i64(offset as i64);
        request.write_i32(131_072);
        result(world.handle(203, 9, UPLOAD_GET_CDN_FILE, request.as_slice()))
    }

    fn reupload_after(world: &ApiWorld, token: &[u8], needed: &[u8]) -> Vec<u8> {
        let mut reader = Reader::new(needed);
        assert_eq!(reader.read_u32().unwrap(), UPLOAD_CDN_FILE_REUPLOAD_NEEDED);
        let mut reupload = Writer::new();
        reupload.write_bytes(token);
        reupload.write_bytes(reader.read_bytes().unwrap());
        result(world.handle(4, 1, UPLOAD_REUPLOAD_CDN_FILE, reupload.as_slice()))
    }

    #[test]
    fn cdn_faults_misbehave_as_configured() {
        let (world, token, _, _) = redirected(CdnFault::TokenInvalid);
        let mut request = Writer::new();
        request.write_bytes(&token);
        request.write_i64(0);
        request.write_i32(131_072);
        assert_eq!(error(world.handle(203, 9, UPLOAD_GET_CDN_FILE, request.as_slice())).1, "FILE_TOKEN_INVALID");

        let (world, token, _, _) = redirected(CdnFault::EndlessReupload);
        for _ in 0..3 {
            let needed = cdn_part(&world, &token, 0);
            reupload_after(&world, &token, &needed);
        }
        assert_eq!(Reader::new(&cdn_part(&world, &token, 0)).read_u32().unwrap(), UPLOAD_CDN_FILE_REUPLOAD_NEEDED);

        let (world, token, _, _) = redirected(CdnFault::NoHashes);
        let needed = cdn_part(&world, &token, 0);
        assert_eq!(parse_vector_header(&mut Reader::new(&reupload_after(&world, &token, &needed))), Some(0));
        let mut hash_request = Writer::new();
        hash_request.write_bytes(&token);
        hash_request.write_i64(0);
        let hashes = result(world.handle(4, 1, UPLOAD_GET_CDN_FILE_HASHES, hash_request.as_slice()));
        assert_eq!(parse_vector_header(&mut Reader::new(&hashes)), Some(0));

        let (world, token, key, iv) = redirected(CdnFault::CorruptData);
        let needed = cdn_part(&world, &token, 0);
        let hashes = reupload_after(&world, &token, &needed);
        let encrypted = cdn_part(&world, &token, 0);
        let mut reader = Reader::new(&encrypted);
        assert_eq!(reader.read_u32().unwrap(), UPLOAD_CDN_FILE);
        let mut data = reader.read_bytes().unwrap().to_vec();
        AesCtr::new(&key, &cdn_iv(&iv, 0)).apply(&mut data);
        assert_ne!(data, file_content(3, 0, 131_072));
        let mut reader = Reader::new(&hashes);
        parse_vector_header(&mut reader).unwrap();
        reader.read_u32().unwrap();
        reader.read_i64().unwrap();
        reader.read_i32().unwrap();
        assert_eq!(reader.read_bytes().unwrap(), sha256(&file_content(3, 0, 131_072)));

        let (world, token, _, _) = redirected(CdnFault::Truncated);
        for offset in [0, MEGABYTE] {
            let needed = cdn_part(&world, &token, offset);
            reupload_after(&world, &token, &needed);
        }
        let before = cdn_part(&world, &token, MEGABYTE - 131_072);
        let mut reader = Reader::new(&before);
        assert_eq!(reader.read_u32().unwrap(), UPLOAD_CDN_FILE);
        assert_eq!(reader.read_bytes().unwrap().len(), 131_072);
        let after = cdn_part(&world, &token, MEGABYTE);
        let mut reader = Reader::new(&after);
        assert_eq!(reader.read_u32().unwrap(), UPLOAD_CDN_FILE);
        assert!(reader.read_bytes().unwrap().is_empty());
    }

    #[test]
    fn bad_redirect_key_fault_sends_a_short_iv() {
        let files = [FileSpec { id: 3, datacenter_id: 4, size: MEGABYTE, cdn: true }];
        let world =
            ApiWorld::new(WorldOptions { cdn_fault: CdnFault::BadRedirectKey, ..WorldOptions::default() }, &files, 7);
        let mut export = Writer::new();
        export.write_i32(4);
        let exported = result(world.handle(2, 1, AUTH_EXPORT_AUTHORIZATION, export.as_slice()));
        let mut reader = Reader::new(&exported);
        reader.read_u32().unwrap();
        let mut import = Writer::new();
        import.write_i64(reader.read_i64().unwrap());
        import.write_bytes(reader.read_bytes().unwrap());
        result(world.handle(4, 1, AUTH_IMPORT_AUTHORIZATION, import.as_slice()));
        let redirect = result(world.handle(4, 1, UPLOAD_GET_FILE, &get_file_with_flags(2, 3, 0, 131_072)));
        let mut reader = Reader::new(&redirect);
        assert_eq!(reader.read_u32().unwrap(), UPLOAD_FILE_CDN_REDIRECT);
        reader.read_i32().unwrap();
        reader.read_bytes().unwrap();
        assert_eq!(reader.read_bytes().unwrap().len(), 32);
        assert_eq!(reader.read_bytes().unwrap().len(), 2);
    }
}
