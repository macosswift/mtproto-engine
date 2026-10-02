mod reader;
mod writer;

pub mod ids;
pub mod mtproto;

pub use reader::Reader;
pub use writer::Writer;
#[allow(unused_imports)]
pub(crate) use writer::serialized_bytes_len;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TlError {
    #[error("unexpected end of data: needed {needed} bytes at offset {offset}")]
    UnexpectedEof { offset: usize, needed: usize },
    #[error("unexpected constructor {found:#010x} at offset {offset}")]
    UnexpectedConstructor { offset: usize, found: u32 },
    #[error("invalid boolean constructor {0:#010x}")]
    InvalidBool(u32),
    #[error("invalid string padding at offset {0}")]
    InvalidPadding(usize),
    #[error("negative or oversized length {length} at offset {offset}")]
    InvalidLength { offset: usize, length: i64 },
    #[error("trailing data: {0} bytes")]
    TrailingData(usize),
    #[error("gzip error: {0}")]
    Gzip(String),
}

pub type TlResult<T> = Result<T, TlError>;

pub trait TlWrite {
    fn write_to(&self, writer: &mut Writer);

    fn to_bytes(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        self.write_to(&mut writer);
        writer.into_inner()
    }
}

pub trait TlRead<'a>: Sized {
    fn read_from(reader: &mut Reader<'a>) -> TlResult<Self>;

    fn from_bytes(data: &'a [u8]) -> TlResult<Self> {
        let mut reader = Reader::new(data);
        let value = Self::read_from(&mut reader)?;
        reader.finish()?;
        Ok(value)
    }
}
