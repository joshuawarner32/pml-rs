

use crate::errors::FormatError;

pub struct Cursor<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    pub fn new(data: &'a [u8]) -> Cursor<'a> {
        Cursor {
            data,
            offset: 0,
        }
    }

    pub fn read_bytes(&mut self, len: usize) -> &'a [u8] {
        let res = &self.data[self.offset .. self.offset+len];
        self.offset += len;
        res
    }

    pub fn read_cursor(&mut self, len: usize) -> Cursor<'a> {
        Cursor::new(self.read_bytes(len))
    }

    pub fn seek_read_bytes(&mut self, skip: usize, len: usize) -> &'a [u8] {
        // Intentionally _don't_ include self.offset here
        &self.data[skip..skip+len]
    }

    pub fn seek_read_cursor(&mut self, skip: usize) -> Cursor<'a> {
        // Intentionally _don't_ include self.offset here
        Cursor::new(self.seek_read_bytes(skip, self.data.len() - skip))
    }

    pub fn read<T: Parse>(&mut self) -> Result<T, FormatError> {
        T::parse_from(self)
    }
}

pub trait Parse: Sized {
    fn parse_from(cursor: &mut Cursor) -> Result<Self, FormatError>;
}

macro_rules! from_le_bytes_parse_impl {
    (
        $($name:ident),*
    ) => {
        $(
            impl Parse for $name {
                fn parse_from(cursor: &mut Cursor) -> Result<Self, FormatError> {
                    let mut bytes = [0; std::mem::size_of::<Self>()];
                    bytes.copy_from_slice(&cursor.read_bytes(std::mem::size_of::<Self>()));
                    Ok(Self::from_le_bytes(bytes))
                }
            }
        )*
    };
}

from_le_bytes_parse_impl! { u8, u16, u32, u64 }
