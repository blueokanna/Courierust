//! HTTP protocol versions.

use core::fmt;

/// HTTP version.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug, Default)]
#[allow(non_camel_case_types)]
pub enum Version {
    /// HTTP/0.9 (legacy, minimal support)
    HTTP_09,
    /// HTTP/1.0
    HTTP_10,
    /// HTTP/1.1
    #[default]
    HTTP_11,
    /// HTTP/2
    HTTP_2,
    /// HTTP/3
    HTTP_3,
}

impl Version {
    /// Version as a display string.
    #[inline]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::HTTP_09 => "HTTP/0.9",
            Self::HTTP_10 => "HTTP/1.0",
            Self::HTTP_11 => "HTTP/1.1",
            Self::HTTP_2 => "HTTP/2",
            Self::HTTP_3 => "HTTP/3",
        }
    }

    /// The wire token used in the HTTP/1 status/request line
    /// (e.g. `HTTP/1.1`).
    #[inline]
    pub const fn wire_str(&self) -> &'static str {
        match self {
            Self::HTTP_09 => "HTTP/0.9",
            Self::HTTP_10 => "HTTP/1.0",
            Self::HTTP_11 => "HTTP/1.1",
            Self::HTTP_2 => "HTTP/2",
            Self::HTTP_3 => "HTTP/3",
        }
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl core::str::FromStr for Version {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "HTTP/0.9" => Self::HTTP_09,
            "HTTP/1.0" => Self::HTTP_10,
            "HTTP/1.1" => Self::HTTP_11,
            "HTTP/2" => Self::HTTP_2,
            "HTTP/3" => Self::HTTP_3,
            _ => return Err(()),
        })
    }
}
