extern crate libc;

use libc::{c_int};
use std::ffi::{NulError};
use std::string::FromUtf8Error;

use context::Context;

#[derive(Debug)]
pub enum Error {
    Krb5(Krb5Error),
    FromUtf8(FromUtf8Error),
    Nul(NulError),
}

#[derive(Debug)]
pub struct Krb5Error {
    major: c_int,
    message: String,
}

impl Krb5Error {
    pub fn new(major: c_int) -> Krb5Error {
        let message = format!("Kerberos Error: {}", major).to_string();
        Krb5Error{major: major, message: message}
    }
    pub fn from_context(context: &Context, major: c_int) -> Krb5Error {
        let message = context.error_message(major);
        match message {
            Some(msg) => Krb5Error{major: major, message: msg},
            None => Krb5Error::new(major),
        }
    }
    fn description(&self) -> &str {
        self.message.as_ref()
    }
}

impl ::std::fmt::Display for Krb5Error {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl ::std::fmt::Display for Error {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match *self {
            Error::FromUtf8(ref e) => e.fmt(f),
            Error::Nul(ref e) => e.fmt(f),
            Error::Krb5(ref e) => e.fmt(f),
        }
    }
}
impl ::std::error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::FromUtf8(ref e) => e.description(),
            Error::Nul(ref e) => e.description(),
            Error::Krb5(ref e) => e.description(),
        }
    }
    fn cause(&self) -> Option<&::std::error::Error> {
        match *self {
            Error::FromUtf8(ref e) => Some(e as &::std::error::Error),
            Error::Nul(ref e) => Some(e as &::std::error::Error),
            Error::Krb5(_) => None,
        }
    }
}

impl From<NulError> for Error {
    fn from(e: NulError) -> Error {
        Error::Nul(e)
    }
}

impl From<FromUtf8Error> for Error {
    fn from(e: FromUtf8Error) -> Error {
        Error::FromUtf8(e)
    }
}

pub type Result<T> = ::std::result::Result<T, Error>;
