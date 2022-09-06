//! Simple credential management.

use std::{
    fs::File,
    io::{self, BufRead, BufReader, Write},
    ops::Index,
    path::Path,
};

use indexmap::IndexMap;

/// A credential store that stores username/password pairs.
#[derive(Default, Debug, Clone)]
pub struct Creds {
    map: IndexMap<String, String>,
}

impl Creds {
    /// Create a new empty credential store.
    pub fn new() -> Self {
        Self {
            map: IndexMap::new(),
        }
    }

    /// Remove all stored credentials. This leaves the cred store empty.
    pub fn clear(&mut self) {
        self.map.clear();
    }

    /// Add a new username and password pair.
    ///
    /// The username should not contain newlines or the colon `:` character,
    /// and the password should not contain newlines.
    ///
    /// If a password already exists for the given username, it will be overwritten.
    pub fn insert(&mut self, username: impl Into<String>, password: impl Into<String>) {
        self.map.insert(username.into(), password.into());
    }

    /// Retrieve a stored password for the given username.
    ///
    /// If a password was set for the given username, then it will be returned.
    /// Otherwise, the username does not exist in the store, and `None` is
    /// returned.
    pub fn get(&self, username: &str) -> Option<&str> {
        self.map.get(username).map(String::as_str)
    }

    /// Writes the credentials into the given writer.
    ///
    /// The output format is:
    ///
    /// ```text
    /// <username1>:<password1>
    /// <username2>:<password2>
    /// ...
    /// ```
    pub fn write(&self, mut writer: impl Write) -> io::Result<()> {
        for (username, password) in &self.map {
            if username.contains(':') || username.contains('\n') || password.contains('\n') {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "username or password contains illegal characters",
                ));
            }
            writeln!(writer, "{}:{}", username, password)?;
        }
        Ok(())
    }

    /// Parses a credentials file from the given reader.
    ///
    /// The expected format is:
    ///
    /// ```text
    /// <username1>:<password1>
    /// <username2>:<password2>
    /// ...
    /// ```
    pub fn read(reader: impl BufRead) -> io::Result<Self> {
        let mut creds = Self::new();
        for line_result in reader.lines() {
            let line = line_result?;
            if let Some((username, password)) = line.split_once(':') {
                creds.insert(username, password);
            }
        }
        Ok(creds)
    }

    /// Writes the credential store to the given file.
    ///
    /// See also: [`Creds::write`]
    pub fn write_to_file(&self, path: impl AsRef<Path>) -> io::Result<()> {
        let file = File::create(path)?;
        self.write(file)
    }

    /// Parses a credential store from the given file.
    ///
    /// See also: [`Creds::read`]
    pub fn read_from_file(path: impl AsRef<Path>) -> io::Result<Self> {
        let file = File::open(path)?;
        Self::read(BufReader::new(file))
    }
}

impl<S> Index<S> for Creds
where
    S: AsRef<str>,
{
    type Output = str;

    fn index(&self, username: S) -> &Self::Output {
        let username = username.as_ref();

        match self.get(username) {
            Some(string) => &*string,
            None => panic!("username not present: {}", username),
        }
    }
}
