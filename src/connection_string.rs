//! One settings value that says everything needed to reach a bucket - see
//! [`S3ConnectionString`].

use super::{S3Client, S3Region};

const ENDPOINT: &str = "Endpoint";
const REGION: &str = "Region";
const ACCESS_KEY: &str = "AccessKey";
const SECRET_KEY: &str = "SecretKey";
const BUCKET: &str = "Bucket";
const PREFIX: &str = "Prefix";
const DEBUG: &str = "Debug";

/// What an error about the string's shape points at.
const EXPECTED_SHAPE: &str =
    "Endpoint=...;Region=...;AccessKey=...;SecretKey=...;Bucket=...[;Prefix=...][;Debug=...]";

/// What an error about a `Debug` value points at.
const EXPECTED_BOOLEAN: &str = "1/0, true/false, yes/no or on/off";

/// The most of a value an error shows: its first characters - and never more than half
/// of it, so a short value does not come out whole either.
const QUOTED_HEAD_LENGTH: usize = 4;

/// The longest unknown name an error quotes whole. The longest real one is 9 characters,
/// so a typo of it fits; an access key (20 characters at AWS and Hetzner) or a secret key
/// (40) does not, and is quoted like a value.
const NAME_MAX_LENGTH: usize = 16;

/// Everything needed to reach one bucket, in one settings value:
///
/// ```text
/// Endpoint=https://fsn1.your-objectstorage.com;Region=fsn1;AccessKey=...;SecretKey=...;Bucket=my-bucket
/// ```
///
/// * Pairs are separated by `;`. Empty pairs (`;;`, a trailing `;`) are skipped, and the
///   whitespace around names and values is trimmed.
/// * A pair splits at its **first** `=` only, because a base64 secret key ends in `=`.
/// * `Endpoint`, `Region`, `AccessKey`, `SecretKey` and `Bucket` are required, and an
///   empty value counts as missing. `Prefix` and `Debug` are optional.
/// * Names match case-insensitively: `endpoint=` is `Endpoint=`.
/// * An unknown name is an error, and so is a name given twice: a typo such as
///   `Secret_Key` must not mean "no secret" and surface later as a `403`.
///
/// The secret key does not come back out: [`Debug`](std::fmt::Debug) writes it as `***`,
/// and an error never quotes a value whole - see [`S3ConnectionStringError`].
///
/// ```
/// let s3 = my_s3::S3ConnectionString::parse(
///     "Endpoint=https://fsn1.your-objectstorage.com;Region=fsn1;AccessKey=...;SecretKey=...;Bucket=my-bucket",
/// )?
/// .create_client();
/// # Ok::<(), my_s3::S3ConnectionStringError>(())
/// ```
#[derive(Clone)]
pub struct S3ConnectionString {
    /// Without a trailing `/`: [`S3Client`] addresses `<endpoint>/<bucket>/<key>`, so one
    /// written there (`https://host/`) is cut off.
    pub endpoint: String,
    pub region: S3Region,
    pub access_key: String,
    pub secret_key: String,
    pub bucket: String,
    /// `Prefix=` - the folder the keys go under, as written. `None` when it is not given,
    /// or given empty.
    pub prefix: Option<String>,
    /// `Debug=1` - the client [`Self::create_client`] builds traces every request to the
    /// console.
    pub debug: bool,
}

impl S3ConnectionString {
    /// Reads a connection string, or says what is wrong with it.
    ///
    /// Never panics. A service that cannot run without its bucket calls `.expect(...)`
    /// on the result; one that serves several buckets shows the error next to the ones
    /// that work.
    pub fn parse(src: &str) -> Result<Self, S3ConnectionStringError> {
        let mut endpoint = None;
        let mut region = None;
        let mut access_key = None;
        let mut secret_key = None;
        let mut bucket = None;
        let mut prefix = None;
        let mut debug = None;

        // Every name the string knows, in its documented spelling, and where its value goes.
        let mut slots = [
            (ENDPOINT, &mut endpoint),
            (REGION, &mut region),
            (ACCESS_KEY, &mut access_key),
            (SECRET_KEY, &mut secret_key),
            (BUCKET, &mut bucket),
            (PREFIX, &mut prefix),
            (DEBUG, &mut debug),
        ];

        for pair in src.split(';') {
            let pair = pair.trim();

            if pair.is_empty() {
                continue;
            }

            // Only the first `=` separates: a base64 secret key ends in `=` of its own. A
            // pair with no name may be that very secret, having lost its own.
            let (name, value) = match pair.split_once('=') {
                Some((name, value)) if !name.trim().is_empty() => (name.trim(), value.trim()),
                _ => return Err(S3ConnectionStringError::NotAPair(quote_value(pair))),
            };

            let Some((known_name, slot)) = slots
                .iter_mut()
                .find(|(known_name, _)| known_name.eq_ignore_ascii_case(name))
            else {
                return Err(S3ConnectionStringError::UnknownName(quote_name(name)));
            };

            if slot.replace(value).is_some() {
                return Err(S3ConnectionStringError::GivenTwice(known_name));
            }
        }

        let debug = match debug {
            Some(value) => parse_bool(value)
                .ok_or_else(|| S3ConnectionStringError::DebugNotABoolean(quote_value(value)))?,
            None => false,
        };

        Ok(Self {
            endpoint: required(endpoint.map(|value| value.trim_end_matches('/')), ENDPOINT)?
                .to_string(),
            region: required(region, REGION)?.into(),
            access_key: required(access_key, ACCESS_KEY)?.to_string(),
            secret_key: required(secret_key, SECRET_KEY)?.to_string(),
            bucket: required(bucket, BUCKET)?.to_string(),
            prefix: prefix
                .filter(|value| !value.is_empty())
                .map(|value| value.to_string()),
            debug,
        })
    }

    /// [`S3Client::new`] with the values of the string, plus
    /// [`S3Client::debug_to_console`] when it says `Debug=1`.
    pub fn create_client(&self) -> S3Client {
        let client = S3Client::new(
            self.access_key.as_str(),
            self.secret_key.as_str(),
            self.region.clone(),
            self.endpoint.as_str(),
        );

        if self.debug {
            client.debug_to_console()
        } else {
            client
        }
    }
}

impl std::str::FromStr for S3ConnectionString {
    type Err = S3ConnectionStringError;

    fn from_str(src: &str) -> Result<Self, Self::Err> {
        Self::parse(src)
    }
}

/// Written out so that the secret key cannot reach a log: it comes out as `***`.
impl std::fmt::Debug for S3ConnectionString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3ConnectionString")
            .field("endpoint", &self.endpoint)
            .field("region", &self.region)
            .field("access_key", &self.access_key)
            .field("secret_key", &format_args!("***"))
            .field("bucket", &self.bucket)
            .field("prefix", &self.prefix)
            .field("debug", &self.debug)
            .finish()
    }
}

/// Why a connection string could not be read.
///
/// No case carries a value whole, because a value may be the secret key: what it quotes
/// is the value's beginning and its length - `abc/… (40 characters)`. An unknown name is
/// quoted whole only while it looks like a name. So the error can be printed anywhere,
/// `{:?}` included.
///
/// [`Display`](std::fmt::Display) says what is wrong, and the shape that was expected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum S3ConnectionStringError {
    /// A pair with no `=`, or nothing before it. Quoted like a value: it may be the secret
    /// key that lost its name.
    NotAPair(String),
    /// A name the string does not know. Quoted whole while it looks like a name - short,
    /// and letters, digits, `_` or `-` only - and like a value otherwise.
    UnknownName(String),
    /// A name given twice, in its documented spelling.
    GivenTwice(&'static str),
    /// A required name that is not there.
    Missing(&'static str),
    /// A required name with nothing after its `=`.
    Empty(&'static str),
    /// A `Debug` value that is none of 1/0, true/false, yes/no or on/off. Quoted like a
    /// value: a `;` left out glues the next pair into this one.
    DebugNotABoolean(String),
}

impl std::fmt::Display for S3ConnectionStringError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAPair(pair) => {
                write!(
                    f,
                    "not a Key=Value pair: {}, expected {}",
                    pair, EXPECTED_SHAPE
                )
            }
            Self::UnknownName(name) => {
                write!(f, "unknown name: {}, expected {}", name, EXPECTED_SHAPE)
            }
            Self::GivenTwice(name) => {
                write!(f, "{} is given twice, expected {}", name, EXPECTED_SHAPE)
            }
            Self::Missing(name) => write!(f, "{} is missing, expected {}", name, EXPECTED_SHAPE),
            Self::Empty(name) => write!(f, "{} is empty, expected {}", name, EXPECTED_SHAPE),
            Self::DebugNotABoolean(value) => {
                write!(f, "{} expects {}, got {}", DEBUG, EXPECTED_BOOLEAN, value)
            }
        }
    }
}

impl std::error::Error for S3ConnectionStringError {}

fn required<'s>(
    value: Option<&'s str>,
    name: &'static str,
) -> Result<&'s str, S3ConnectionStringError> {
    match value {
        None => Err(S3ConnectionStringError::Missing(name)),
        Some("") => Err(S3ConnectionStringError::Empty(name)),
        Some(value) => Ok(value),
    }
}

/// Spelled out rather than "anything but `1` is off": `Debug=ture` quietly meaning off is
/// what this refuses.
fn parse_bool(value: &str) -> Option<bool> {
    match value.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

/// How an error shows a value: its beginning and its length, never all of it.
fn quote_value(value: &str) -> String {
    let length = value.chars().count();

    if length == 0 {
        return "an empty value".to_string();
    }

    let head: String = value
        .chars()
        .take(QUOTED_HEAD_LENGTH.min(length / 2))
        .collect();

    let unit = if length == 1 {
        "character"
    } else {
        "characters"
    };

    format!("{}… ({} {})", head, length, unit)
}

/// A typo is found faster when it can be read, so a name is quoted whole. Anything that
/// does not look like one may be a value that lost its own name, and is quoted like one.
fn quote_name(name: &str) -> String {
    let looks_like_a_name = name.len() <= NAME_MAX_LENGTH
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');

    if looks_like_a_name {
        name.to_string()
    } else {
        quote_value(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The string the services test their own parsers with.
    const SERVICES_STRING: &str = "Endpoint=https://s3.eu-central-1.amazonaws.com;Region=eu-central-1;AccessKey=AKIA123;SecretKey=abc/def+ghi=;Bucket=my-bucket";

    const REQUIRED: [(&str, &str); 5] = [
        (ENDPOINT, "https://fsn1.your-objectstorage.com"),
        (REGION, "fsn1"),
        (ACCESS_KEY, "AKIA123"),
        (SECRET_KEY, "abc/def+ghi="),
        (BUCKET, "my-bucket"),
    ];

    fn string_of(pairs: &[(&str, &str)]) -> String {
        pairs
            .iter()
            .map(|(name, value)| format!("{}={}", name, value))
            .collect::<Vec<_>>()
            .join(";")
    }

    fn parse(src: &str) -> Result<S3ConnectionString, S3ConnectionStringError> {
        S3ConnectionString::parse(src)
    }

    #[test]
    fn reads_the_string_the_services_read() {
        let parsed = parse(SERVICES_STRING).unwrap();

        assert_eq!(parsed.endpoint, "https://s3.eu-central-1.amazonaws.com");
        assert_eq!(parsed.region, S3Region::AwsEuCentral1);
        assert_eq!(parsed.access_key, "AKIA123");
        // Only the first `=` separates: the secret keeps its own.
        assert_eq!(parsed.secret_key, "abc/def+ghi=");
        assert_eq!(parsed.bucket, "my-bucket");
        assert_eq!(parsed.prefix, None);
        assert!(!parsed.debug);
    }

    #[test]
    fn reads_prefix_and_debug_and_skips_a_trailing_separator() {
        let parsed = parse(&format!("{};Prefix=my-logs;Debug=1;", SERVICES_STRING)).unwrap();

        assert_eq!(parsed.prefix.as_deref(), Some("my-logs"));
        assert!(parsed.debug);
        assert_eq!(parsed.secret_key, "abc/def+ghi=");
        assert_eq!(parsed.bucket, "my-bucket");
    }

    #[test]
    fn skips_empty_pairs_and_trims_whitespace() {
        let parsed = parse(
            " ;; Endpoint = https://fsn1.your-objectstorage.com ;Region=fsn1;;AccessKey= AKIA123 ; SecretKey=abc/def+ghi= ;Bucket = my-bucket ; Prefix = logs ; ",
        )
        .unwrap();

        assert_eq!(parsed.endpoint, "https://fsn1.your-objectstorage.com");
        assert_eq!(parsed.region, S3Region::HetznerFsn1);
        assert_eq!(parsed.access_key, "AKIA123");
        assert_eq!(parsed.secret_key, "abc/def+ghi=");
        assert_eq!(parsed.bucket, "my-bucket");
        assert_eq!(parsed.prefix.as_deref(), Some("logs"));
    }

    #[test]
    fn an_empty_prefix_is_no_prefix() {
        for written in ["Prefix=", "Prefix=  "] {
            let parsed = parse(&format!("{};{}", SERVICES_STRING, written)).unwrap();
            assert_eq!(parsed.prefix, None, "{}", written);
        }
    }

    #[test]
    fn every_accepted_debug_value_in_any_case() {
        let accepted = [
            ("1", true),
            ("true", true),
            ("yes", true),
            ("on", true),
            ("0", false),
            ("false", false),
            ("no", false),
            ("off", false),
        ];

        for (value, expected) in accepted {
            for written in [value.to_string(), value.to_uppercase()] {
                let parsed = parse(&format!("{};Debug={}", SERVICES_STRING, written)).unwrap();
                assert_eq!(parsed.debug, expected, "Debug={}", written);
            }
        }

        for (written, expected) in [("True", true), ("yEs", true), ("Off", false), ("nO", false)] {
            let parsed = parse(&format!("{};Debug={}", SERVICES_STRING, written)).unwrap();
            assert_eq!(parsed.debug, expected, "Debug={}", written);
        }
    }

    #[test]
    fn a_debug_value_that_is_not_a_boolean_is_an_error_not_off() {
        let err = parse(&format!("{};Debug=maybe", SERVICES_STRING)).unwrap_err();
        assert_eq!(
            err,
            S3ConnectionStringError::DebugNotABoolean("ma… (5 characters)".to_string())
        );
        assert_eq!(
            err.to_string(),
            "Debug expects 1/0, true/false, yes/no or on/off, got ma… (5 characters)"
        );

        for written in ["2", "ture", "enabled", ""] {
            let err = parse(&format!("{};Debug={}", SERVICES_STRING, written)).unwrap_err();
            assert!(
                matches!(err, S3ConnectionStringError::DebugNotABoolean(_)),
                "Debug={}: {:?}",
                written,
                err
            );
        }
    }

    /// A `;` left out glues the next pair into the `Debug` value.
    #[test]
    fn a_debug_value_is_quoted_by_its_beginning_only() {
        let err = parse(&format!(
            "{};Debug=1SecretKey=abc/def+ghi=",
            SERVICES_STRING
        ))
        .unwrap_err();

        assert_eq!(
            err,
            S3ConnectionStringError::DebugNotABoolean("1Sec… (23 characters)".to_string())
        );
        assert!(!err.to_string().contains("abc/def+ghi="), "{}", err);
    }

    #[test]
    fn each_required_name_missing() {
        for (name, _) in REQUIRED {
            let pairs: Vec<_> = REQUIRED
                .into_iter()
                .filter(|(known_name, _)| *known_name != name)
                .collect();

            assert_eq!(
                parse(&string_of(&pairs)).unwrap_err(),
                S3ConnectionStringError::Missing(name)
            );
        }

        assert_eq!(
            parse("").unwrap_err(),
            S3ConnectionStringError::Missing(ENDPOINT)
        );
    }

    #[test]
    fn each_required_name_empty() {
        for (name, _) in REQUIRED {
            for empty in ["", "  "] {
                let pairs: Vec<_> = REQUIRED
                    .into_iter()
                    .map(|(known_name, value)| {
                        (known_name, if known_name == name { empty } else { value })
                    })
                    .collect();

                assert_eq!(
                    parse(&string_of(&pairs)).unwrap_err(),
                    S3ConnectionStringError::Empty(name),
                    "{}='{}'",
                    name,
                    empty
                );
            }
        }
    }

    #[test]
    fn an_unknown_name_is_an_error_not_ignored() {
        let err =
            parse("Endpoint=https://s3;Region=eu;AccessKey=a;Secret_Key=abc/def+ghi=;Bucket=c")
                .unwrap_err();

        assert_eq!(
            err,
            S3ConnectionStringError::UnknownName("Secret_Key".to_string())
        );
        assert!(
            err.to_string().contains("unknown name: Secret_Key"),
            "{}",
            err
        );
        assert!(!err.to_string().contains("abc/def+ghi="), "{}", err);
    }

    /// A secret that lost its name keeps its own `=` padding, and so arrives where a name
    /// would.
    #[test]
    fn an_unknown_name_that_does_not_look_like_one_is_quoted_like_a_value() {
        for (name, quoted) in [
            ("abc/def+ghi", "abc/… (11 characters)"),
            (
                "ABCDEFGHIJKLMNOPQRST0123456789abcdefghij",
                "ABCD… (40 characters)",
            ),
            ("Secret Key", "Secr… (10 characters)"),
        ] {
            let err = parse(&format!("{};{}=", SERVICES_STRING, name)).unwrap_err();

            assert_eq!(
                err,
                S3ConnectionStringError::UnknownName(quoted.to_string())
            );
            assert!(!err.to_string().contains(name), "{}", err);
        }
    }

    #[test]
    fn a_name_given_twice_is_an_error() {
        assert_eq!(
            parse(&format!("{};Bucket=other", SERVICES_STRING)).unwrap_err(),
            S3ConnectionStringError::GivenTwice(BUCKET)
        );

        // In another case, and with the first one empty: which one was meant is not for
        // the parser to guess.
        assert_eq!(
            parse("secretKey=;Endpoint=https://s3;SECRETKEY=b").unwrap_err(),
            S3ConnectionStringError::GivenTwice(SECRET_KEY)
        );
    }

    #[test]
    fn names_match_in_any_case() {
        let parsed = parse(
            "endpoint=https://s3;region=eu;accesskey=a;secretkey=b;bucket=c;prefix=p;debug=on",
        )
        .unwrap();

        assert_eq!(parsed.endpoint, "https://s3");
        assert_eq!(parsed.region.as_str(), "eu");
        assert_eq!(parsed.access_key, "a");
        assert_eq!(parsed.secret_key, "b");
        assert_eq!(parsed.bucket, "c");
        assert_eq!(parsed.prefix.as_deref(), Some("p"));
        assert!(parsed.debug);

        // The spelling my-prop-trading writes its strings in.
        let parsed = parse(
            "endpoint=https://fsn1.your-objectstorage.com;region=fsn1;accessKey=a;secretKey=b;bucket=prop-blobs",
        )
        .unwrap();

        assert_eq!(parsed.access_key, "a");
        assert_eq!(parsed.secret_key, "b");
        assert_eq!(parsed.bucket, "prop-blobs");

        let parsed =
            parse("ENDPOINT=https://s3;REGION=eu;ACCESSKEY=a;SECRETKEY=b;BUCKET=c").unwrap();
        assert_eq!(parsed.secret_key, "b");
    }

    /// A pair with no `=` may be the secret key that lost its name.
    #[test]
    fn a_pair_without_equals_is_not_quoted_whole() {
        let secret = "abc/defghijklmnopqrstuvwxyz0123456789+AB";
        assert_eq!(secret.len(), 40);

        let err = parse(&format!(
            "Endpoint=https://s3;Region=eu;AccessKey=a;{};Bucket=c",
            secret
        ))
        .unwrap_err();

        assert_eq!(
            err,
            S3ConnectionStringError::NotAPair("abc/… (40 characters)".to_string())
        );

        for printed in [err.to_string(), format!("{:?}", err)] {
            assert!(!printed.contains(secret), "{}", printed);
            assert!(!printed.contains("abc/d"), "{}", printed);
        }
    }

    #[test]
    fn a_pair_with_nothing_before_its_equals_is_not_a_pair() {
        assert_eq!(
            parse(&format!("{};=abc/def+ghi=", SERVICES_STRING)).unwrap_err(),
            S3ConnectionStringError::NotAPair("=abc… (13 characters)".to_string())
        );
    }

    #[test]
    fn a_short_value_is_never_quoted_whole() {
        assert_eq!(quote_value("x"), "… (1 character)");
        assert_eq!(quote_value("abc"), "a… (3 characters)");
        assert_eq!(quote_value("abcdefgh"), "abcd… (8 characters)");
        assert_eq!(quote_value("abcdefghijklmnop"), "abcd… (16 characters)");
        assert_eq!(quote_value("ключ-ключ"), "ключ… (9 characters)");
    }

    #[test]
    fn every_error_names_what_was_expected() {
        for err in [
            S3ConnectionStringError::NotAPair("abc/… (40 characters)".to_string()),
            S3ConnectionStringError::UnknownName("Secret_Key".to_string()),
            S3ConnectionStringError::GivenTwice(BUCKET),
            S3ConnectionStringError::Missing(BUCKET),
            S3ConnectionStringError::Empty(BUCKET),
        ] {
            assert!(
                err.to_string()
                    .contains("Endpoint=...;Region=...;AccessKey=...;SecretKey=...;Bucket=..."),
                "{}",
                err
            );
        }

        let err = S3ConnectionStringError::DebugNotABoolean("an empty value".to_string());
        assert!(
            err.to_string()
                .contains("1/0, true/false, yes/no or on/off")
        );

        let _: Box<dyn std::error::Error> = Box::new(err);
    }

    #[test]
    fn the_debug_output_hides_the_secret_key() {
        let printed = format!("{:?}", parse(SERVICES_STRING).unwrap());

        assert!(!printed.contains("abc/def+ghi="), "{}", printed);
        assert!(printed.contains("secret_key: ***"), "{}", printed);
        assert!(printed.contains("AKIA123"), "{}", printed);
    }

    #[test]
    fn create_client_carries_the_four_values() {
        let client = parse(SERVICES_STRING).unwrap().create_client();

        assert_eq!(client.access_key, "AKIA123");
        assert_eq!(client.secret_key, "abc/def+ghi=");
        assert_eq!(client.region, S3Region::AwsEuCentral1);
        assert_eq!(client.endpoint, "https://s3.eu-central-1.amazonaws.com");
        assert!(!client.debug_to_console);

        let client = parse(&format!("{};Debug=yes", SERVICES_STRING))
            .unwrap()
            .create_client();
        assert!(client.debug_to_console);
    }

    #[test]
    fn a_trailing_slash_of_the_endpoint_is_cut() {
        for endpoint in [
            "https://fsn1.your-objectstorage.com/",
            "https://fsn1.your-objectstorage.com//",
        ] {
            let parsed = parse(&format!(
                "Endpoint={};Region=fsn1;AccessKey=a;SecretKey=b;Bucket=c",
                endpoint
            ))
            .unwrap();

            assert_eq!(parsed.endpoint, "https://fsn1.your-objectstorage.com");
            assert_eq!(
                parsed.create_client().endpoint,
                "https://fsn1.your-objectstorage.com"
            );
        }

        assert_eq!(
            parse("Endpoint=/;Region=fsn1;AccessKey=a;SecretKey=b;Bucket=c").unwrap_err(),
            S3ConnectionStringError::Empty(ENDPOINT)
        );
    }

    #[test]
    fn from_str_is_parse() {
        let parsed: S3ConnectionString = SERVICES_STRING.parse().unwrap();
        assert_eq!(parsed.bucket, "my-bucket");

        assert_eq!(
            "Endpoint=https://s3"
                .parse::<S3ConnectionString>()
                .unwrap_err(),
            S3ConnectionStringError::Missing(REGION)
        );
    }
}
