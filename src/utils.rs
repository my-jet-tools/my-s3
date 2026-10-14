use flurl::FlUrl;
use hmac::{Hmac, KeyInit, Mac};
use rust_extensions::date_time::DateTimeAsMicroseconds;
use sha2::{Digest, Sha256};

use crate::{S3Client, S3Error};

pub type HmacSha256 = Hmac<Sha256>;

/// Signs an already-built request with SigV4 and attaches the three headers S3 needs.
///
/// The canonical request is derived from `fl_url`'s own url builder rather than from
/// a separately formatted bucket/key pair. That matters: `FlUrl` percent-encodes path
/// segments and query params as it builds the URL, and it sends `Host` as
/// `url_builder.get_host_port()`. Re-deriving those strings by hand meant signing
/// something the wire never carried - a key with a space, a non-ASCII character, or a
/// `http://` endpoint (the old code only stripped `https://`) all produced a 403 that
/// looked like a credentials problem. Reading them back from the builder makes the
/// signed bytes and the sent bytes the same bytes by construction.
///
/// Call this *after* every `append_path_segment` / `append_query_param`, and before
/// any further `with_header` that must not be signed (only `host`,
/// `x-amz-content-sha256` and `x-amz-date` are in `SignedHeaders`, so unsigned extras
/// such as `Range` are fine either way). An `x-amz-*` header is not such an extra: it
/// goes through [`sign_request_with_headers`].
///
/// Fails with [`S3Error::Other`] carrying the error when `fl_url` has already met one -
/// an endpoint that is not a usable url, a header that can not be put on the wire.
pub fn sign_request(
    s3: &S3Client,
    fl_url: FlUrl,
    method: &str,
    payload: &[u8],
) -> Result<FlUrl, S3Error> {
    sign_request_with_headers(s3, fl_url, method, payload, &[])
}

/// [`sign_request`] for a request that carries headers of its own which have to be
/// signed - `x-amz-copy-source` on a `CopyObject`.
///
/// SigV4 signs every `x-amz-*` header of a request, and S3 refuses one that carries a
/// header it was not signed with. So `headers` are put on the request here rather than
/// by the caller: what is signed and what is sent can then not differ.
///
/// Each of them joins `host`, `x-amz-content-sha256` and `x-amz-date` in the canonical
/// headers and in `SignedHeaders`, lowercased and in alphabetical order. Those three,
/// and `Authorization`, are this function's to set and are not passed in. With no
/// `headers` the request is signed byte for byte as [`sign_request`] signs it.
pub fn sign_request_with_headers(
    s3: &S3Client,
    fl_url: FlUrl,
    method: &str,
    payload: &[u8],
    headers: &[(&str, &str)],
) -> Result<FlUrl, S3Error> {
    let payload_hash = hex::encode(Sha256::digest(payload));
    sign(s3, fl_url, method, &payload_hash, headers)
}

pub fn sign_request_with_payload_hash(
    s3: &S3Client,
    fl_url: FlUrl,
    method: &str,
    payload_hash: &str,
) -> Result<FlUrl, S3Error> {
    sign(s3, fl_url, method, payload_hash, &[])
}

fn sign(
    s3: &S3Client,
    fl_url: FlUrl,
    method: &str,
    payload_hash: &str,
    headers: &[(&str, &str)],
) -> Result<FlUrl, S3Error> {
    let service = "s3";

    // An error here is bad input - an endpoint that is not a usable url, say. There is
    // nothing to sign and nothing to send, so it goes straight back, saying what has to
    // be fixed. `FlUrlError` is not `Clone`, and only a reference to it is handed out,
    // hence its text rather than the error itself.
    let url_builder = match fl_url.get_url_builder() {
        Ok(url_builder) => url_builder,
        Err(err) => {
            return Err(S3Error::Other(format!("Can not sign the request: {}", err)));
        }
    };

    // Exactly what FlUrl will put in the Host header and on the request line.
    let host = url_builder.get_host_port().to_string();
    let canonical_uri = url_builder.get_path().to_string();
    let canonical_query = canonical_query_string(url_builder.get_query());

    let timestamp = get_amz_timestamp();
    let date = timestamp[..8].to_string();

    let (canonical_request, signed_headers) = canonical_request(
        method,
        &canonical_uri,
        &canonical_query,
        &host,
        payload_hash,
        &timestamp,
        headers,
    );
    let hashed_canonical_request = hex::encode(Sha256::digest(canonical_request.as_bytes()));

    let scope = format!("{}/{}/{}/aws4_request", date, s3.region.as_str(), service);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        timestamp, scope, hashed_canonical_request
    );

    let signing_key = get_signature_key(&s3.secret_key, &date, s3.region.as_str(), service);

    let mut mac = HmacSha256::new_from_slice(&signing_key).map_err(|itm| itm.to_string())?;
    mac.update(string_to_sign.as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());

    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={}/{},SignedHeaders={},Signature={}",
        s3.access_key, scope, signed_headers, signature
    );

    let fl_url = headers
        .iter()
        .fold(fl_url, |fl_url, (name, value)| fl_url.with_header(*name, *value));

    let fl_url = fl_url
        .with_header("X-Amz-Content-Sha256", payload_hash)
        .with_header("X-Amz-Date", &timestamp)
        .with_header("Authorization", &authorization);

    Ok(fl_url)
}

/// The SigV4 canonical request, and the `SignedHeaders` list that goes with it.
///
/// `host`, `x-amz-content-sha256` and `x-amz-date` are always signed, and `headers` join
/// them. SigV4 wants every name lowercased, one list sorted by name for both the
/// canonical headers and `SignedHeaders`, and every value trimmed with each run of spaces
/// inside it folded into one.
fn canonical_request(
    method: &str,
    canonical_uri: &str,
    canonical_query: &str,
    host: &str,
    payload_hash: &str,
    timestamp: &str,
    headers: &[(&str, &str)],
) -> (String, String) {
    let mut signed: Vec<(String, &str)> = vec![
        ("host".to_string(), host),
        ("x-amz-content-sha256".to_string(), payload_hash),
        ("x-amz-date".to_string(), timestamp),
    ];
    signed.extend(
        headers
            .iter()
            .map(|(name, value)| (name.to_ascii_lowercase(), *value)),
    );
    signed.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));

    let mut canonical_headers = String::new();
    let mut signed_headers = String::new();

    for (name, value) in &signed {
        canonical_headers.push_str(name);
        canonical_headers.push(':');
        push_canonical_header_value(&mut canonical_headers, value);
        canonical_headers.push('\n');

        if !signed_headers.is_empty() {
            signed_headers.push(';');
        }
        signed_headers.push_str(name);
    }

    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method, canonical_uri, canonical_query, canonical_headers, signed_headers, payload_hash
    );

    (canonical_request, signed_headers)
}

/// Appends `value` the way SigV4 canonicalises a header value: without the spaces around
/// it, and with each run of spaces inside it folded into one.
fn push_canonical_header_value(dest: &mut String, value: &str) {
    for (index, word) in value.split(' ').filter(|word| !word.is_empty()).enumerate() {
        if index > 0 {
            dest.push(' ');
        }
        dest.push_str(word);
    }
}

/// Builds the SigV4 canonical query string out of the query FlUrl already encoded.
///
/// The pairs are taken verbatim - re-encoding them here would be the whole bug this
/// function exists to avoid - and only reordered, since SigV4 requires ascending order
/// by encoded name and then by encoded value. A parameter with no value (`?uploads`)
/// canonicalises to `uploads=`, which is also how the server reads it off the wire.
fn canonical_query_string(query: Option<&str>) -> String {
    let Some(query) = query else {
        return String::new();
    };

    if query.is_empty() {
        return String::new();
    }

    let mut pairs: Vec<(&str, &str)> = query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((name, value)) => (name, value),
            None => (pair, ""),
        })
        .collect();

    // Sort on the (name, value) tuple rather than on the joined string: a byte-wise
    // sort of "name=value" ranks `a-b=1` before `a=2` because '-' < '=', which is the
    // opposite of the name-first order AWS specifies.
    pairs.sort_unstable();

    let mut result = String::with_capacity(query.len() + pairs.len());
    for (index, (name, value)) in pairs.iter().enumerate() {
        if index > 0 {
            result.push('&');
        }
        result.push_str(name);
        result.push('=');
        result.push_str(value);
    }

    result
}

/// URI-encodes one query-string name or value the way SigV4 requires.
///
/// **This exists because `FlUrl` encodes queries by a different rule and the difference
/// is a 403.** `FlUrl::append_query_param` runs the value through
/// `my_http_utils::url_encoder`, which is an `x-www-form-urlencoded` encoder: a space
/// becomes `+`, and `!` is left alone. SigV4 - and RFC 3986, which it cites - says the
/// unreserved set is exactly `A-Za-z0-9-_.~` and that **everything** else is `%XX`, so a
/// space is `%20` and `!` is `%21`.
///
/// Both halves of that gap bite, and neither is visible locally:
///
/// * S3 does not read `+` in a query value as a space, so `prefix=a+b` would list the
///   prefix `a+b` - a listing that silently comes back empty.
/// * The server rebuilds the canonical query from what arrived, re-encoding it by the
///   RFC 3986 rule, so its `%2B` never matches our `+` and the request is refused as
///   `SignatureDoesNotMatch` - which reads as a credentials problem.
///
/// A `prefix` almost always contains `/`, and a continuation token is base64 and
/// contains `+ / =`, so this is the normal case, not an edge one.
///
/// Encoding runs over the UTF-8 **bytes**, which is what makes a non-ASCII key encode to
/// the same `%XX` sequence the server will re-derive.
pub fn encode_uri_component(src: &str, dest: &mut String) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";

    for byte in src.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                dest.push(*byte as char)
            }
            _ => {
                dest.push('%');
                dest.push(HEX[(*byte >> 4) as usize] as char);
                dest.push(HEX[(*byte & 0x0F) as usize] as char);
            }
        }
    }
}

/// Appends `&name=value` to a query string being built by hand, URI-encoding both
/// halves. A `None` value appends nothing at all - S3 tells "not asked for" from
/// "asked for, empty" by the absence of the parameter.
pub fn append_query_param(query: &mut String, name: &str, value: Option<&str>) {
    let Some(value) = value else {
        return;
    };

    if !query.is_empty() {
        query.push('&');
    }

    encode_uri_component(name, query);
    query.push('=');
    encode_uri_component(value, query);
}

pub fn get_signature_key(secret_key: &str, date: &str, region: &str, service: &str) -> Vec<u8> {
    let k_secret = format!("AWS4{}", secret_key).into_bytes();
    let k_date = HmacSha256::new_from_slice(&k_secret)
        .unwrap()
        .chain_update(date)
        .finalize()
        .into_bytes();
    let k_region = HmacSha256::new_from_slice(&k_date)
        .unwrap()
        .chain_update(region)
        .finalize()
        .into_bytes();
    let k_service = HmacSha256::new_from_slice(&k_region)
        .unwrap()
        .chain_update(service)
        .finalize()
        .into_bytes();
    let result = HmacSha256::new_from_slice(&k_service)
        .unwrap()
        .chain_update("aws4_request")
        .finalize();

    let result = result.into_bytes();

    result.to_vec()
}

pub fn get_amz_timestamp() -> String {
    let now = DateTimeAsMicroseconds::now().to_rfc3339();
    let now = now.replace("-", "");
    let mut now = now.replace(":", "");

    while now.len() > 15 {
        now.pop();
    }

    now.push('Z');

    now
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known-answer test from the AWS docs ("Examples of how to derive a signing key
    /// for Signature Version 4"). This pins the whole HMAC chain, so a future bump of
    /// `hmac`/`sha2` that changes the output bytes fails here instead of turning every
    /// request into a 403.
    #[test]
    fn signature_key_matches_aws_reference_vector() {
        let key = get_signature_key(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20120215",
            "us-east-1",
            "iam",
        );

        assert_eq!(
            hex::encode(key),
            "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d"
        );
    }

    /// The payload hash is hex-encoded by hand at every call site; a byte < 0x10 must
    /// stay zero-padded to two digits. `sha2::Sha256::digest(b"")` is the canonical
    /// empty-payload hash SigV4 uses for bodyless requests.
    #[test]
    fn empty_payload_hash_is_the_canonical_sha256() {
        assert_eq!(
            hex::encode(sha2::Sha256::digest([].as_slice())),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn amz_timestamp_is_compact_iso8601_utc() {
        let timestamp = get_amz_timestamp();

        // AWS requires exactly YYYYMMDDTHHMMSSZ - 16 chars, no separators, no fraction.
        assert_eq!(timestamp.len(), 16, "got {:?}", timestamp);
        assert!(timestamp.ends_with('Z'), "got {:?}", timestamp);
        assert_eq!(timestamp.as_bytes()[8], b'T', "got {:?}", timestamp);
        assert!(
            timestamp[..8].bytes().all(|b| b.is_ascii_digit())
                && timestamp[9..15].bytes().all(|b| b.is_ascii_digit()),
            "got {:?}",
            timestamp
        );
    }

    #[test]
    fn no_query_canonicalises_to_empty_string() {
        assert_eq!(canonical_query_string(None), "");
        assert_eq!(canonical_query_string(Some("")), "");
    }

    /// `?uploads` is a valueless flag; SigV4 wants it as `uploads=`.
    #[test]
    fn valueless_param_gets_an_equals_sign() {
        assert_eq!(canonical_query_string(Some("uploads")), "uploads=");
    }

    /// UploadPart sends `?partNumber=N&uploadId=X`; SigV4 wants them name-sorted, and
    /// "partNumber" < "uploadId" so this pair happens to already be in order - the
    /// point of the test is that the values survive untouched.
    #[test]
    fn upload_part_query_is_sorted_by_name() {
        assert_eq!(
            canonical_query_string(Some("uploadId=abc123&partNumber=7")),
            "partNumber=7&uploadId=abc123"
        );
    }

    /// The pairs must be passed through byte-for-byte: whatever FlUrl percent-encoded
    /// is what the server sees, so re-encoding (or decoding) here breaks the signature.
    #[test]
    fn already_encoded_values_are_not_touched() {
        assert_eq!(
            canonical_query_string(Some("uploadId=2%7EabC.d-e_f%2Bg")),
            "uploadId=2%7EabC.d-e_f%2Bg"
        );
    }

    fn encode(value: &str) -> String {
        let mut result = String::new();
        encode_uri_component(value, &mut result);
        result
    }

    /// The rule itself: `A-Za-z0-9-_.~` and nothing else survives. `~` in particular is
    /// unreserved and must stay literal - encoding it is as wrong as not encoding a
    /// space.
    #[test]
    fn only_the_unreserved_set_survives_uri_encoding() {
        assert_eq!(
            encode("abcXYZ019-_.~"),
            "abcXYZ019-_.~",
            "the unreserved set must pass through untouched"
        );

        for (raw, encoded) in [
            (" ", "%20"),
            ("/", "%2F"),
            ("+", "%2B"),
            ("=", "%3D"),
            ("!", "%21"),
            ("*", "%2A"),
            ("'", "%27"),
            ("(", "%28"),
            (")", "%29"),
            ("%", "%25"),
            ("&", "%26"),
            ("?", "%3F"),
            ("#", "%23"),
            (":", "%3A"),
            ("@", "%40"),
            (",", "%2C"),
            (";", "%3B"),
            ("$", "%24"),
        ] {
            assert_eq!(encode(raw), encoded, "wrong encoding for {:?}", raw);
        }
    }

    /// **The divergence this function exists for.** `FlUrl`'s own query encoder is an
    /// `x-www-form-urlencoded` one: a space becomes `+` and `!` is left alone. Either
    /// would be a 403 that reads as a credentials problem, because the server rebuilds
    /// the canonical query by the RFC 3986 rule and never sees ours.
    #[test]
    fn a_space_is_percent_20_and_never_a_plus() {
        assert_eq!(encode("a b"), "a%20b");
        assert!(!encode("a b").contains('+'));
        // And a literal plus is not a space either - the two must stay distinguishable.
        assert_eq!(encode("a+b"), "a%2Bb");
    }

    /// The parameter that is almost never free of `/`: a folder prefix, with a space in
    /// it for good measure. This exact value is the one that used to come back as an
    /// empty listing *and* a signature mismatch at the same time.
    #[test]
    fn a_folder_prefix_is_encoded_the_way_sigv4_reads_it() {
        assert_eq!(encode("photos/2024 summer/"), "photos%2F2024%20summer%2F");
    }

    /// A continuation token is base64 and therefore carries `+`, `/` and `=` - the three
    /// characters a query string is least able to leave alone. Sending any of them raw
    /// would end the parameter early or be re-read as a different token.
    #[test]
    fn a_continuation_token_survives_its_base64_punctuation() {
        assert_eq!(
            encode("1ueGcxLPRx1Tr/XYExHnhbYLgveDs2J/wm36Hy4vbOwM="),
            "1ueGcxLPRx1Tr%2FXYExHnhbYLgveDs2J%2Fwm36Hy4vbOwM%3D"
        );
    }

    /// Encoding runs over UTF-8 bytes, not chars, which is the only way the server's
    /// re-encoding of the same key lands on the same string. Hex digits are uppercase,
    /// as RFC 3986 and every AWS SDK write them.
    #[test]
    fn non_ascii_is_encoded_byte_wise_in_uppercase_hex() {
        assert_eq!(encode("Пример"), "%D0%9F%D1%80%D0%B8%D0%BC%D0%B5%D1%80");
        assert_eq!(encode("café"), "caf%C3%A9");
        assert_eq!(encode("\u{1F600}"), "%F0%9F%98%80");
    }

    /// Neither `=` nor `&` can survive encoding, which is what lets
    /// `canonical_query_string` split the query on them without ambiguity.
    #[test]
    fn an_encoded_value_can_not_forge_a_query_separator() {
        let mut query = String::new();
        append_query_param(&mut query, "prefix", Some("a=1&b=2"));

        assert_eq!(query, "prefix=a%3D1%26b%3D2");
        assert_eq!(query.matches('=').count(), 1);
        assert_eq!(query.matches('&').count(), 0);
    }

    /// A parameter that was not asked for is not sent at all. S3 reads `delimiter=` as
    /// "with an empty delimiter", which is a different request from "no delimiter".
    #[test]
    fn a_none_parameter_is_not_sent() {
        let mut query = String::from("list-type=2");

        append_query_param(&mut query, "prefix", None);
        append_query_param(&mut query, "delimiter", None);

        assert_eq!(query, "list-type=2");

        // An empty value, on the other hand, was asked for and is sent.
        append_query_param(&mut query, "prefix", Some(""));
        assert_eq!(query, "list-type=2&prefix=");
    }

    /// The `&` goes between parameters and never in front of the first one - including
    /// when the query starts out empty.
    #[test]
    fn parameters_are_joined_with_a_single_ampersand() {
        let mut query = String::new();

        append_query_param(&mut query, "a", Some("1"));
        append_query_param(&mut query, "b", Some("2"));

        assert_eq!(query, "a=1&b=2");
    }

    /// The whole reason this is safe to sign: what we build is already canonical-ready,
    /// so `canonical_query_string` only has to sort it.
    #[test]
    fn a_hand_built_query_canonicalises_by_sorting_alone() {
        let mut query = String::from("list-type=2");
        append_query_param(&mut query, "prefix", Some("photos/2024 summer/"));
        append_query_param(&mut query, "delimiter", Some("/"));

        assert_eq!(
            canonical_query_string(Some(query.as_str())),
            "delimiter=%2F&list-type=2&prefix=photos%2F2024%20summer%2F"
        );
    }

    /// Sorting is by name first, then value - not by the joined "name=value" string.
    /// '-' (0x2D) sorts before '=' (0x3D), so a byte-wise sort of the joined strings
    /// would put `a-b` before `a`, which is not the order AWS specifies.
    #[test]
    fn sort_is_by_name_then_value_not_by_joined_pair() {
        assert_eq!(canonical_query_string(Some("a-b=1&a=2")), "a=2&a-b=1");
        assert_eq!(canonical_query_string(Some("k=2&k=1")), "k=1&k=2");
    }

    const EMPTY_PAYLOAD_HASH: &str =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    const TIMESTAMP: &str = "20261014T120000Z";

    /// The canonical request exactly as it was built before headers could be added to
    /// the signature - one `format!` with the three headers written into it.
    fn canonical_request_as_it_was(
        method: &str,
        canonical_uri: &str,
        canonical_query: &str,
        host: &str,
        payload_hash: &str,
        timestamp: &str,
    ) -> String {
        format!(
            "{}\n{}\n{}\nhost:{}\nx-amz-content-sha256:{}\nx-amz-date:{}\n\nhost;x-amz-content-sha256;x-amz-date\n{}",
            method, canonical_uri, canonical_query, host, payload_hash, timestamp, payload_hash
        )
    }

    /// A signature is all or nothing: every request that signs no header of its own has
    /// to keep producing the very bytes it always did, or it is a 403.
    #[test]
    fn without_extra_headers_the_canonical_request_is_the_one_it_always_was() {
        for (method, canonical_uri, canonical_query, payload_hash) in [
            ("GET", "/my-bucket/my%20folder/a.txt", "", EMPTY_PAYLOAD_HASH),
            ("PUT", "/my-bucket/archives/backup.tar", "", "UNSIGNED-PAYLOAD"),
            (
                "GET",
                "/my-bucket",
                "delimiter=%2F&list-type=2&prefix=photos%2F",
                EMPTY_PAYLOAD_HASH,
            ),
            ("GET", "/my-bucket", "location=", EMPTY_PAYLOAD_HASH),
            ("HEAD", "/my-bucket", "", EMPTY_PAYLOAD_HASH),
        ] {
            let (canonical, signed_headers) = canonical_request(
                method,
                canonical_uri,
                canonical_query,
                "127.0.0.1:9000",
                payload_hash,
                TIMESTAMP,
                &[],
            );

            assert_eq!(
                canonical,
                canonical_request_as_it_was(
                    method,
                    canonical_uri,
                    canonical_query,
                    "127.0.0.1:9000",
                    payload_hash,
                    TIMESTAMP,
                )
            );
            assert_eq!(signed_headers, "host;x-amz-content-sha256;x-amz-date");
        }
    }

    /// `x-amz-copy-source` sorts between `x-amz-content-sha256` and `x-amz-date` - `n`
    /// before `p`, `c` before `d` - in the canonical headers and in `SignedHeaders` alike.
    #[test]
    fn an_extra_header_takes_its_alphabetical_place() {
        let (canonical, signed_headers) = canonical_request(
            "PUT",
            "/dst-bucket/b.bin",
            "",
            "127.0.0.1:9000",
            EMPTY_PAYLOAD_HASH,
            TIMESTAMP,
            &[("x-amz-copy-source", "/src-bucket/a.bin")],
        );

        assert_eq!(
            signed_headers,
            "host;x-amz-content-sha256;x-amz-copy-source;x-amz-date"
        );
        assert_eq!(
            canonical,
            format!(
                "PUT\n/dst-bucket/b.bin\n\nhost:127.0.0.1:9000\nx-amz-content-sha256:{0}\nx-amz-copy-source:/src-bucket/a.bin\nx-amz-date:{1}\n\nhost;x-amz-content-sha256;x-amz-copy-source;x-amz-date\n{0}",
                EMPTY_PAYLOAD_HASH, TIMESTAMP
            )
        );
    }

    /// The name is signed lowercased however it is sent, and the value the way the
    /// storage will read it back: trimmed, inner runs of spaces folded into one.
    #[test]
    fn an_extra_header_is_canonicalised_the_sigv4_way() {
        let (canonical, signed_headers) = canonical_request(
            "PUT",
            "/my-bucket/a.bin",
            "",
            "127.0.0.1:9000",
            EMPTY_PAYLOAD_HASH,
            TIMESTAMP,
            &[("X-Amz-Meta-Note", "  two   words  ")],
        );

        assert_eq!(
            signed_headers,
            "host;x-amz-content-sha256;x-amz-date;x-amz-meta-note"
        );
        assert!(
            canonical.contains("\nx-amz-meta-note:two words\n"),
            "got {:?}",
            canonical
        );
    }
}
