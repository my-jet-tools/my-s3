//! `ListBuckets` - the buckets the keys of a client can see.

use crate::{S3ConnectionString, S3Error};

/// Every bucket the keys of a connection string can see - `ListBuckets`, `GET /` on its
/// `Endpoint`, signed with its `Region` and keys - in the order the storage gives them.
///
/// `Bucket` of the string is not read: write `Bucket=*` - "every bucket" - so that the string
/// still reads as any other. A string which can not be read is [`S3Error::Other`] saying why, and
/// never quoting a value whole.
///
/// ```no_run
/// # async fn doc() -> Result<(), my_s3::S3Error> {
/// let buckets = my_s3::list_buckets(
///     "Endpoint=https://fsn1.your-objectstorage.com;Region=fsn1;AccessKey=...;SecretKey=...;Bucket=*",
/// )
/// .await?;
///
/// for bucket in &buckets {
///     println!("{}", bucket.name);
/// }
/// # Ok(())
/// # }
/// ```
pub async fn list_buckets(connection_string: &str) -> Result<Vec<S3BucketInfo>, S3Error> {
    let connection = S3ConnectionString::parse(connection_string)
        .map_err(|err| S3Error::Other(format!("The connection string can not be read: {err}")))?;

    connection.create_client().list_buckets().await
}

/// One bucket of a `ListBuckets` answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S3BucketInfo {
    /// The name of the bucket - what every other call of the client takes.
    pub name: String,
    /// `<CreationDate>` exactly as the storage wrote it - ISO 8601, normally
    /// `2024-07-01T12:34:56.000Z` - when it sent one. Left as a string, as
    /// [`crate::S3ObjectInfo::last_modified`] is.
    pub creation_date: Option<String>,
    /// `<BucketRegion>` - AWS sends it; Ceph (Hetzner) and MinIO may not.
    pub region: Option<String>,
}

/// One page of a `ListBuckets` answer, and what the next one is asked with.
#[derive(Debug)]
pub(crate) struct ListBucketsPage {
    pub buckets: Vec<S3BucketInfo>,
    /// `Some` while there is a next page to ask for with `continuation-token`.
    pub continuation_token: Option<String>,
}

/// Root children worth stopping at. `<Owner>`, `<Prefix>` and whatever a given implementation
/// adds are skipped by the walker.
const PAGE_ELEMENTS: &[&str] = &["Buckets", "ContinuationToken"];

const BUCKET_ELEMENTS: &[&str] = &["Name", "CreationDate", "BucketRegion"];

/// Reads a `ListBuckets` answer.
///
/// The elements are read in whatever order they arrive, as in a `ListObjectsV2` answer: AWS
/// puts `<Owner>` first and `<ContinuationToken>` after `<Buckets>`, and another implementation
/// is free to do otherwise.
pub(crate) fn parse_list_buckets(body: &[u8]) -> Result<ListBucketsPage, S3Error> {
    let walker = match crate::xml::XmlWalker::open(body, "ListAllMyBucketsResult") {
        Ok(walker) => walker,
        Err(err) => {
            return Err(S3Error::Other(format!(
                "ListBuckets answered with a body that is not a ListAllMyBucketsResult ({}): {}",
                err,
                String::from_utf8_lossy(body)
            )));
        }
    };

    // Readable, and not a list of buckets: the answer is not the one that was asked for. An
    // `<Error>` body has already been typed by `read_success_body`.
    let Some(mut walker) = walker else {
        return Err(S3Error::Other(format!(
            "ListBuckets answered with a body that is not a ListAllMyBucketsResult: {}",
            String::from_utf8_lossy(body)
        )));
    };

    let mut buckets = Vec::new();
    let mut continuation_token = None;

    while let Some(node) = walker.next_child(PAGE_ELEMENTS).map_err(malformed)? {
        match node.name {
            "Buckets" => {
                while let Some(bucket) = walker
                    .next_child_of(&node, &["Bucket"])
                    .map_err(malformed)?
                {
                    buckets.push(read_bucket(&mut walker, bucket)?);
                }
            }
            "ContinuationToken" => {
                let token = walker.read_text(node).map_err(malformed)?;

                if !token.is_empty() {
                    continuation_token = Some(token);
                }
            }
            // `next_child` only ever returns a name from the list it was given.
            _ => {}
        }
    }

    Ok(ListBucketsPage {
        buckets,
        continuation_token,
    })
}

fn read_bucket<'t>(
    walker: &mut crate::xml::XmlWalker<'t>,
    bucket: my_xml_reader::XmlTagInfo<'t>,
) -> Result<S3BucketInfo, S3Error> {
    let mut name = None;
    let mut creation_date = None;
    let mut region = None;

    while let Some(field) = walker
        .next_child_of(&bucket, BUCKET_ELEMENTS)
        .map_err(malformed)?
    {
        let field_name = field.name;
        let value = walker.read_text(field).map_err(malformed)?;

        match field_name {
            "Name" => name = Some(value),
            "CreationDate" => creation_date = Some(value).filter(|value| !value.is_empty()),
            "BucketRegion" => region = Some(value).filter(|value| !value.is_empty()),
            _ => {}
        }
    }

    // A bucket with no name is not one a client can address: a list that silently dropped it
    // would look complete.
    let name = name.filter(|name| !name.is_empty()).ok_or_else(|| {
        S3Error::Other("ListBuckets sent a <Bucket> with no <Name> in it".to_string())
    })?;

    Ok(S3BucketInfo {
        name,
        creation_date,
        region,
    })
}

fn malformed(err: String) -> S3Error {
    S3Error::Other(format!("ListBuckets answered with malformed XML: {}", err))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shape AWS documents: `<Owner>` first, `<BucketRegion>` in every bucket, and - when it
    /// pages - `<ContinuationToken>` after the buckets.
    const AWS_PAGE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Owner>
    <ID>75aa57f09aa0c8caeab4f8c24e99d10f8e7faeebf76c078efc7c6caea54ba06a</ID>
    <DisplayName>someone</DisplayName>
  </Owner>
  <Buckets>
    <Bucket>
      <Name>amzn-s3-demo-bucket</Name>
      <CreationDate>2024-07-01T12:34:56.000Z</CreationDate>
      <BucketRegion>us-east-1</BucketRegion>
    </Bucket>
    <Bucket>
      <Name>reports &amp; logs</Name>
      <CreationDate>2024-08-01T00:00:00.000Z</CreationDate>
      <BucketRegion>eu-central-1</BucketRegion>
    </Bucket>
  </Buckets>
  <ContinuationToken>dGhlIG5leHQgcGFnZQ==</ContinuationToken>
</ListAllMyBucketsResult>"#;

    #[test]
    fn the_aws_page_reads_with_its_token() {
        let page = parse_list_buckets(AWS_PAGE.as_bytes()).unwrap();

        assert_eq!(
            page.buckets,
            [
                S3BucketInfo {
                    name: "amzn-s3-demo-bucket".to_string(),
                    creation_date: Some("2024-07-01T12:34:56.000Z".to_string()),
                    region: Some("us-east-1".to_string()),
                },
                S3BucketInfo {
                    // Unescaped, as a key of a listing is.
                    name: "reports & logs".to_string(),
                    creation_date: Some("2024-08-01T00:00:00.000Z".to_string()),
                    region: Some("eu-central-1".to_string()),
                },
            ]
        );
        assert_eq!(
            page.continuation_token.as_deref(),
            Some("dGhlIG5leHQgcGFnZQ==")
        );
    }

    /// Ceph RGW - what Hetzner runs: no `<BucketRegion>`, no token, `<Owner>` after the buckets,
    /// and the fields of a bucket in another order.
    #[test]
    fn a_ceph_answer_reads_the_same() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?><ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Buckets><Bucket><CreationDate>2025-01-02T03:04:05.000Z</CreationDate><Name>backups</Name></Bucket><Bucket><Name>media</Name><CreationDate>2025-02-03T04:05:06.000Z</CreationDate></Bucket></Buckets><Owner><ID>project</ID><DisplayName>project</DisplayName></Owner></ListAllMyBucketsResult>"#;

        let page = parse_list_buckets(xml.as_bytes()).unwrap();

        let names: Vec<&str> = page
            .buckets
            .iter()
            .map(|bucket| bucket.name.as_str())
            .collect();

        assert_eq!(names, ["backups", "media"]);
        assert_eq!(page.buckets[0].region, None);
        assert_eq!(
            page.buckets[0].creation_date.as_deref(),
            Some("2025-01-02T03:04:05.000Z")
        );
        assert_eq!(page.continuation_token, None);
    }

    #[test]
    fn no_buckets_is_an_empty_list_not_an_error() {
        for xml in [
            "<ListAllMyBucketsResult><Owner><ID>x</ID></Owner><Buckets/></ListAllMyBucketsResult>",
            "<ListAllMyBucketsResult><Buckets></Buckets></ListAllMyBucketsResult>",
            "<ListAllMyBucketsResult><Owner><ID>x</ID></Owner></ListAllMyBucketsResult>",
            "<ListAllMyBucketsResult/>\n",
        ] {
            let page = parse_list_buckets(xml.as_bytes()).unwrap();

            assert!(page.buckets.is_empty(), "{xml}");
            assert_eq!(page.continuation_token, None, "{xml}");
        }
    }

    /// An empty token is no next page - handing it back would ask for the first page again.
    #[test]
    fn an_empty_token_is_no_next_page() {
        let xml = "<ListAllMyBucketsResult><Buckets><Bucket><Name>a</Name></Bucket></Buckets><ContinuationToken/></ListAllMyBucketsResult>";

        assert_eq!(
            parse_list_buckets(xml.as_bytes())
                .unwrap()
                .continuation_token,
            None
        );
    }

    /// A name buried in `<Owner>` is not the name of a bucket, and a bucket without one of its
    /// own is an error, never a bucket dropped from the list.
    #[test]
    fn a_bucket_with_no_name_is_an_error() {
        let xml = "<ListAllMyBucketsResult><Buckets><Bucket><Owner><Name>owner</Name></Owner><CreationDate>x</CreationDate></Bucket></Buckets></ListAllMyBucketsResult>";

        assert!(parse_list_buckets(xml.as_bytes()).is_err());

        let empty = "<ListAllMyBucketsResult><Buckets><Bucket><Name></Name></Bucket></Buckets></ListAllMyBucketsResult>";

        assert!(parse_list_buckets(empty.as_bytes()).is_err());
    }

    #[test]
    fn what_is_not_a_list_of_buckets_is_an_error() {
        for body in [
            b"".as_slice(),
            b"<html><body>nope</body></html>".as_slice(),
            b"<ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>".as_slice(),
            b"<ListAllMyBucketsResult><Buckets><Bucket><Name>half".as_slice(),
        ] {
            assert!(
                parse_list_buckets(body).is_err(),
                "{:?} must not read as a list of buckets",
                String::from_utf8_lossy(body)
            );
        }
    }
}
