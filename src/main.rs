use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use env_logger::Env;
#[cfg(not(test))]
use log::info;
use openssl::symm::Mode;
use openssl::{
    rand::rand_bytes,
    symm::{Cipher, Crypter},
};
use pipe::{pipe, PipeReader};
use reqwest::Url;
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::pkcs8::{DecodePublicKey, LineEnding};
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use serde_json::Value;
use tar::Builder;
use zip::{write::SimpleFileOptions, CompressionMethod, ZipArchive, ZipWriter};

use base64::prelude::*;
#[cfg(test)]
use std::println as info;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{
    fs::File,
    io::{stdout, Bytes, Cursor, Read, Seek, Write},
    path::PathBuf,
    thread,
};

fn main() -> Result<()> {
    let env = Env::default()
        .filter_or("MY_LOG_LEVEL", "info")
        .write_style_or("MY_LOG_STYLE", "always");

    env_logger::init_from_env(env);

    let args = Args::parse();

    let pub_key_pem = args.get_pub_key()?;

    let return_key_dest = args.ret.clone();
    let uuid = args.get_uuid()?;

    let (mut payload, mime_type) = args.get_payload()?;
    info!("Got enough info to create payload");
    let (zip_file, return_key) = create_zip(
        &uuid,
        &pub_key_pem,
        &mut payload,
        Some(mime_type),
        if args.encrypt_only {
            Some(PathBuf::from("."))
        } else {
            None
        },
        return_key_dest.is_some(),
    )?;
    if args.encrypt_only {
        info!("Wrote encrypted file to {:?}", zip_file);
    } else {
        let jwt = args.get_jwt()?;

        let target_server = args.get_server()?;
        let client = reqwest::blocking::Client::builder().timeout(None).build()?;
        let posted = client
            .post(target_server.clone())
            .bearer_auth(jwt)
            .body(File::open(&zip_file)?)
            .send()
            .with_context(|| format!("uploading {:?} to {:?}", zip_file, target_server))?;

        if posted.status().is_success() {
            info!("Successfully sent bundle");

            match (return_key_dest, return_key) {
                (Some(dest), Some(key)) => {
                    let mut dest_file: Box<dyn Write> = if dest == "-" {
                        Box::new(stdout())
                    } else {
                        Box::new(File::create(dest)?)
                    };
                    dest_file.write_all(key.as_bytes())?;
                }

                _ => {}
            }
        } else {
            bail!("Failed to send package {} {}", posted.status(),String::from_utf8( posted.bytes()?.iter().map(|b| *b).collect())?)
        }
    }
    Ok(())
}

#[derive(Parser, Debug, Default, Clone, PartialEq)]
#[command(version, about, long_about = None, arg_required_else_help = true)]
struct Args {
    /// The location of the zip file that contains JWT, server, & public key
    #[arg(long, short)]
    pub zipin: Option<PathBuf>,

    /// The JWT to use to communicate with the server (if `zipin` provided, that's authoritative)
    #[arg(long, short)]
    pub jwt: Option<String>,

    /// The file that contains the public key PEM used to encrypt the upload
    /// if `zipin` contains the key, this option with be ignored
    #[arg(long, short)]
    pub key: Option<PathBuf>,

    /// The address of the server to post the results to
    /// /// if `zipin` contains the server, this option with be ignored
    #[arg(long, short)]
    pub server: Option<Url>,

    /// Generate a public/private key pair to use to encrypt returned information.
    /// If the value is `-`, the private key PEM will be written to standard output.
    /// If the value is any other string, a new file will be created and the
    /// private key PEM will be written to the file. If there is a problem writing
    /// to the file, the PEM will be written to standard output.
    #[arg(long, short)]
    pub ret: Option<String>,

    /// The path to the payload to upload. It can be an individual file
    /// or a directory. If it's a directory, the contents will be TARed
    /// for upload
    #[arg(long, short)]
    pub payload: PathBuf,

    /// Only encrypt using the key. Do not upload.
    #[arg(long, short, action)]
    pub encrypt_only: bool,

    /// For encrypt_only operations, provide the uuid that would
    /// otherwise be provided by the JWT
    #[arg(long)]
    pub uuid: Option<String>,
}

impl Args {
    pub fn jwt_to_uuid(jwt: &str) -> Result<String> {
        let ss = jwt.split('.').collect::<Vec<&str>>();
        if ss.len() < 2 {
            bail!("JWT not '.' separated");
        }

        let decoded = BASE64_STANDARD_NO_PAD.decode(ss[1])?;
        let parsed: Value = serde_json::from_slice(&decoded)?;
        if let Value::Object(obj) = &parsed {
            if let Some(Value::String(uuid)) = obj.get("uuid") {
                return Ok(uuid.clone());
            }
        }
        bail!("Could not find `uuid` entry in {:?}", parsed);
    }
    pub fn get_jwt(&self) -> Result<String> {
        if let Some(jwt) = self.get_item_from_zip("jwt.txt")? {
            info!("Got jwt from zip {}", jwt);
            Ok(jwt)
        } else {
            match &self.jwt {
                Some(s) => Ok(s.clone()),
                None => bail!("Can't find jwt. Please use the -jwt flag"),
            }
        }
    }

    pub fn get_uuid(&self) -> Result<String> {
        match self.get_jwt() {
            Ok(jwt) => Args::jwt_to_uuid(&jwt),
            Err(_) => match &self.uuid {
                Some(uuid) => Ok(uuid.clone()),
                _ => bail!("Must either provide a JWT or a uuid"),
            },
        }
    }

    pub fn get_pub_key(&self) -> Result<String> {
        if let Some(pem) = self.get_item_from_zip("pub_key.pem")? {
            Ok(pem)
        } else {
            match &self.key {
                Some(s) => {
                    let f = File::open(s)?;
                    Args::bytes_to_string(f.bytes())
                }
                None => bail!("Can't find the public key. Please use the `-k` flag"),
            }
        }
    }

    pub fn get_server(&self) -> Result<Url> {
        if let Some(server) = self.get_item_from_zip("server.txt")? {
            Url::parse(&server)
                .map_err(|e| anyhow::anyhow!("Failed to parse {} with error {}", server, e))
        } else {
            match &self.server {
                Some(s) => Ok(s.clone()),
                None => bail!("Unable to find the server URL. Please use the `-s` flag"),
            }
        }
    }

    pub fn get_payload(&self) -> Result<(PipeReader, String)> {
        let is_dir = self.payload.is_dir();
        let the_path = self.payload.to_path_buf();
        let mime_type = if self.payload.is_dir() {
            "application/tar"
        } else {
            "application/octet-stream"
        };

        info!("payload mime {}", mime_type);

        let (read, mut write) = pipe();

        thread::spawn(move || {
            if is_dir {
                let mut b = Builder::new(write);
                let mut tar_path = PathBuf::new();
                tar_path.push("data");
                for v in &the_path {
                    tar_path.push(v);
                }
                match b.append_dir_all(tar_path, the_path) {
                    Ok(_) => {}
                    _ => {
                        return;
                    }
                };
                let _ = b.finish();
            } else {
                if let Ok(mut f) = File::open(the_path) {
                    let mut in_buf = [0u8; 4096];
                    loop {
                        if let Ok(len) = f.read(&mut in_buf) {
                            if len == 0 {
                                return;
                            }
                            if write.write_all(&mut in_buf[0..len]).is_err() {
                                return;
                            }
                        } else {
                            return;
                        }
                    }
                }
            }
        });

        //thread::

        Ok((read, mime_type.to_string()))
    }

    fn get_item_from_zip(&self, item_name: &str) -> Result<Option<String>> {
        if let Some(path) = self.clone().zipin {
            let file = File::open(&path)?;
            Ok({
                let mut zip =
                    ZipArchive::new(file).with_context(|| format!("Zip file {:}", path.to_string_lossy()))?;
                let item = zip.by_name(item_name).with_context(|| format!("Reading {:} from {:}", item_name, path.to_string_lossy()))?;
                Args::bytes_to_string(item.bytes()).ok()
            })
        } else {
            Ok(None)
        }
    }

    fn bytes_to_string<R: Read>(bytes: Bytes<R>) -> Result<String> {
        let ret: Vec<u8> = match bytes.collect() {
            Ok(b) => b,
            Err(e) => return Err(anyhow!("Failed to collect bytes {}", e)),
        };
        let str = String::from_utf8(ret)?;

        Ok(str)
    }
}

fn key_from_rsa_pub(pub_key: &str) -> Result<RsaPublicKey> {
    let ret = RsaPublicKey::from_public_key_pem(pub_key)?;
    Ok(ret)
}

fn encrypt_with_public_key(pub_key: RsaPublicKey, to_encrypt: &[u8]) -> Result<Vec<u8>> {
    let padding = Oaep::new::<sha2::Sha256>();
    let mut rng = rand::thread_rng();
    let res = pub_key.encrypt(&mut rng, padding, to_encrypt)?;
    Ok(res)
}

fn create_zip<R: Read>(
    uuid: &str,
    pub_key_pem: &str,
    payload: &mut R,
    payload_mime_type: Option<String>,
    directory: Option<PathBuf>,
    return_key: bool,
) -> Result<(PathBuf, Option<String>)> {
    let mut directory = directory.unwrap_or_else(|| PathBuf::from("/tmp"));
    directory.push(format!(
        "{}-{}.zip",
        uuid,
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis()
    ));
    let file = File::create(directory.clone())?;
    let mut zip = ZipWriter::new(file);
    let file_options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
    let big_file_options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        // files over u32::MAX require this flag set.
        .large_file(true);
    {
        zip.start_file("uuid.txt", file_options.clone())?;
        zip.write_all(uuid.as_bytes())?;
    }
    info!("Wrote uuid");

    // if we want a return key, write the public key into the zip and return
    // the PEM of the private key
    let return_key: Option<String> = {
        if return_key {
            use rsa::pkcs1::EncodeRsaPublicKey;
            let mut rng = rand::thread_rng();
            let rsa_key = RsaPrivateKey::new(&mut rng, 4096)?;
            let pub_key = RsaPublicKey::from(&rsa_key).to_pkcs1_pem(LineEnding::LF)?;

            zip.start_file("return_key.pem", file_options.clone())?;
            zip.write_all(pub_key.as_bytes())?;
            let pem = rsa_key.to_pkcs1_pem(LineEnding::LF)?;
            let pem: &str = &pem;
            Some(pem.to_string())
        } else {
            None
        }
    };

    let secret_key = gen_aes_key()?;
    {
        let pub_key = key_from_rsa_pub(&pub_key_pem)?;
        let encrypted_secret_key = encrypt_with_public_key(pub_key, &secret_key)?;
        zip.start_file("key.txt", file_options.clone())?;
        zip.write_all(BASE64_STANDARD.encode(encrypted_secret_key).as_bytes())?;
    }

    info!("Wrote key");

    {
        zip.start_file("pubkey.pem", file_options.clone())?;
        zip.write_all(pub_key_pem.as_bytes())?;
    }

    info!("Wrote pub key");

    {
        let random = random_bytes(128)?;
        let mut out = Cursor::new(vec![0u8; random.len() + 16]);
        let (_len, iv) = aes_encrypt(secret_key.clone(), None, &mut random.as_slice(), &mut out)?;
        let out = out.into_inner();
        zip.start_file("test.txt", file_options.clone())?;
        zip.write_all(
            format!(
                "{}\n{}\n{}",
                BASE64_STANDARD.encode(&iv),
                BASE64_STANDARD.encode(&random),
                BASE64_STANDARD.encode(&out)
            )
            .as_bytes(),
        )?;
    }
    info!("Wrote test file");

    let iv = gen_iv()?;
    {
        zip.start_file("iv.txt", file_options.clone())?;
        zip.write_all(BASE64_STANDARD.encode(&iv).as_bytes())?;
    }
    info!("Wrote iv");

    {
        zip.start_file("mime.txt", file_options.clone())?;
        zip.write_all(
            payload_mime_type
                .unwrap_or("application/octect-stream".to_string())
                .as_bytes(),
        )?;
    }
    info!("Wrote mime");

    {
        zip.start_file("payload.enc", big_file_options)?;
        aes_encrypt(secret_key, Some(iv), payload, &mut zip)?;
    }
    info!("Wrote payload");

    zip.flush()?;
    Ok((directory, return_key))
}

fn aes_encrypt<R: Read, W: Write>(
    key: SymKey,
    maybe_iv: Option<IV>,
    plain: &mut R,
    out: &mut W,
) -> Result<(usize, IV)> {
    let iv = match maybe_iv {
        Some(v) => v,
        None => gen_iv()?,
    };

    let cipher = Cipher::aes_256_gcm();
    let mut total_len = 0;

    let mut crypter = Crypter::new(cipher, Mode::Encrypt, &key, Some(&iv))?;
    crypter.pad(false);

    let mut in_buffer = [0u8; 4096];
    let mut out_buffer = [0u8; 4096];

    loop {
        let len = plain.read(&mut in_buffer)?;
        if len == 0 {
            break;
        }
        let enc = crypter.update(&in_buffer[0..len], &mut out_buffer)?;
        total_len += enc;
        out.write_all(&out_buffer[0..enc])?;
    }
    let enc = crypter.finalize(&mut out_buffer)?;

    total_len += enc;
    out.write_all(&out_buffer[0..enc])?;

    let mut tag = [0u8; 16];
    crypter.get_tag(&mut tag)?;
    total_len += tag.len();
    out.write_all(&tag)?;

    Ok((total_len, iv))
}

fn _aes_decrypt<R: Read + Seek, W: Write>(
    key: SymKey,
    iv: IV,
    encrypted: &mut R,
    out: &mut W,
) -> Result<usize> {
    let end = encrypted.seek(std::io::SeekFrom::End(-16))?;
    let mut tag = [0u8; 16];
    encrypted.read_exact(&mut tag)?;
    encrypted.seek(std::io::SeekFrom::Start(0))?;
    let cipher = Cipher::aes_256_gcm();
    let mut total_len = 0;

    let mut crypter = Crypter::new(cipher, Mode::Decrypt, &key, Some(&iv))?;
    crypter.pad(false);

    let mut in_buffer = [0u8; 4096];
    let mut out_buffer = [0u8; 4096];

    while total_len < end {
        let to_read = if total_len + (in_buffer.len() as u64) <= end {
            in_buffer.len()
        } else {
            (end - total_len) as usize
        };
        let len = encrypted.read(&mut in_buffer[0..to_read])?;
        if len == 0 {
            break;
        }
        let enc = crypter.update(&in_buffer[0..len], &mut out_buffer)?;
        total_len += enc as u64;
        out.write_all(&out_buffer[0..enc])?;
    }

    crypter.set_tag(&tag)?;

    let enc = crypter.finalize(&mut out_buffer)?;

    out.write_all(&out_buffer[0..enc])?;

    Ok(total_len as usize)
}

type SymKey = [u8; 32];
type IV = [u8; 12];

fn gen_aes_key() -> Result<SymKey> {
    let mut buf = [0; 32];
    rand_bytes(&mut buf)?;

    Ok(buf)
}

fn gen_iv() -> Result<IV> {
    let mut buf = [0; 12];
    rand_bytes(&mut buf)?;

    Ok(buf)
}

fn random_bytes(len: usize) -> Result<Vec<u8>> {
    let mut ret = vec![0u8; len];
    rand_bytes(ret.as_mut_slice())?;
    Ok(ret)
}

#[cfg(test)]
mod inner_test {

    use base64::prelude::*;

    const PUB_KEY: &str = r#"-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA+q8QFhkrmIrsaiY7g2RJ
H/B7wnr7HfUicJ/9KfUgLwgA85AkQOX326qQ9BgmNDyolUmVNbrZ98uKE1UNfKqc
/nCzJ9veE9XonVXcO5vKHLAb5N5qC2xIQU8uCxPYFFco6t0zmoZSoeMaRN4StVlB
m0YkCc0RhgpLqO2zFoHaWpAZq02kX/NHczuQb8YqhyPo5tKuWTB18J9wYka4/LOp
g3b2L8qNJqCkApVo7hbGsGeAWVIr3b8qar1LzV1l0+YJrwG4tfadOxXXDlFbzRV1
TVRMb4EEWp/IzBzQ43KhIlzthvqCyGz4sNkYy5QTyHnMgCAh9yPvzskXi3pNl1xV
ygYXFu73n91AMEr4ugzMYwGL9AZTocu2wmB7UgICL4fW0K3qYTzE2EP+QqIX5KFv
HyYPgBkfs5waH88rbtkUN0/MXBXKpS64sx712odYzLR7tDWj260zqcOmV8TyC0Xu
M8CS00VddnEILgP6Ogxjvk8TrNd9sOOiMc+UtrrbEzwvCnotBu0lgI3+lE3uuX7N
spp4EkzAnsq4qr5lfpASsMS20n7CX6CFzAg5WlPqQCmj3NLcRVHMdZrxqNnXVWwM
tN+7s5LN2ktxcugqDRzN8PiFhJ+udoU9LQJFtcaybme29IuuBu1eaMe4Z8YqyHJR
5vQFzEOtiliZlc3M9wTMWU0CAwEAAQ==
-----END PUBLIC KEY-----"#;

    #[test]
    fn test_encrypt() {
        let key = key_from_rsa_pub(PUB_KEY).expect("Should parse this key");
        let out = crate::encrypt_with_public_key(key, b"foo_bar").expect("Should encrypt");
        println!("{}", BASE64_STANDARD.encode(out));
    }

    #[test]
    #[cfg(not(debug_assertions))] // this takes a long time to run in debug mode, so only do in release mode
    fn test_create_private_key() {
        use rsa::{pkcs1::EncodeRsaPublicKey, pkcs8::LineEnding, RsaPrivateKey};
        let mut rng = rand::thread_rng();
        let rsa_key = RsaPrivateKey::new(&mut rng, 4096).expect("Should create an RSA private key");
        let pub_key = rsa_key.to_public_key();
        let pub_key = pub_key
            .to_pkcs1_pem(LineEnding::LF)
            .expect("Should make key a pem");

        assert!(
            pub_key.len() > 50,
            "Should get a reasonably long public key"
        );
    }

    use std::io::Cursor;

    use crate::{_aes_decrypt as aes_decrypt, aes_encrypt, key_from_rsa_pub, Args, SymKey, IV};
    #[test]
    fn test_round_trip() {
        let key: SymKey = BASE64_STANDARD
            .decode(KEY)
            .expect("Can't get key")
            .try_into()
            .expect("Can copy to key");
        let iv: IV = BASE64_STANDARD
            .decode(TEST_IV)
            .expect("Can't decode IV")
            .try_into()
            .expect("Can't make IV");
        let plain = BASE64_STANDARD
            .decode(PLAIN)
            .expect("Didn't get plain message");
        let mut encrypted = vec![0u8; plain.len() + 50];
        let (len, _) = aes_encrypt(
            key,
            Some(iv),
            &mut plain.as_slice(),
            &mut encrypted.as_mut_slice(),
        )
        .expect("can encrypt");
        // encrypted.shrink_to(len);
        let encrypted_str = BASE64_STANDARD.encode(&encrypted[0..len]);
        // assert_eq!(encrypted_str.len(), ENC.len());
        assert_eq!(encrypted_str, ENC);

        let mut decrypted = Cursor::new(vec![]);
        let mut encrypted_vec = vec![0u8; len];
        encrypted_vec.clone_from_slice(&encrypted[0..len]);
        aes_decrypt(key, iv, &mut Cursor::new(encrypted_vec), &mut decrypted).expect("to decrypt");
        let decrypted_base64 = BASE64_STANDARD.encode(decrypted.into_inner());

        assert_eq!(decrypted_base64, PLAIN);

        let mut decrypted = Cursor::new(vec![]);
        let mut encrypted_vec = vec![0u8; len];
        encrypted_vec.clone_from_slice(&encrypted[0..len]);
        encrypted_vec[721] += 1; // make sure the hash checking works
        aes_decrypt(key, iv, &mut Cursor::new(encrypted_vec), &mut decrypted)
            .expect_err("should have failed");
    }

    #[test]
    fn test_jwt() {
        let uuid = Args::jwt_to_uuid(JWT).expect("Can find UUID");
        assert_eq!("7f77279d-9077-42a1-b581-1fbd13f4a41d", uuid);
    }

    const KEY: &str = "QklonvToEuXPyzj8LE3oK4iMF1C7AoZMt97k4rTgCFY=";
    const TEST_IV: &str = "ecYntCPeFvvTh+sX";
    const PLAIN: &str = "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";
    const ENC: &str = "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";

    const JWT: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1dWlkIjoiN2Y3NzI3OWQtOTA3Ny00MmExLWI1ODEtMWZiZDEzZjRhNDFkIiwiZXhwIjoxNzIxMzUxMjcwfQ.dmF1bHQ6djE6ZTRKd04vaXJmUHV6cUsrczI2c0hBNGlXUVFSclBmbjBoZ2kzTmM3dVdxczVidFM2QW1hbWdtV1AyMXp3dy9xQ1RjWndxano5RTllVUNldittaFphUmtkWFVRVnVBaHlOREVtZWVhaGpUakx6N0NYaHY3L3pWczhSTG9wbi80VTh6UWxzQUdDUUR2eUZpQ3VSTTFyck9LaVY3OHZodFIxSzh3WTZqZWIxWnIrcXlSeG5wUHdleWQ1M3YxZFh3a3l3c3MxZVFsTGVaSklERnUvQ2FRRjhUeFJoV1J0bzBoTVhBSU1ZY2Q0blB0T0pSejJkZFFEYUVLSkkvWWsyL3N6Q21WN0lnOXRmeVRxOVVUdFd0V1dXdDIxdkZzdXgreFd6b01WMWJkUHhCUVVVR1Q2L3MzZURJeVczQitTY0Ira0ZlVEsvemh5dmZsODR1N2laMDV1SzNybFlNL2kxK0pZZDZ0UGRmcU9LYmJVT0pqaWpzWkMxK24wZEhqclZ4NVpMbGJDT05EZmF1d0JRWEpWdDY3S3U5MWxJS29KVTJkdDFKQUVkVm5iU2JvSk51bVlVVllCanZjNmluK3dwREp2S0dDOU8yUExFeC9PMlltU0EwREw5L2RDa3UvcXo2eUxyd1lzMkVpM05qVGhSeHFMUDA2RmNPK0VTQ09BTmJRRjY4RzllQTI2L0FSUE1iaS9PQS9EQ2dpclRQZjliM1RBVEJuSmVMaTEzY2NZblZIV3dzZDFTYTZSMzNzUDZ6WG4rNGY4b1I4OGtrM1F1ckRRTUhKY2Ywa04vb3JSc2NsRi9rVytxWGdsTGRZOVpGQkcvMDAySW13TG5VdXk0Wm93bEFZVDNQK3N3THNUMFRGTXpvK0FJdlo2TkdJbWgxdThpckZzYkt6Z1JwTDA9";
}
