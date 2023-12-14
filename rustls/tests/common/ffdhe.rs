use rustls::{
    crypto::{
        self, ActiveKeyExchange, CipherSuiteCommon, CryptoProvider, KeyExchangeAlgorithm,
        SupportedKxGroup,
    },
    CipherSuite, NamedGroup, SupportedCipherSuite, Tls12CipherSuite,
};

use super::*;

static TLS12_DHE_RSA_WITH_AES_128_GCM_SHA256: Tls12CipherSuite =
    match &provider::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 {
        SupportedCipherSuite::Tls12(provider) => Tls12CipherSuite {
            common: CipherSuiteCommon {
                suite: CipherSuite::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
                hash_provider: provider.common.hash_provider,
                confidentiality_limit: 1 << 23,
                integrity_limit: 1 << 52,
            },
            kx: KeyExchangeAlgorithm::DHE,
            sign: provider.sign,
            aead_alg: provider.aead_alg,
            prf_provider: provider.prf_provider,
        },
        _ => unreachable!(),
    };

/// The (test-only) TLS1.2 ciphersuite TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
pub static TLS_DHE_RSA_WITH_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&TLS12_DHE_RSA_WITH_AES_128_GCM_SHA256);

static FFDHE_CIPHER_SUITES: &[rustls::SupportedCipherSuite] = &[
    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
    provider::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
];

#[derive(Debug)]
pub struct FfdheKxGroup(pub NamedGroup);

impl SupportedKxGroup for FfdheKxGroup {
    fn start(&self) -> Result<Box<dyn crypto::ActiveKeyExchange>, rustls::Error> {
        let mut x = vec![0; 64];
        ffdhe_provider()
            .secure_random
            .fill(&mut x)?;
        let group = rustls::ffdhe_groups::FfdheGroup::from_named_group(self.0).unwrap();
        let x = num_bigint::BigUint::from_bytes_be(&x);
        let p = num_bigint::BigUint::from_bytes_be(group.p);
        let g = num_bigint::BigUint::from_bytes_be(group.g);
        let x_pub = g.modpow(&x, &p);
        Ok(Box::new(ActiveFfdheKx {
            x_pub: x_pub.to_bytes_be(),
            x,
            p,
            group: self.0,
        }))
    }

    fn name(&self) -> rustls::NamedGroup {
        self.0
    }
}

struct ActiveFfdheKx {
    x_pub: Vec<u8>,
    x: num_bigint::BigUint,
    p: num_bigint::BigUint,
    group: NamedGroup,
}

impl ActiveKeyExchange for ActiveFfdheKx {
    fn complete(
        self: Box<Self>,
        peer_pub_key: &[u8],
    ) -> Result<crypto::SharedSecret, rustls::Error> {
        let peer_pub = num_bigint::BigUint::from_bytes_be(peer_pub_key);
        let secret = peer_pub.modpow(&self.x, &self.p);

        Ok(crypto::SharedSecret::from(&secret.to_bytes_be()[..]))
    }

    fn pub_key(&self) -> &[u8] {
        &self.x_pub
    }

    fn group(&self) -> rustls::NamedGroup {
        self.group
    }
}

pub const FFDHE2048_KX_GROUP: FfdheKxGroup = FfdheKxGroup(NamedGroup::FFDHE2048);
static FFDHE_KX_GROUPS: &[&dyn rustls::crypto::SupportedKxGroup] = &[&FFDHE2048_KX_GROUP];

pub fn ffdhe_provider() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: FFDHE_CIPHER_SUITES.to_vec(),
        kx_groups: FFDHE_KX_GROUPS.to_vec(),
        ..provider::default_provider()
    }
}
