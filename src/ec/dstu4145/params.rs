use untrusted::Reader;
use signature::VerificationAlgorithm;
use error;
use private;

use super::gf2m;
use super::curve;
use super::dstu_params;
use super::dstu4145::verify_helper;
use digest::gost34311;

use untrusted;

pub struct DSTUParameters {}

macro_rules! oid {
    ( $first:expr, $second:expr, $( $tail:expr ),* ) =>
    (
        [(40 * $first) + $second, $( $tail ),*]
    )
}

struct DSTUPubKey {
    curve: curve::Curve,
    point: curve::Point,
}

fn parse_sig(data: untrusted::Input) -> Result<(gf2m::Field, gf2m::Field), error::Unspecified> {
    let len = data.len() - 2;
    let half = len / 2;
    let r = gf2m::from_bytes_le(
        &data.as_slice_less_safe()[2..half+2]
    );
    let s = gf2m::from_bytes_le(
        &data.as_slice_less_safe()[2+half..]
    );

    return Ok((r, s));
}

impl DSTUPubKey {
    pub fn read(data: untrusted::Input) -> Result<DSTUPubKey, error::Unspecified> {
        let mut reader = Reader::new(data);
        let point_type = try!(reader.read_byte());
        if point_type != 0x04 {
            return Err(error::Unspecified);
        }

        let point_len = try!(reader.read_byte()) as usize;
        let curve = match point_len {
            54=>  dstu_params::curve_431(),
            33=>  dstu_params::curve_257(),
            _=> return Err(error::Unspecified),
        };

        if point_len + 2 != data.len() {
            return Err(error::Unspecified);
        }

        let compressed = gf2m::from_bytes_le(
            &data.as_slice_less_safe()[2..]
        );
        return Ok(DSTUPubKey {
            point: curve::point_expand(&compressed, &curve),
            curve: curve,
        });
    }

    pub fn verify(&self, msg: untrusted::Input, signature: untrusted::Input) -> Result<(), error::Unspecified> {
        let (r, s) = try!(parse_sig(signature));

        let to_be_signed = gost34311::digest(msg.as_slice_less_safe());
        let to_be_signed = gf2m::from_bytes_le(&to_be_signed);

        let ok = verify_helper(&self.point, &s, &r, &to_be_signed, &self.curve);
        if ok {
            return Ok(());
        }
        return Err(error::Unspecified);
    }
}

impl VerificationAlgorithm for DSTUParameters {
    fn verify(&self, public_key: untrusted::Input, msg: untrusted::Input,
              signature: untrusted::Input) -> Result<(), error::Unspecified> {
        let pubkey = try!(DSTUPubKey::read(public_key));
        return pubkey.verify(msg, signature);
    }
}

impl private::Private for DSTUParameters {}

/// DSTU4145 Signature with Gost hashsum
pub static SIGNATURE_DSTU4145_GOST34311_95: DSTUParameters = DSTUParameters {};
