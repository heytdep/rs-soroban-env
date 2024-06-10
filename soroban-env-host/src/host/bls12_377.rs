//! Pairings for Bls12-377 elliptic curves.
#![allow(dead_code)]

use std::ops::MulAssign;

use ark_bls12_377::{Bls12_377, Fq12Parameters, G1Affine, G2Affine};
use ark_ec::PairingEngine;
use ark_ff::{Fp12ParamsWrapper, Fp384, QuadExtField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use soroban_env_common::BytesObject;
use crate::xdr::{ScError, ScErrorCode, ScBytes};
//use ark_ff::bytes::ToBytes;
//use ark_serialize::*;

use crate::{Host, HostError};

// note: the point is on the curve, thus not at infinity. But I would like to be fact-checked on this.
const INFINITY: bool = false;

pub(crate) struct CurveWrapper {
    p: G1Affine,
    q: G2Affine
}

fn to_host_error(_: ()) -> HostError {
    crate::Error::from_scerror(ScError::Crypto(ScErrorCode::InvalidInput)).into()
}

impl CurveWrapper {
    fn to_affine_g1(x: Vec<u8>, y: Vec<u8>) -> Result<G1Affine, HostError> {
        let x = Fp384::deserialize(x.as_slice()).map_err(|_| to_host_error(()))?;
        let y = Fp384::deserialize(y.as_slice()).map_err(|_| to_host_error(()))?;
        Ok(G1Affine::new(x, y, INFINITY))
    }

    fn to_affine_g2(x_0: Vec<u8>, y_0: Vec<u8>, x_1: Vec<u8>, y_1: Vec<u8>) -> Result<G2Affine, HostError> {
        let x_0 = Fp384::deserialize(x_0.as_slice()).map_err(|_| to_host_error(()))?;
        let x_1 = Fp384::deserialize(x_1.as_slice()).map_err(|_| to_host_error(()))?;
        let y_0 = Fp384::deserialize(y_0.as_slice()).map_err(|_| to_host_error(()))?;
        let y_1 = Fp384::deserialize(y_1.as_slice()).map_err(|_| to_host_error(()))?;
        let x = QuadExtField::new(x_0, y_0);
        let y = QuadExtField::new(x_1, y_1);
        Ok(G2Affine::new(x, y, INFINITY))
    }

    // Note: for safety it might be better to express arguments with their own structure
    // to avoid confusion in the future.
    fn build(p: [Vec<u8>; 2], q: [Vec<u8>; 4]) -> Result<Self, HostError> {
        let p = Self::to_affine_g1(p[0], p[1])?;
        let q = Self::to_affine_g2(q[0], q[1], q[2], q[3])?;

        Ok(Self {
            p,
            q
        })
    }

    fn pair(&self) -> QuadExtField<Fp12ParamsWrapper<Fq12Parameters>> {
        Bls12_377::pairing(self.p, self.q)
    }
}

impl Host {
    pub(crate) fn field_from_bytesobj_input(&self, fp: BytesObject) -> Result<Vec<u8>, HostError> {
        self.visit_obj(fp, |bytes: &ScBytes| {
            Ok(bytes.0.to_vec())
        })
    }
    
    pub(crate) fn inner_bls12_377_pairing(&self, p: [Vec<u8>; 2], q: [Vec<u8>; 4]) -> Result<Vec<u8>, HostError> {
        let wrapper = CurveWrapper::build(p, q)?;
        let result = wrapper.pair();
        let mut writer = Vec::new();
        result.serialize(&mut writer).map_err(|_| to_host_error(()))?;
        
        Ok(writer)
    }

    pub(crate) fn inner_quad_ext_fields_mul(&self, a: Vec<u8>, b: Vec<u8>) -> Result<Vec<u8>, HostError> {
        let mut lhs: QuadExtField<Fp12ParamsWrapper<Fq12Parameters>> = QuadExtField::deserialize(a.as_slice()).map_err(|_| to_host_error(()))?;
        let rhs: QuadExtField<Fp12ParamsWrapper<Fq12Parameters>> = QuadExtField::deserialize(b.as_slice()).map_err(|_| to_host_error(()))?;
        lhs.mul_assign(rhs);

        let mut writer = Vec::new();
        lhs.serialize(&mut writer).map_err(|_| to_host_error(()))?;

        Ok(writer)
    }
}
