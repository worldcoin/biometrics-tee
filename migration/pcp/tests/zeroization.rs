use orb_pcp_defs::v1;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[test]
fn biometric_messages_zeroize_on_drop() {
    // Keep the dependency pin from silently losing the upstream zeroization contract.
    fn assert_zeroizes<T: Zeroize + ZeroizeOnDrop>() {
        assert!(std::mem::needs_drop::<T>());
    }

    assert_zeroizes::<v1::IrisCodes>();
    assert_zeroizes::<v1::IrisCodeShares>();
    assert_zeroizes::<v1::DiIrisEmbeddingV1>();
    assert_zeroizes::<v1::DiIrisEmbeddingShareV1>();
    assert_zeroizes::<v1::FaceEmbedding>();
}
