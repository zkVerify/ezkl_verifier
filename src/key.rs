use ark_bn254_ext::CurveHooks;

use crate::{Fr, G1, G2, U256};

#[derive(PartialEq, Eq, Debug)]
pub struct PreparedVerificationKey<H: CurveHooks> {
    pub digest: U256,
    pub num_instances: usize, // number of PIs (3 in the sample)
    pub k: u32,               // domain k
    pub n_inv: Fr,            // inverse of 2^k modulo r
    pub omega: Fr,
    pub omega_inv: Fr,
    pub omega_inv_to_l: Fr, // What is l
    pub has_accumulator: bool,
    pub acc_offset: usize,
    pub num_acc_limbs: usize,
    pub num_acc_limb_bits: usize,
    // TODO: Update the valid_proof in should.rs to remove the SRS fields.
    pub neg_s_g2: G2<H>, // Negation of s_g2

    // mstore(0x07c0, 0x186282957db913abd99f91db59fe69922e95040603ef44c0bd7aa3adeef8f5ac) // neg_s_g2_x_1
    // mstore(0x07e0, 0x17944351223333f260ddc3b4af45191b856689eda9eab5cbcddbbe570ce860d2) // neg_s_g2_x_2
    // mstore(0x0800, 0x06d971ff4a7467c3ec596ed6efc674572e32fd6f52b721f97e35b0b3d3546753) // neg_s_g2_y_1
    // mstore(0x0820, 0x06ecdb9f9567f59ed2eee36e1e1d58797fd13cc97fafc2910f5e8a12f202fa9a) // neg_s_g2_y_2
    pub fixed_comms: Vec<G1<H>>,

    // These seem to vary but not based on k:
    // Maybe based on the number of fixed columns in the meta?
    // mstore(0x0840, 0x2bd93c0d692b335f71e0d03dee02c1442ab7e9f96a43409a9b1f0a4d6fff690b) // fixed_comms[0].x
    // mstore(0x0860, 0x1342e7b31456b04f76b173b83c3db23297dd04ad43aa1db6ac50c7b3ac3791cd) // fixed_comms[0].y
    // mstore(0x0880, 0x26b6099cbe3fffa074e8a76fd31d5e10aabd6b396406b27ef018db6c759c349b) // fixed_comms[1].x
    // mstore(0x08a0, 0x22f345155662caab46494b6eed2d7573aa44f000f5a3759899f4bc0847e13e01) // fixed_comms[1].y
    // mstore(0x08c0, 0x052669693850a7b66ce748a9357cea4af3c120d45adc96a3f51c21dce2006e09) // fixed_comms[2].x
    // mstore(0x08e0, 0x284ec1e9db21d06f5557731d473e4699dc02210cc9a7bd08ffab5f93e861715b) // fixed_comms[2].y
    // mstore(0x0900, 0x02f29b2d7b17de09a06be3ccba7370d4610d4d468345411ed121dfb3be0c88b9) // fixed_comms[3].x
    // mstore(0x0920, 0x09e16cd5997d09e56cbe0603cab42fb471b6a35a3dec71b52990f97645b1be3e) // fixed_comms[3].y
    // mstore(0x0940, 0x13bce136eb7fad9fb32615163b0c799c25d07b2ef87aaced9fa33ad185760dec) // fixed_comms[4].x
    // mstore(0x0960, 0x02ed884305ec8bfb2edcd14210d8cf8900f549c79efe0b7f90fcdb82b493c5ab) // fixed_comms[4].y
    // mstore(0x0980, 0x14eda040a7c41565bb3558d3382d695cc94af002861aa147eca8a11fa2750a50) // fixed_comms[5].x
    // mstore(0x09a0, 0x136b1743d764af07be59985759483c7920b5451f25b3b27c9944eb6faa24c6b1) // fixed_comms[5].y
    // mstore(0x09c0, 0x264beb6f2563ff0fdd25493d495c20f2a58300f507acb41b4c9253b8c240ccc3) // fixed_comms[6].x
    // mstore(0x09e0, 0x22a5c1012fd6b8a37e8ac9621127aa103ac2e884d20a5c6d4e2bf3d16e796595) // fixed_comms[6].y
    // mstore(0x0a00, 0x258c86e42ea8c545494c8320766ea7d8d393b8b7b91879b4ec8356bfc9d6f69f) // fixed_comms[7].x
    // mstore(0x0a20, 0x2b7f67400de4d1247937fb22c8ed31b821aa6cc76c88c1cd98181406c1b1a2e9) // fixed_comms[7].y
    // mstore(0x0a40, 0x15895fd3a455775a130847914d22585976a60c3f619861cc8f2cae557f92d1d8) // fixed_comms[8].x
    // mstore(0x0a60, 0x02c986df47f58ade46d77ea46863aa4c946f08c7822c3ec219459a9015b3cb45) // fixed_comms[8].y
    // mstore(0x0a80, 0x2834690b7ea06e03b517864d6f5f444bfe42ee9997c84b5169a0d17bf21b4c89) // fixed_comms[9].x
    // mstore(0x0aa0, 0x1548dbd7b66595b3e276a4799e87a39dca32da68c9804d184815ede8f74ce413) // fixed_comms[9].y
    // mstore(0x0ac0, 0x1f48113f826b9513b2f272efadc2f9e6f7f7252c801e14839124c385e15b5bb2) // fixed_comms[10].x
    // mstore(0x0ae0, 0x17c3cea76b12a45679cda11f0f3fb075ce90c28cf206ed39dcf505622492a330) // fixed_comms[10].y
    // mstore(0x0b00, 0x209a4f4b8b251c332a984b328a29575c887808ede0a2bfb39624825df8c05bf8) // fixed_comms[11].x
    // mstore(0x0b20, 0x2e6d693478cec05a9750a0298793210f8a811ce933c53b849fb78c01ecd099b4) // fixed_comms[11].y
    // mstore(0x0b40, 0x29c019ff3782997e6a58a773e5ef451127088cdb864344de3fb5e6255d41b46d) // fixed_comms[12].x
    // mstore(0x0b60, 0x2e5b65a67f0463a8fb48b5064c6c0c44eb059d2c0a6ed6476269c907dc2aa4b2) // fixed_comms[12].y

    // These seem to vary but not based on k:
    // Maybe based on the number of advice columns in the meta?
    pub permutation_comms: Vec<G1<H>>,
    // mstore(0x0b80, 0x0da36e183faa09b64ba2d6e08308880ff4c1b115c8d82339ffca370da4c038a6) // permutation_comms[0].x
    // mstore(0x0ba0, 0x285b18bb4df8f1531a0a462e8474090d07584600b6f842e3654ac719927a2fa8) // permutation_comms[0].y
    // mstore(0x0bc0, 0x0168a9355984706f7f3d16aab006feeb7eaa0ab79c32015c938ca32edee0a2bc) // permutation_comms[1].x
    // mstore(0x0be0, 0x20e947ba83144b6f6e5b3b547f96da54f2d69651cd44ea959eecea4535152a7a) // permutation_comms[1].y
    // mstore(0x0c00, 0x27fb8a99641e91f06b52d5139419a8c5f1e6fc28b3d9e6e3bd12d0df6acbb4ac) // permutation_comms[2].x
    // mstore(0x0c20, 0x24acee1919def9185ce62cdff58d70fa7b0937bdc30fc355fd3baf3f62c78bd4) // permutation_comms[2].y
    // mstore(0x0c40, 0x2048cff4dff4b6c3c219e91542150d8628dd12a41f02ae57a8777c2724861fc4) // permutation_comms[3].x
    // mstore(0x0c60, 0x04ca4e5b754da691a63e720117c3f8fb0a10fc2ad5913e846badf94f5fdced04) // permutation_comms[3].y
    // mstore(0x0c80, 0x0faa7976ae20fc176b94171b7beac85cf973bdfc5e6199d1663a24c14ae49a9e) // permutation_comms[4].x
    // mstore(0x0ca0, 0x10a4fc53fe718685de70ebf2b042ecef741f719fc8ce2cc5f4b479091c7c1241) // permutation_comms[4].y
    // mstore(0x0cc0, 0x147df0d7fb214cefcfa5348c8b9a8d369c17f78dc2564654c302af86bd74e2f3) // permutation_comms[5].x
    // mstore(0x0ce0, 0x29749f284530f865c0e0905adcd067f0c8d0dd452b7c8686ee2c0a667109b6de) // permutation_comms[5].y
    // mstore(0x0d00, 0x2cbe3d4342c10cac39692921cf7a78e724086968c335679a10638f2c927e0755) // permutation_comms[6].x
    // mstore(0x0d20, 0x04875037fcaf29245d662b63c36800f26efa2a004e1ef33804616c9f11dc61db) // permutation_comms[6].y
    // mstore(0x0d40, 0x1a0f4c6787b2b09669904a1f937090a95b67e709c0695272e7197d3148268069) // permutation_comms[7].x
    // mstore(0x0d60, 0x1871031b1e834b4b7bc00dcb1dc4f1bd2092fc49dd164cde758b215a295f78e5) // permutation_comms[7].y
}

// #[derive(PartialEq, Eq, Debug)]
// pub struct VerificationKey<H: CurveHooks> {}
