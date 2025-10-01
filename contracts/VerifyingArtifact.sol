// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

contract Halo2VerifyingArtifact {
    constructor() {
        assembly {
            mstore(
                0x0000,
                0x0e6a484c06b99faa7bb0b2048167f3b881501f9bbfce84011df0d1b29355ea76
            ) // vk_digest
            mstore(
                0x0020,
                0x0000000000000000000000000000000000000000000000000000000000000480
            ) // fsm
            mstore(
                0x0040,
                0x000000000000000000000000000000000000000000000000000000000000000a
            ) // num_instances
            mstore(
                0x0060,
                0x0000000000000000000000000000000000000000000000000000000000000011
            ) // num_evals
            mstore(
                0x0080,
                0x0000000000000000000000000000000000000000000000000000000000000000
            ) // challenges_offset
            mstore(
                0x00a0,
                0x000000000000000000000000000000000000000000000000000000000000000a
            ) // k
            mstore(
                0x00c0,
                0x3058355f447953c1ade231a513e0f80710e9db4e679b02351f90fd168b040001
            ) // n_inv
            mstore(
                0x00e0,
                0x2ad9021ed07c42ab19f77c5cf2cbd2deb135ea330f1b1573bd08d99309c4bb7d
            ) // omega
            mstore(
                0x0100,
                0x0ae3c95fc03c0a5f2de8a8f46c03ccdfdfed2bb98c9e4ae0b10b15eda4e3b1e3
            ) // omega_inv
            mstore(
                0x0120,
                0x15f79db9c39181bc3e31c83f9291da76eedf1b23c410add7e9098464aaa4fb26
            ) // omega_inv_to_l
            mstore(
                0x0140,
                0x0000000000000000000000000000000000000000000000000000000000000000
            ) // has_accumulator
            mstore(
                0x0160,
                0x0000000000000000000000000000000000000000000000000000000000000000
            ) // acc_offset
            mstore(
                0x0180,
                0x0000000000000000000000000000000000000000000000000000000000000000
            ) // num_acc_limbs
            mstore(
                0x01a0,
                0x0000000000000000000000000000000000000000000000000000000000000000
            ) // num_acc_limb_bits
            mstore(
                0x01c0,
                0x0000000000000000000000000000000000000000000000000000000000000001
            ) // g1_x
            mstore(
                0x01e0,
                0x0000000000000000000000000000000000000000000000000000000000000002
            ) // g1_y
            mstore(
                0x0200,
                0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2
            ) // g2_x_1
            mstore(
                0x0220,
                0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed
            ) // g2_x_2
            mstore(
                0x0240,
                0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b
            ) // g2_y_1
            mstore(
                0x0260,
                0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa
            ) // g2_y_2
            mstore(
                0x0280,
                0x1c0cbcefcad6a7edee142a147decbca82bea4bb9d58777175ee80e4e4be6442e
            ) // neg_s_g2_x_1
            mstore(
                0x02a0,
                0x2e248c50c4ccb992cb7a73e2303254fec4c687ed45cf58bc30b8e30fd54c537c
            ) // neg_s_g2_x_2
            mstore(
                0x02c0,
                0x0867bd916313ca877ac2297fd9f6c57b2132ebe814ba5c1db87a98f8c50fcab6
            ) // neg_s_g2_y_1
            mstore(
                0x02e0,
                0x1a4f680e16aa5319974d1fe0c11b7d49d1308959f9ad589be5c477a726d9df91
            ) // neg_s_g2_y_2
            mstore(
                0x0300,
                0x0000000000000000000000000000000000000000000000000000000000000284
            ) // last_quotient_x_cptr
            mstore(
                0x0320,
                0x0000000000000000000000000000000000000000000000000000000000000204
            ) // first_quotient_x_cptr
            mstore(
                0x0340,
                0x00000000000000000000000000000000000000000000000000000000000006e0
            ) // gate_computations_len_offset
            mstore(
                0x0360,
                0x0000000000000000000000000000000000000000000000000000000000000760
            ) // permutation_computations_len_offset
            mstore(
                0x0380,
                0x00000000000000000000000000000000000000000000000000000000000007c0
            ) // lookup_computations_len_offset
            mstore(
                0x03a0,
                0x00000000000000000000000000000000000000000000000000000000000007e0
            ) // pcs_computations_len_offset
            mstore(
                0x03c0,
                0x0000000000000000000000000000000000000000000000000000000000000a20
            ) // rescaling_computations_len_offset
            mstore(
                0x03e0,
                0x0000000000000000000000000000000000000000000000000000000000000006
            ) // num_neg_lagranges
            mstore(
                0x0400,
                0x0000000000000000000000000000000000000000000000000000000000000005
            ) // num_fixed_comms
            mstore(
                0x0420,
                0x000000000000000000000000000000000000000000000100c00100c00300c001
            ) // num_advices_user_challenges_0
            mstore(
                0x0440,
                0x0ced4068a620e4e0b4c6daa5ba488657a026bcbdb160301011b425b3eb51776a
            ) // fixed_comms[0].x
            mstore(
                0x0460,
                0x077e0661e0d47a64c6f9d82dfa2a6837698313606ca29d377548eb55a8a7047d
            ) // fixed_comms[0].y
            mstore(
                0x0480,
                0x01ddd0ee703cbb46d9ed8e66d0a341eb51cf8af53dd0ce0acba34deb7019df02
            ) // fixed_comms[1].x
            mstore(
                0x04a0,
                0x03b2d10e4f987a66f3e95c74a9dc324257f958df05637a4888bf30a1c1c031f7
            ) // fixed_comms[1].y
            mstore(
                0x04c0,
                0x2d3340acdd1780a47262633ae4d6b8dcb39a2c21725063552a3c789781aad103
            ) // fixed_comms[2].x
            mstore(
                0x04e0,
                0x1d0cb46cb88fea7c921be2697f0ed3c2f63fb7858a0e47389e372084142c050a
            ) // fixed_comms[2].y
            mstore(
                0x0500,
                0x2e75a50d6a6f6fa08318f07cbe3a01435dbcc3907751131a6422dca5209e9b9d
            ) // fixed_comms[3].x
            mstore(
                0x0520,
                0x110c5b8030e51a4d87066695accae358e3eecb43857c21124929e319f7e17903
            ) // fixed_comms[3].y
            mstore(
                0x0540,
                0x094fc2d0d4cfc93d44d3a5a2d3763338fea4174bcba05ac37d7a294c4322ed0e
            ) // fixed_comms[4].x
            mstore(
                0x0560,
                0x2831b7bcb4bd8c7d377539685320094cf83d9a6e3f36a257b8537a52e6ed04b8
            ) // fixed_comms[4].y
            mstore(
                0x0580,
                0x21d8fb2aeeac865693eaad80b49c84a70af3553b4d17ac2794b3f27d915ef8a2
            ) // permutation_comms[0].x
            mstore(
                0x05a0,
                0x1f81641885e8dbd83fb8091a6817d632b92a9f2c3687c34f3ede36718e2cf0f8
            ) // permutation_comms[0].y
            mstore(
                0x05c0,
                0x15c906670ed66c84df55c644a084d95c42760a54c82d78bbc36a94106bc3d2a6
            ) // permutation_comms[1].x
            mstore(
                0x05e0,
                0x1645f0f5d5a0452f1e4d6f212d4a6b0e07d41ff17ec88f175fc4454784cd4f4a
            ) // permutation_comms[1].y
            mstore(
                0x0600,
                0x1b81df845a3495d5c108eb0ead6d982e00c56b3c2f022c99e16716f3a1355646
            ) // permutation_comms[2].x
            mstore(
                0x0620,
                0x1d959a3d1e51396791165938224723d76ac4093bbaae10b3ad8be6990dda9203
            ) // permutation_comms[2].y
            mstore(
                0x0640,
                0x0000000000000000000000000000000000000000000000000000000000000020
            ) // gate_computations length
            mstore(
                0x0660,
                0x000364000b600b00020b400b200302e4000344000ae00ac00302c40003240003
            ) // packed_expression_word [0]
            mstore(
                0x0680,
                0x000c600c00020b400c40030ae00c20030384000be00b80020bc00ba003030400
            ) // packed_expression_word [1]
            mstore(
                0x06a0,
                0x0000000000000000000000000000000000000011600cc0020ca00c800203a400
            ) // packed_expression_word [2]
            mstore(
                0x06c0,
                0x0000000000000000000000000000000000000000000000000000000020002001
            ) // permutation_meta_data
            mstore(
                0x06e0,
                0x00000000000000000000000000000000040402e40003e402c400048404640444
            ) // permutation_data [0]
            mstore(
                0x0700,
                0x000000000000000000000000000000000000000000042403040004e404c404a4
            ) // permutation_data [1]
            mstore(
                0x0720,
                0x0000000000000000000000000000000000000000000000000000000000000000
            ) // meta_data of lookup_computations
            mstore(
                0x0740,
                0x000000000000000000000000000000000000000000000000000000000002c001
            ) // point_computations[0]
            mstore(
                0x0760,
                0x00000000000000000000000000000000000280000000000000000000000602a0
            ) // point_computations[1]
            mstore(
                0x0780,
                0x00000000000000000000000000000000000000000000000300010280034002e0
            ) // vanishing_computations[0]
            mstore(
                0x07a0,
                0x0000000000000000000000000000000000000000000000000000000000030340
            ) // vanishing_computations[1]
            mstore(
                0x07c0,
                0x00000000000000000000000000000000000000000000000000000000032002e0
            ) // vanishing_computations[2]
            mstore(
                0x07e0,
                0x0000000000000000000000000000000000000000000000000000000000000020
            ) // vanishing_computations[3]
            mstore(
                0x0800,
                0x00000000000000000000000000000000000000000000000000000000000002e0
            ) // vanishing_computations[4]
            mstore(
                0x0820,
                0x0000000000000000000000000000000000000000000000000000000002030101
            ) // coeff_computations[0]
            mstore(
                0x0840,
                0x0000000000000000000000000000000000000000000000000000000000200300
            ) // coeff_computations[1]
            mstore(
                0x0860,
                0x00000000000000000000000000000080006000400320030002e002c002a00280
            ) // coeff_computations[2]
            mstore(
                0x0880,
                0x000000000000000000000000000000000000000000c000a00320030002c002a0
            ) // coeff_computations[3]
            mstore(
                0x08a0,
                0x00000000000000000000000000000000000000000000000000000060036000e0
            ) // normalized_coeff_computations
            mstore(
                0x08c0,
                0x00000000000000000000000000000000000000000000000040602003c0038001
            ) // r_evals_computations[0]
            mstore(
                0x08e0,
                0x0000000000000000000000000000000000000002a403a40003c404240003c401
            ) // r_evals_computations[1]
            mstore(
                0x0900,
                0x0000000000000000000000000000000000000000000000000004640444048401
            ) // r_evals_computations[2]
            mstore(
                0x0920,
                0x00000000000000000000000000000000000000000000000000000004c404a401
            ) // r_evals_computations[3]
            mstore(
                0x0940,
                0x0000000000000000000000000000000000000000000004604004406004202001
            ) // coeff_sums_computations[0]
            mstore(
                0x0960,
                0x0000000000000000000000000000000000000000000000000000040004200060
            ) // r_eval_computations
            mstore(
                0x0980,
                0x00000000000000000000000000000000202020054405240340050404e4038001
            ) // pairing_input_computations[0]
            mstore(
                0x09a0,
                0x000000000000000000000000000000440104000104a006a00000010201e401c4
            ) // pairing_input_computations[1]
            mstore(
                0x09c0,
                0x0000000000000000000000000000000000000000000000000000000001640144
            ) // pairing_input_computations[2]
            mstore(
                0x09e0,
                0x0000000000000000000000000000000000000000000000000000000001a40184
            ) // pairing_input_computations[3]
            mstore(
                0x0a00,
                0x0000000000000000000000000000000000000000000000000000000140001201
            ) // rescaling_computations[0]
            return(0, 0x0a20)
        }
    }
}
