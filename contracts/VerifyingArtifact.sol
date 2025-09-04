// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

contract Halo2VerifyingArtifact {
    constructor() {
        assembly {
            mstore(
                0x0000,
                0x1fe0d513504f581f31f32119eab70b52f80721e526f4cecc64fa31eec3f26583
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
                0x02207a8aa427312328edb5d388472c92de8e31879da4f00d409a5e63098f5aa2
            ) // neg_s_g2_x_1
            mstore(
                0x02a0,
                0x11ef39cf7bc5fd28860d0da574adead1b57327a7b55035d41bd97e1a1073af53
            ) // neg_s_g2_x_2
            mstore(
                0x02c0,
                0x29de290723c5a7f6950ed18a0aa49f987c33c77462be032e0611537e790d6a83
            ) // neg_s_g2_y_1
            mstore(
                0x02e0,
                0x06ca314546e1010e26890124622568cf717963a1b982b90ad08106c8ac98a868
            ) // neg_s_g2_y_2

            mstore(
                0x0300,
                0x0000000000000000000000000000000000000000000000000000000000000284
            ) // last_quotient_x_cptr
            mstore(
                0x0320,
                0x0000000000000000000000000000000000000000000000000000000000000204
            ) // first_quotient_x_cptr

            /* last_quotient_x_cptr - first_quotient_x_cptr = 0x80 ==> 4 EVM words (or, 2 points) in the calldata */

            mstore(
                0x0340,
                0x00000000000000000000000000000000000000000000000000000000000006c0
            ) // gate_computations_len_offset

            /*  permutation_computations_len_offset - gate_computations_len_offset = 0x80
             *  ==> 4 EVM words between "gate_computations length" and "permutation_meta_data"
             */

            mstore(
                0x0360,
                0x0000000000000000000000000000000000000000000000000000000000000740
            ) // permutation_computations_len_offset

            /*  lookup_computations_len_offset - permutation_computations_len_offset = 0x60
             *  ==> 3 EVM words between "permutation_meta_data" and "meta_data of lookup_computations"
             */

            mstore(
                0x0380,
                0x00000000000000000000000000000000000000000000000000000000000007a0
            ) // lookup_computations_len_offset

            /*  pcs_computations_len_offset - lookup_computations_len_offset = 0x20
             *  ==> 1 EVM word for "meta_data of lookup_computations"
             */

            mstore(
                0x03a0,
                0x00000000000000000000000000000000000000000000000000000000000007c0
            ) // pcs_computations_len_offset

            /*  rescaling_computations_len_offset - pcs_computations_len_offset = 0x2c0
             *  ==> 22 EVM words between "point_computations[0]" and "rescaling_computations[0]"
             * Q: How do we distinguish between "subsections"?
             */

            mstore(
                0x03c0,
                0x0000000000000000000000000000000000000000000000000000000000000a80
            ) // rescaling_computations_len_offset

            mstore(
                0x03e0,
                0x0000000000000000000000000000000000000000000000000000000000000006
            ) // num_neg_lagranges
            mstore(
                0x0400,
                0x000000000000000000000000000000000000000000000100c00100c00300c001
            ) // num_advices_user_challenges_0
            mstore(
                0x0420,
                0x0dd48bb13a012eadd60ba8b677ad95b9b06b987159b0ef1a0d27f950a2d37864
            ) // fixed_comms[0].x
            mstore(
                0x0440,
                0x11dabb9b32f52158d0a3dadc8c19554c8157e71513c5c8fbaa67e601bba3661b
            ) // fixed_comms[0].y
            mstore(
                0x0460,
                0x1c8ff63c28eafd904ee172ebfb85c01aa4dd00fcbdaaeb23d24a3b702fcab136
            ) // fixed_comms[1].x
            mstore(
                0x0480,
                0x074280c836f4ac235bc166a079625d375ac6f58a3eb02ac80b59d4eac287da14
            ) // fixed_comms[1].y
            mstore(
                0x04a0,
                0x14b05245c506241dc5c81d6792f9024efa03b6ff9c15afd0d596b25d21b81af8
            ) // fixed_comms[2].x
            mstore(
                0x04c0,
                0x02b75ec04cb27287363ee6beef8ea465262e0ff0cb43ffd61fd9f7d71573b59c
            ) // fixed_comms[2].y
            mstore(
                0x04e0,
                0x052babdbc146d41c6dffae9c801fd8abe308aa42f8eb704217d17f3ff0e9da25
            ) // fixed_comms[3].x
            mstore(
                0x0500,
                0x2e829c182b388c350f33c6b22abe42f3d2ac556430e44d6b580c98ef7bd98add
            ) // fixed_comms[3].y
            mstore(
                0x0520,
                0x1185f6d3acf9f813b4f33e4606b2bfd72337fbe670c59874cec1e1a3956060f6
            ) // fixed_comms[4].x
            mstore(
                0x0540,
                0x0c52247d55755399fd79ec33251d61f0b636136e51f5aa1e0c113c0aafb76709
            ) // fixed_comms[4].y
            mstore(
                0x0560,
                0x0632430459f54bfc761c358daaa033da15473825561ee4892f0bdf9ba13f4d02
            ) // permutation_comms[0].x
            mstore(
                0x0580,
                0x03e32dd37539ee93196856e97873802fc28a51608a37c51f808b37794bda6d54
            ) // permutation_comms[0].y
            mstore(
                0x05a0,
                0x2d6dc6272191731c7abd7583cfebab83323233647ee355f316df5fe58aea54a5
            ) // permutation_comms[1].x
            mstore(
                0x05c0,
                0x1f77bb288fd75f97c29cf16ae2e56e0244a7cbee292aa2af32d005fc8adc5980
            ) // permutation_comms[1].y
            mstore(
                0x05e0,
                0x1fee29c60d1c550364f1292ba60fc8482d853179f627a9bc0c3e29c44fd8c53e
            ) // permutation_comms[2].x
            mstore(
                0x0600,
                0x16b54867acbad5c77de4624a271ca745bce2d79cf6d1a63db427869a7ac81da5
            ) // permutation_comms[2].y
            mstore(
                0x0620,
                0x0000000000000000000000000000000000000000000000000000000000000020
            ) // gate_computations length
            mstore(
                0x0640,
                0x000364000b400ae0020b200b000302e4000344000ac00aa00302c40003240003
            ) // packed_expression_word [0]
            mstore(
                0x0660,
                0x000c400be0020b200c20030ac00c00030384000bc00b60020ba00b8003030400
            ) // packed_expression_word [1]
            mstore(
                0x0680,
                0x0000000000000000000000000000000000000011400ca0020c800c600203a400
            ) // packed_expression_word [2]
            mstore(
                0x06a0,
                0x0000000000000000000000000000000000000000000000000000000020002001
            ) // permutation_meta_data
            mstore(
                0x06c0,
                0x00000000000000000000000000000000040402e40003e402c400048404640444
            ) // permutation_data [0]
            mstore(
                0x06e0,
                0x000000000000000000000000000000000000000000042403040004e404c404a4
            ) // permutation_data [1]
            mstore(
                0x0700,
                0x0000000000000000000000000000000000000000000000000000000000000000
            ) // meta_data of lookup_computations
            mstore(
                0x0720,
                0x000000000000000000000000000000000000000000000000000000000002c001
            ) // point_computations[0]
            mstore(
                0x0740,
                0x00000000000000000000000000000000000280000000000000000000000602a0
            ) // point_computations[1]
            mstore(
                0x0760,
                0x00000000000000000000000000000000000000000000000300010280034002e0
            ) // vanishing_computations[0]
            mstore(
                0x0780,
                0x0000000000000000000000000000000000000000000000000000000000030340
            ) // vanishing_computations[1]
            mstore(
                0x07a0,
                0x00000000000000000000000000000000000000000000000000000000032002e0
            ) // vanishing_computations[2]
            mstore(
                0x07c0,
                0x0000000000000000000000000000000000000000000000000000000000000020
            ) // vanishing_computations[3]
            mstore(
                0x07e0,
                0x00000000000000000000000000000000000000000000000000000000000002e0
            ) // vanishing_computations[4]
            mstore(
                0x0800,
                0x0000000000000000000000000000000000000000000000000000000002030101
            ) // coeff_computations[0]
            mstore(
                0x0820,
                0x0000000000000000000000000000000000000000000000000000000000200300
            ) // coeff_computations[1]
            mstore(
                0x0840,
                0x00000000000000000000000000000080006000400320030002e002c002a00280
            ) // coeff_computations[2]
            mstore(
                0x0860,
                0x000000000000000000000000000000000000000000c000a00320030002c002a0
            ) // coeff_computations[3]
            mstore(
                0x0880,
                0x00000000000000000000000000000000000000000000000000000060036000e0
            ) // normalized_coeff_computations
            mstore(
                0x08a0,
                0x00000000000000000000000000000000000000000000000040602003c0038001
            ) // r_evals_computations[0]
            mstore(
                0x08c0,
                0x0000000000000000000000000000000000000002a403a40003c404240003c401
            ) // r_evals_computations[1]
            mstore(
                0x08e0,
                0x0000000000000000000000000000000000000000000000000004640444048401
            ) // r_evals_computations[2]
            mstore(
                0x0900,
                0x00000000000000000000000000000000000000000000000000000004c404a401
            ) // r_evals_computations[3]
            mstore(
                0x0920,
                0x0000000000000000000000000000000000000000000004604004406004202001
            ) // coeff_sums_computations[0]
            mstore(
                0x0940,
                0x0000000000000000000000000000000000000000000000000000040004200060
            ) // r_eval_computations
            mstore(
                0x0960,
                0x00000000000000000000000000000000202020054405240340050404e4038001
            ) // pairing_input_computations[0]
            mstore(
                0x0980,
                0x0000000000000000000000000000004401040001048006800000010201e401c4
            ) // pairing_input_computations[1]
            mstore(
                0x09a0,
                0x0000000000000000000000000000000000000000000000000000000001640144
            ) // pairing_input_computations[2]
            mstore(
                0x09c0,
                0x0000000000000000000000000000000000000000000000000000000001a40184
            ) // pairing_input_computations[3]
            mstore(
                0x09e0,
                0x0000000000000000000000000000000000000000000000000000000140001201
            ) // rescaling_computations[0]
            return(0, 0x0a00)
        }
    }
}
