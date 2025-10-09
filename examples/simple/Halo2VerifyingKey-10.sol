// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

contract Halo2VerifyingKey {
    constructor() {
        assembly {
            mstore(0x0000, 0x289c5aa3a02888029b217c46689fe63db0ea367dc19b91f0b2c98746a00e9f17) // vk_digest
            mstore(0x0020, 0x000000000000000000000000000000000000000000000000000000000000000a) // num_instances
            mstore(0x0040, 0x000000000000000000000000000000000000000000000000000000000000000a) // k
            mstore(0x0060, 0x3058355f447953c1ade231a513e0f80710e9db4e679b02351f90fd168b040001) // n_inv
            mstore(0x0080, 0x2ad9021ed07c42ab19f77c5cf2cbd2deb135ea330f1b1573bd08d99309c4bb7d) // omega
            mstore(0x00a0, 0x0ae3c95fc03c0a5f2de8a8f46c03ccdfdfed2bb98c9e4ae0b10b15eda4e3b1e3) // omega_inv
            mstore(0x00c0, 0x15f79db9c39181bc3e31c83f9291da76eedf1b23c410add7e9098464aaa4fb26) // omega_inv_to_l
            mstore(0x00e0, 0x0000000000000000000000000000000000000000000000000000000000000000) // has_accumulator
            mstore(0x0100, 0x0000000000000000000000000000000000000000000000000000000000000000) // acc_offset
            mstore(0x0120, 0x0000000000000000000000000000000000000000000000000000000000000000) // num_acc_limbs
            mstore(0x0140, 0x0000000000000000000000000000000000000000000000000000000000000000) // num_acc_limb_bits
            mstore(0x0160, 0x0000000000000000000000000000000000000000000000000000000000000001) // g1_x
            mstore(0x0180, 0x0000000000000000000000000000000000000000000000000000000000000002) // g1_y
            mstore(0x01a0, 0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2) // g2_x_1
            mstore(0x01c0, 0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed) // g2_x_2
            mstore(0x01e0, 0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b) // g2_y_1
            mstore(0x0200, 0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa) // g2_y_2
            mstore(0x0220, 0x2c3f167b1cd6f704f9a7226924aef98e7c5ffb79b38726ec28b8bba01fbae9f4) // neg_s_g2_x_1
            mstore(0x0240, 0x1ba036ba9fff4e5b506841bf9a7035b36c9eb8c90d86a9dcaad6dd5a89835b37) // neg_s_g2_x_2
            mstore(0x0260, 0x28ce9ad2e7862f396e3634d47dc3d68cad3646c3965dc7c82c8ac59cc72ebc15) // neg_s_g2_y_1
            mstore(0x0280, 0x023a7f5178aac902bcd8bb8157174fb195739828dd3c04323a340c94bee21695) // neg_s_g2_y_2
            mstore(0x02a0, 0x2678a66cad477cf0d44adaba92425b169d2b672a147342974672d8c59d30e40a) // fixed_comms[0].x
            mstore(0x02c0, 0x042e5a886c683a7e8d8128c64735d62af9120b57885c2b8522908d044f714375) // fixed_comms[0].y
            mstore(0x02e0, 0x09ae21ba3d08f982a38e66b5f3507656ae6635308cd4b54f4b616d7614ea4c26) // fixed_comms[1].x
            mstore(0x0300, 0x1cecd9d1e5008441af62153146d57a2b4992bcd0d602d029588d536c60e2f4a7) // fixed_comms[1].y
            mstore(0x0320, 0x1f96dcf15b11e4249d5773d127581d547bf98c0b0d3f367fb26db34b66075f5f) // fixed_comms[2].x
            mstore(0x0340, 0x1ae7163d3826175b1a2abfe192736c37491d3b3b56281f6a14132c65bf5e2eee) // fixed_comms[2].y
            mstore(0x0360, 0x2ae2973b7a332ff47dfa07aa8f818a018306117d550533d2672c624d0df50f1a) // fixed_comms[3].x
            mstore(0x0380, 0x0c531ebcf608723eb7aa4d7a245026aedcb3a5bd14c27e3da4ce5dbe1077b13f) // fixed_comms[3].y
            mstore(0x03a0, 0x17b5de8f11b69917bf98b9b2df4de67e9f752910b7eac3542f68aeaeff975b62) // fixed_comms[4].x
            mstore(0x03c0, 0x24a9ac8037c027af108553b5cfa7747f963c2fb6f1b233200271dbf30602121a) // fixed_comms[4].y
            mstore(0x03e0, 0x199410aec079f3fe2894514d54d14d901599c0f1511515dfefa81a1a3b314b79) // permutation_comms[0].x
            mstore(0x0400, 0x179c5ad4860cece37f92ba182459c02fef6315f8ad94cba2de72a57e9833c592) // permutation_comms[0].y
            mstore(0x0420, 0x0b0ece336f0172586fd7b96af0f088c9819f838f5ed7c16e4fb08a694319cce9) // permutation_comms[1].x
            mstore(0x0440, 0x095ceb827a2b6879d53d34683e4462ef61e18138aa83e802ed68353e5d3bf617) // permutation_comms[1].y
            mstore(0x0460, 0x1b5254aa7d178823e11d86bc4ce8375a20f4e6553b0cdd98a5a477608aa1072a) // permutation_comms[2].x
            mstore(0x0480, 0x24cbac7c4477c3600c6fa3c51d4b63382d43f42d4c732dc4fafaa79716ebf25c) // permutation_comms[2].y

            return(0, 0x04a0)
        }
    }
}