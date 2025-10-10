// Copyright 2025 zkonduit
// Copyright 2025 Horizen Labs, Inc.
// SPDX-License-Identifier: Apache-2.0 or MIT

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::{Fr, U256};
use ark_ff::MontFp;

pub(crate) const PTR_BITMASK: u64 = 0xFFFF;
pub(crate) const BYTE_FLAG_BITMASK: u64 = 0xFF;
pub(crate) const DELTA: Fr =
    MontFp!("4131629893567559867359510883348571134090853742863529169391034518566172092834");
pub(crate) const MAX_U32: U256 = U256::new([u32::MAX as u64, 0, 0, 0]);
