// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License..

use crate::pfs::sys::error::{FsError, FsResult, SgxStatus};
use crate::pfs::sys::file::{CloseMode, FileInner, FileStatus};
use crate::pfs::sys::host;
use crate::{bail, ensure, AeadKey, BlockSet};

impl<D: BlockSet> FileInner<D> {
    pub fn close(&mut self, mode: CloseMode) -> FsResult<Option<AeadKey>> {
        match mode {
            CloseMode::Import | CloseMode::Export => {
                ensure!(
                    self.metadata.encrypt_flags().is_auto_key(),
                    FsError::SgxError(SgxStatus::Unexpected)
                );
            }
            _ => (),
        }

        if mode == CloseMode::Import {
            self.need_writing = true;
        }

        if !self.status.is_ok() {
            self.clear_error()?;
        } else {
            self.internal_flush(true)?;
        }

        if self.status.is_ok() && self.last_error.is_success() {
            self.remove_recovery_file();
        }

        self.set_file_status(FileStatus::Closed);
        if mode == CloseMode::Export {
            self.metadata.restore_key(&self.key_gen).map(Some)
        } else {
            Ok(None)
        }
    }

    fn remove_recovery_file(&mut self) {
        self.journal.reset().unwrap();
    }
}
