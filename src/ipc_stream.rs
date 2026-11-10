//! Bounded JSON Lines transport shared by laboratory and future IPC supervisors.
//! No process spawning, privileges, or package updates.
use std::io::{BufRead, Read};
use std::sync::mpsc;

// Shared bounded JSON Lines reader.
// Transport only: transaction semantics remain in TransactionWorker.
pub(crate) fn read_ipc_stream<R: BufRead>(
    mut reader: R,
    tx: mpsc::Sender<Result<Vec<u8>, String>>,
) {
    loop {
        let mut bytes = Vec::new();

        let result = reader
            .by_ref()
            .take((crate::transaction_ipc::MAX_MESSAGE_BYTES + 1) as u64)
            .read_until(b'\n', &mut bytes);

        match result {
            Ok(0) => break,
            Ok(_) => {
                if bytes.len() > crate::transaction_ipc::MAX_MESSAGE_BYTES {
                    let _ = tx.send(Err("Oversized IPC message".into()));
                    break;
                }

                if bytes.last() != Some(&b'\n') {
                    let _ = tx.send(Err("Incomplete IPC line".into()));
                    break;
                }

                if tx.send(Ok(bytes)).is_err() {
                    break;
                }
            }
            Err(error) => {
                let _ = tx.send(Err(error.to_string()));
                break;
            }
        }
    }
}
