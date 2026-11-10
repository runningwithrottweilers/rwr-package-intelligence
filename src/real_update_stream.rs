// RWR PACKAGE INTELLIGENCE
// Production update stream reader.
// No command execution.

use std::io::{self, BufRead};
use std::sync::mpsc::Sender;

use crate::real_update_events::RealUpdateEvent;

pub fn forward_output<R: BufRead>(reader: R, sender: &Sender<RealUpdateEvent>) -> io::Result<()> {
    for line in reader.lines() {
        let line = line?;
        if sender
            .send(RealUpdateEvent::from_pacman_line(&line))
            .is_err()
        {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "GUI event receiver disconnected",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::sync::mpsc;

    #[test]
    fn forwards_multiple_pacman_lines() {
        let input = Cursor::new(":: Retrieving packages...\n(1/3) upgrading linux\n");
        let (sender, receiver) = mpsc::channel();

        forward_output(input, &sender).unwrap();

        assert_eq!(
            receiver.recv().unwrap(),
            RealUpdateEvent::Phase(crate::real_progress::UpgradeEvent::Downloading)
        );

        assert_eq!(
            receiver.recv().unwrap(),
            RealUpdateEvent::Phase(crate::real_progress::UpgradeEvent::Upgrading)
        );
    }

    #[test]
    fn disconnected_receiver_returns_error() {
        let input = Cursor::new(":: Retrieving packages...\n");
        let (sender, receiver) = mpsc::channel();
        drop(receiver);

        assert!(forward_output(input, &sender).is_err());
    }
}
