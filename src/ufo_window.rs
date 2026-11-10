use gtk4::prelude::*;
use gtk4::{Application, ApplicationWindow, Box as GtkBox, Label, Orientation};
use std::cell::RefCell;
use std::rc::Rc;

use crate::ufo_progress::{UfoStage, UfoStatus, build_ufo_scene};

/// Visual preview only: cycles through every phase with sample values.
/// No scan, download, installation or IPC happens here.
pub fn build_ufo_window(app: &Application) -> ApplicationWindow {
    let window = ApplicationWindow::builder()
        .application(app)
        .title("RWR UFO ABDUCTION — PREVIEW")
        .default_width(960)
        .default_height(620)
        .build();
    window.add_css_class("rwr-window");

    let layout = GtkBox::new(Orientation::Vertical, 10);
    layout.add_css_class("root");
    layout.set_margin_top(12);
    layout.set_margin_bottom(12);
    layout.set_margin_start(12);
    layout.set_margin_end(12);

    let status = Rc::new(RefCell::new(UfoStatus::default()));
    let scene = build_ufo_scene(Rc::clone(&status));
    scene.set_vexpand(true);
    scene.add_css_class("ufo-stage");
    layout.append(&scene);

    let note = Label::new(Some(
        "PODGLĄD — brak operacji na pakietach / PREVIEW — no package operations",
    ));
    note.add_css_class("test-mode-label");
    layout.append(&note);

    // (stage, seconds, measured, detail PL, detail EN)
    let script: [(UfoStage, u32, bool, &str, &str); 7] = [
        (UfoStage::Scanning, 4, false, "", ""),
        (
            UfoStage::Changelogs,
            4,
            true,
            "linux-firmware",
            "linux-firmware",
        ),
        (
            UfoStage::Preparing,
            3,
            false,
            "Plan: 19 pakietów",
            "Plan: 19 packages",
        ),
        (
            UfoStage::Download,
            6,
            true,
            "POBIERANIE · linux · ",
            "DOWNLOADING · linux · ",
        ),
        (
            UfoStage::Verify,
            3,
            false,
            "WERYFIKACJA PODPISÓW",
            "VERIFYING SIGNATURES",
        ),
        (
            UfoStage::Install,
            6,
            true,
            "INSTALACJA PAKIETÓW · mesa · ",
            "INSTALLING PACKAGES · mesa · ",
        ),
        (
            UfoStage::Finished,
            3,
            true,
            "WYNIK ZAPISANY",
            "RESULT SAVED",
        ),
    ];
    let total: u32 = script.iter().map(|step| step.1 * 10).sum();
    let mut tick = 0_u32;
    let weak = scene.downgrade();
    gtk4::glib::timeout_add_local(std::time::Duration::from_millis(100), move || {
        if weak.upgrade().is_none() {
            return gtk4::glib::ControlFlow::Break;
        }
        tick = (tick + 1) % (total * 2);
        // Language alternates every full cycle.
        let english = tick >= total;
        let mut at = tick % total;
        for (stage, seconds, measured, pl, en) in script {
            let length = seconds * 10;
            if at < length {
                let fraction = f64::from(at) / f64::from(length - 1);
                let percent = format!("{:.0}%", fraction * 100.0);
                let base = if english { en } else { pl };
                let detail = match stage {
                    UfoStage::Download | UfoStage::Install => format!("{base}{percent}"),
                    UfoStage::Changelogs => {
                        format!("{} / 19 · {base}", (fraction * 19.0).round() as u32)
                    }
                    _ => base.to_owned(),
                };
                *status.borrow_mut() = UfoStatus {
                    stage,
                    progress: measured.then_some(if stage == UfoStage::Finished {
                        1.0
                    } else {
                        fraction
                    }),
                    detail,
                    english,
                };
                break;
            }
            at -= length;
        }
        gtk4::glib::ControlFlow::Continue
    });

    window.set_child(Some(&layout));
    window
}
