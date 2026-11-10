mod authorization_gate;
mod change_items;
mod changelog;
mod changelog_fetch;
mod changelog_sources;
mod classification;
mod cli;
mod cli_demo;
mod download_progress;
mod intelligence;
mod ipc_demo_worker;
mod ipc_stream;
mod lab_ipc_runner;
mod lab_seccomp;
use rwr_package_intelligence::process_guard;
mod production_ipc;
use rwr_package_intelligence::libalpm_ffi;
mod package_description;
mod packages;
mod process_runner;
mod real_progress;
mod real_update_events;
mod real_update_preflight;
mod real_update_stream;
mod real_update_worker;
mod system_info;
mod terminal_backend;
mod transaction_engine;
use rwr_package_intelligence::transaction_ipc;
#[cfg(test)]
mod transaction_process_test;
use rwr_package_intelligence::transaction_protocol;
use rwr_package_intelligence::transaction_state;
use rwr_package_intelligence::transaction_worker;
mod fbi_access;
mod ufo_progress;
mod ufo_window;
mod ui;
mod update_analysis;
mod update_cards;
mod update_engine;
mod update_event_parser;
mod update_event_stream;
mod update_events;
mod update_launcher;
mod update_progress;
mod update_report;
mod update_result;
mod update_worker;

use gtk4::Application;
use gtk4::prelude::*;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args == ["--help"] {
        println!("RWR PACKAGE INTELLIGENCE");
        println!("  --cli                 Read-only terminal update scanner");
        println!("  --cli --demo          Demonstration data only");
        println!("  --cli --lang pl       Polish CLI");
        println!("  --cli --lang en       English CLI");
        println!("  --ufo-preview  UFO interface preview");
        println!("  --help         Show this help");
        return;
    }

    if args.first().map(String::as_str) == Some("--cli") {
        let language = match args.as_slice() {
            [_] | [_, _] if args.len() == 1 || args[1] == "--demo" => cli::Language::detect(),
            [_, flag, code] if flag == "--lang" => match cli::Language::from_code(code) {
                Some(language) => language,
                None => {
                    eprintln!("Unsupported language. Use pl or en.");
                    std::process::exit(2);
                }
            },
            [_, demo, flag, code] if demo == "--demo" && flag == "--lang" => {
                cli::Language::from_code(code).unwrap_or_else(|| {
                    eprintln!("Unsupported language. Use pl or en.");
                    std::process::exit(2);
                })
            }
            _ => {
                eprintln!("Usage: --cli [--demo] [--lang pl|en]");
                std::process::exit(2);
            }
        };

        std::process::exit(cli::run(language, args.iter().any(|x| x == "--demo")));
    }

    if !args.is_empty() && args != ["--ufo-preview"] {
        eprintln!("Unknown arguments. Use --help.");
        std::process::exit(2);
    }

    let app = Application::builder()
        .application_id("io.github.runningwithrottweilers.PackageIntelligence")
        .build();

    let preview = std::env::args().any(|arg| arg == "--ufo-preview");

    if preview {
        app.connect_activate(|app| {
            let window = ufo_window::build_ufo_window(app);
            window.present();
        });
    } else {
        app.connect_activate(ui::build_ui);
    }

    app.run_with_args::<&str>(&[]);
}

// Test builds of this binary never reach the production host (deny-only).
rwr_package_intelligence::isolate_test_binary!();
