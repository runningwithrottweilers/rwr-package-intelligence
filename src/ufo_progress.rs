// RWR UFO ABDUCTION — X-FILES progress scene.
// Visual-only component. It renders state supplied by the GUI and never
// performs, starts or authorizes any package operation.

use gtk4::DrawingArea;
use gtk4::cairo::{Context, FontSlant, FontWeight, LinearGradient, RadialGradient};
use gtk4::prelude::*;
use std::cell::{Cell, RefCell};
use std::f64::consts::{PI, TAU};
use std::rc::Rc;

/// Logical scene size. The scene is scaled uniformly to fit its widget.
pub const SCENE_WIDTH: f64 = 720.0;
pub const SCENE_HEIGHT: f64 = 360.0;
const HORIZON: f64 = 250.0;
const COW_GROUND: f64 = 262.0;
const UFO_Y: f64 = 132.0;
const COW_SHIP: f64 = UFO_Y + 58.0;
const HUD_TOP: f64 = 280.0;

/// Operation phase shown by the scene. Mirrors real GUI/IPC state only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UfoStage {
    Scanning,
    Changelogs,
    Preparing,
    Download,
    Verify,
    Install,
    Finished,
    Failed,
}

const SCAN_STEPS: [UfoStage; 2] = [UfoStage::Scanning, UfoStage::Changelogs];
const TRANSACTION_STEPS: [UfoStage; 5] = [
    UfoStage::Preparing,
    UfoStage::Download,
    UfoStage::Verify,
    UfoStage::Install,
    UfoStage::Finished,
];

impl UfoStage {
    pub fn title(self, english: bool) -> &'static str {
        let (pl, en) = match self {
            Self::Scanning => ("SKANOWANIE SYSTEMU", "SCANNING SYSTEM"),
            Self::Changelogs => ("ANALIZA ZMIAN", "ANALYZING CHANGES"),
            Self::Preparing => ("PRZYGOTOWANIE PLANU", "PREPARING PLAN"),
            Self::Download => ("POBIERANIE PAKIETÓW", "DOWNLOADING PACKAGES"),
            Self::Verify => ("WERYFIKACJA PAKIETÓW", "VERIFYING PACKAGES"),
            Self::Install => ("INSTALACJA PAKIETÓW", "INSTALLING PACKAGES"),
            Self::Finished => ("ZAKOŃCZONO", "COMPLETED"),
            Self::Failed => ("PRZERWANO", "STOPPED"),
        };
        if english { en } else { pl }
    }

    pub fn hint(self, english: bool) -> &'static str {
        let (pl, en) = match self {
            Self::Scanning => (
                "Przeszukiwanie repozytoriów Arch Linux…",
                "Searching Arch Linux repositories…",
            ),
            Self::Changelogs => (
                "Pobieranie informacji o zmianach",
                "Reading change information",
            ),
            Self::Preparing => (
                "Przygotowanie i sprawdzanie planu",
                "Preparing and validating the plan",
            ),
            Self::Download => (
                "Pobieranie pakietów z mirrorów",
                "Downloading packages from mirrors",
            ),
            Self::Verify => (
                "Sprawdzanie podpisów i integralności",
                "Checking signatures and integrity",
            ),
            Self::Install => ("NIE WYŁĄCZAJ KOMPUTERA", "DO NOT POWER OFF"),
            Self::Finished => ("Operacja zakończona", "Operation finished"),
            Self::Failed => (
                "Operacja przerwana — sprawdź komunikat",
                "Operation stopped — see the message",
            ),
        };
        if english { en } else { pl }
    }

    fn step_label(self, english: bool) -> &'static str {
        let (pl, en) = match self {
            Self::Scanning => ("SKAN", "SCAN"),
            Self::Changelogs => ("ZMIANY", "CHANGES"),
            Self::Preparing => ("PLAN", "PLAN"),
            Self::Download => ("POBIERANIE", "DOWNLOAD"),
            Self::Verify => ("WERYFIKACJA", "VERIFY"),
            Self::Install => ("INSTALACJA", "INSTALL"),
            Self::Finished => ("KONIEC", "DONE"),
            Self::Failed => ("BŁĄD", "ERROR"),
        };
        if english { en } else { pl }
    }

    fn steps(self) -> &'static [UfoStage] {
        match self {
            Self::Scanning | Self::Changelogs => &SCAN_STEPS,
            _ => &TRANSACTION_STEPS,
        }
    }
}

/// What the scene shows. `progress` is `None` whenever no measured value
/// exists; the scene then animates without displaying a percentage.
#[derive(Clone, Debug, PartialEq)]
pub struct UfoStatus {
    pub stage: UfoStage,
    pub progress: Option<f64>,
    pub detail: String,
    pub english: bool,
}

impl Default for UfoStatus {
    fn default() -> Self {
        Self {
            stage: UfoStage::Scanning,
            progress: None,
            detail: String::new(),
            english: false,
        }
    }
}

impl UfoStatus {
    /// Only finite values are measurements; anything else is "unknown".
    pub fn measured(&self) -> Option<f64> {
        self.progress
            .filter(|value| value.is_finite())
            .map(|value| value.clamp(0.0, 1.0))
    }
}

/// Cow altitude (logical y of its feet) for a measured progress.
pub fn cow_height(progress: f64) -> f64 {
    let p = progress.clamp(0.0, 1.0);
    // Linear: the altitude is the measured value, not an eased impression.
    COW_GROUND - p * (COW_GROUND - COW_SHIP)
}

fn neon(cr: &Context, alpha: f64) {
    cr.set_source_rgba(0.224, 0.910, 0.475, alpha);
}

fn amber(cr: &Context, alpha: f64) {
    cr.set_source_rgba(1.0, 0.72, 0.20, alpha);
}

fn alarm(cr: &Context, alpha: f64) {
    cr.set_source_rgba(1.0, 0.27, 0.27, alpha);
}

fn ellipse(cr: &Context, x: f64, y: f64, rx: f64, ry: f64) {
    cr.save().ok();
    cr.translate(x, y);
    cr.scale(rx.max(0.01), ry.max(0.01));
    cr.arc(0.0, 0.0, 1.0, 0.0, TAU);
    cr.restore().ok();
}

fn rounded(cr: &Context, x: f64, y: f64, w: f64, h: f64, r: f64) {
    cr.new_sub_path();
    cr.arc(x + w - r, y + r, r, -PI / 2.0, 0.0);
    cr.arc(x + w - r, y + h - r, r, 0.0, PI / 2.0);
    cr.arc(x + r, y + h - r, r, PI / 2.0, PI);
    cr.arc(x + r, y + r, r, PI, 1.5 * PI);
    cr.close_path();
}

fn font(cr: &Context, size: f64) {
    cr.select_font_face("Monospace", FontSlant::Normal, FontWeight::Bold);
    cr.set_font_size(size);
}

/// Shorten `text` with an ellipsis until it fits `max_width` at the current font.
fn fit_text(cr: &Context, text: &str, max_width: f64) -> String {
    let width = |s: &str| cr.text_extents(s).map(|e| e.x_advance()).unwrap_or(0.0);
    if width(text) <= max_width {
        return text.to_owned();
    }
    let mut chars: Vec<char> = text.chars().collect();
    while !chars.is_empty() {
        chars.pop();
        let candidate: String = chars.iter().collect::<String>() + "…";
        if width(&candidate) <= max_width {
            return candidate;
        }
    }
    String::new()
}

fn text_at(cr: &Context, text: &str, x: f64, y: f64, align: f64) {
    let advance = cr.text_extents(text).map(|e| e.x_advance()).unwrap_or(0.0);
    cr.move_to(x - advance * align, y);
    let _ = cr.show_text(text);
}

fn draw_sky(cr: &Context, sw: f64, t: f64, ufo_x: f64) {
    cr.set_source_rgb(0.012, 0.024, 0.016);
    cr.rectangle(0.0, 0.0, sw, SCENE_HEIGHT);
    let _ = cr.fill();

    let glow = RadialGradient::new(ufo_x, UFO_Y, 10.0, ufo_x, UFO_Y, 300.0);
    glow.add_color_stop_rgba(0.0, 0.22, 0.91, 0.47, 0.16);
    glow.add_color_stop_rgba(1.0, 0.22, 0.91, 0.47, 0.0);
    let _ = cr.set_source(&glow);
    cr.rectangle(0.0, 0.0, sw, HORIZON);
    let _ = cr.fill();

    // Deterministic star field with gentle twinkle.
    let mut seed: u32 = 0x5eed_1947;
    for index in 0..46 {
        seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        let x = f64::from(seed >> 8) / f64::from(1_u32 << 24) * sw;
        seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        let y = f64::from(seed >> 8) / f64::from(1_u32 << 24) * (HORIZON - 20.0);
        let twinkle = ((t * 1.7 + f64::from(index) * 0.9).sin() + 1.0) * 0.5;
        cr.set_source_rgba(0.62, 0.96, 0.72, 0.18 + twinkle * 0.55);
        cr.arc(x, y, if index % 7 == 0 { 1.6 } else { 1.0 }, 0.0, TAU);
        let _ = cr.fill();
    }
}

fn draw_ground(cr: &Context, sw: f64) {
    // Distant hills.
    cr.set_source_rgb(0.020, 0.060, 0.034);
    cr.save().ok();
    cr.scale(sw / SCENE_WIDTH, 1.0);
    cr.move_to(0.0, HORIZON);
    cr.curve_to(120.0, 214.0, 210.0, 236.0, 300.0, 226.0);
    cr.curve_to(420.0, 212.0, 520.0, 238.0, 720.0, 218.0);
    cr.line_to(720.0, HORIZON);
    cr.close_path();
    let _ = cr.fill();
    cr.restore().ok();

    let field = LinearGradient::new(0.0, HORIZON, 0.0, HUD_TOP);
    field.add_color_stop_rgb(0.0, 0.035, 0.105, 0.058);
    field.add_color_stop_rgb(1.0, 0.012, 0.035, 0.020);
    let _ = cr.set_source(&field);
    cr.rectangle(0.0, HORIZON, sw, HUD_TOP - HORIZON);
    let _ = cr.fill();

    neon(cr, 0.45);
    cr.set_line_width(1.2);
    cr.move_to(0.0, HORIZON + 0.5);
    cr.line_to(sw, HORIZON + 0.5);
    let _ = cr.stroke();

    // Grass tufts.
    cr.set_source_rgba(0.10, 0.36, 0.18, 0.9);
    let mut x = 6.0;
    while x < sw {
        let h = 4.0 + (x * 0.37).sin().abs() * 6.0;
        cr.move_to(x, HORIZON + 14.0);
        cr.line_to(x + 2.0, HORIZON + 14.0 - h);
        cr.line_to(x + 4.0, HORIZON + 14.0);
        x += 19.0;
    }
    let _ = cr.fill();
}

fn draw_beam(cr: &Context, x: f64, t: f64, strength: f64, failed: bool) {
    if strength <= 0.0 {
        return;
    }
    let top = UFO_Y + 18.0;
    let bottom = HORIZON + 18.0;
    let gradient = LinearGradient::new(0.0, top, 0.0, bottom);
    if failed {
        gradient.add_color_stop_rgba(0.0, 1.0, 0.3, 0.3, 0.30 * strength);
        gradient.add_color_stop_rgba(1.0, 1.0, 0.3, 0.3, 0.05 * strength);
    } else {
        gradient.add_color_stop_rgba(0.0, 0.40, 1.0, 0.55, 0.50 * strength);
        gradient.add_color_stop_rgba(1.0, 0.22, 0.91, 0.47, 0.10 * strength);
    }
    let _ = cr.set_source(&gradient);
    cr.move_to(x - 34.0, top);
    cr.line_to(x - 112.0, bottom);
    cr.line_to(x + 112.0, bottom);
    cr.line_to(x + 34.0, top);
    cr.close_path();
    let _ = cr.fill();

    // Rising energy rings inside the beam.
    cr.set_line_width(1.4);
    for ring in 0..5 {
        let phase = ((t * 0.55 + f64::from(ring) / 5.0) % 1.0 + 1.0) % 1.0;
        let y = bottom - phase * (bottom - top);
        let half = 34.0 + (y - top) / (bottom - top) * 78.0;
        let alpha = (1.0 - phase) * 0.45 * strength;
        if failed {
            alarm(cr, alpha);
        } else {
            neon(cr, alpha);
        }
        ellipse(cr, x, y, half, 4.0 + half * 0.05);
        let _ = cr.stroke();
    }

    // Spot on the ground.
    neon(cr, 0.22 * strength);
    ellipse(cr, x, bottom - 2.0, 112.0, 9.0);
    let _ = cr.fill();
}

fn draw_ufo(cr: &Context, x: f64, y: f64, t: f64, stage: UfoStage) {
    // Halo.
    let halo = RadialGradient::new(x, y, 20.0, x, y, 190.0);
    halo.add_color_stop_rgba(0.0, 0.22, 0.91, 0.47, 0.20);
    halo.add_color_stop_rgba(1.0, 0.22, 0.91, 0.47, 0.0);
    let _ = cr.set_source(&halo);
    ellipse(cr, x, y, 190.0, 70.0);
    let _ = cr.fill();

    // Lower skirt and emitter.
    let skirt = LinearGradient::new(0.0, y, 0.0, y + 26.0);
    skirt.add_color_stop_rgb(0.0, 0.16, 0.22, 0.19);
    skirt.add_color_stop_rgb(1.0, 0.05, 0.08, 0.06);
    let _ = cr.set_source(&skirt);
    ellipse(cr, x, y + 12.0, 96.0, 18.0);
    let _ = cr.fill();
    let emitter = RadialGradient::new(x, y + 24.0, 2.0, x, y + 24.0, 34.0);
    emitter.add_color_stop_rgba(0.0, 0.75, 1.0, 0.82, 0.95);
    emitter.add_color_stop_rgba(1.0, 0.22, 0.91, 0.47, 0.0);
    let _ = cr.set_source(&emitter);
    ellipse(cr, x, y + 24.0, 34.0, 9.0);
    let _ = cr.fill();

    // Glass dome.
    let dome = LinearGradient::new(x - 50.0, y - 46.0, x + 50.0, y);
    dome.add_color_stop_rgba(0.0, 0.55, 1.0, 0.70, 0.55);
    dome.add_color_stop_rgba(1.0, 0.06, 0.30, 0.16, 0.85);
    let _ = cr.set_source(&dome);
    cr.save().ok();
    cr.translate(x, y - 10.0);
    cr.scale(56.0, 42.0);
    cr.arc(0.0, 0.0, 1.0, PI, TAU);
    cr.restore().ok();
    let _ = cr.fill();
    cr.set_source_rgba(0.9, 1.0, 0.93, 0.35);
    ellipse(cr, x - 20.0, y - 32.0, 14.0, 6.0);
    let _ = cr.fill();

    // Metallic hull.
    let hull = LinearGradient::new(0.0, y - 22.0, 0.0, y + 22.0);
    hull.add_color_stop_rgb(0.0, 0.62, 0.70, 0.66);
    hull.add_color_stop_rgb(0.45, 0.30, 0.36, 0.33);
    hull.add_color_stop_rgb(1.0, 0.09, 0.12, 0.10);
    let _ = cr.set_source(&hull);
    ellipse(cr, x, y, 160.0, 24.0);
    let _ = cr.fill();
    neon(cr, 0.75);
    cr.set_line_width(1.6);
    ellipse(cr, x, y, 160.0, 24.0);
    let _ = cr.stroke();

    // Chasing rim lights; colour reflects the phase.
    let lights = 11;
    let lead = (t * 6.0) as i64;
    for index in 0..lights {
        let angle = PI * (f64::from(index) + 0.5) / f64::from(lights);
        let lx = x - 150.0 * angle.cos();
        let ly = y + 9.0 * angle.sin();
        let active = (lead - i64::from(index)).rem_euclid(i64::from(lights)) < 3;
        let alpha = if active { 1.0 } else { 0.35 };
        match stage {
            UfoStage::Install => amber(cr, alpha),
            UfoStage::Failed => alarm(cr, alpha),
            _ => cr.set_source_rgba(0.70, 1.0, 0.78, alpha),
        }
        cr.arc(lx, ly, if active { 4.0 } else { 3.0 }, 0.0, TAU);
        let _ = cr.fill();
    }
}

/// Cow drawn around its feet centre. `lift` 0..1 controls dangling legs.
fn draw_cow(cr: &Context, x: f64, feet: f64, scale: f64, tilt: f64, lift: f64, t: f64) {
    if scale <= 0.02 {
        return;
    }
    cr.save().ok();
    cr.translate(x, feet);
    cr.rotate(tilt);
    cr.scale(scale, scale);

    let white = |cr: &Context| cr.set_source_rgb(0.93, 0.97, 0.93);
    let dark = |cr: &Context| cr.set_source_rgb(0.05, 0.07, 0.06);

    // Legs (swing when lifted).
    cr.set_line_width(5.0);
    cr.set_line_cap(gtk4::cairo::LineCap::Round);
    for (index, leg_x) in [-24.0_f64, -12.0, 12.0, 24.0].into_iter().enumerate() {
        let swing = lift * (t * 5.0 + index as f64).sin() * 6.0;
        white(cr);
        cr.move_to(leg_x, -14.0);
        cr.line_to(leg_x + swing, -1.0);
        let _ = cr.stroke();
        dark(cr);
        cr.arc(leg_x + swing, -1.0, 2.6, 0.0, TAU);
        let _ = cr.fill();
    }

    // Body with patches.
    white(cr);
    rounded(cr, -34.0, -40.0, 68.0, 30.0, 12.0);
    let _ = cr.fill_preserve();
    neon(cr, 0.9);
    cr.set_line_width(1.6);
    let _ = cr.stroke();
    dark(cr);
    ellipse(cr, -14.0, -30.0, 10.0, 7.0);
    let _ = cr.fill();
    ellipse(cr, 12.0, -22.0, 8.0, 6.0);
    let _ = cr.fill();
    ellipse(cr, -26.0, -18.0, 5.0, 4.0);
    let _ = cr.fill();

    // Udder.
    cr.set_source_rgb(0.98, 0.62, 0.72);
    ellipse(cr, 4.0, -11.0, 7.0, 4.0);
    let _ = cr.fill();

    // Tail.
    white(cr);
    cr.set_line_width(2.4);
    cr.move_to(-33.0, -34.0);
    cr.curve_to(
        -44.0,
        -32.0,
        -42.0,
        -20.0,
        -46.0,
        -14.0 + (t * 3.0).sin() * 2.0,
    );
    let _ = cr.stroke();

    // Head.
    white(cr);
    rounded(cr, 28.0, -54.0, 24.0, 22.0, 8.0);
    let _ = cr.fill_preserve();
    neon(cr, 0.9);
    cr.set_line_width(1.6);
    let _ = cr.stroke();
    cr.set_source_rgb(0.98, 0.70, 0.76);
    rounded(cr, 38.0, -42.0, 16.0, 11.0, 5.0);
    let _ = cr.fill();
    dark(cr);
    cr.arc(36.0, -47.0, 2.2, 0.0, TAU);
    let _ = cr.fill();
    cr.arc(44.0, -38.0, 1.2, 0.0, TAU);
    cr.arc(50.0, -38.0, 1.2, 0.0, TAU);
    let _ = cr.fill();
    // Ears and horns.
    white(cr);
    ellipse(cr, 26.0, -52.0, 6.0, 3.5);
    let _ = cr.fill();
    cr.set_source_rgb(0.85, 0.82, 0.62);
    cr.move_to(32.0, -54.0);
    cr.line_to(30.0, -62.0);
    cr.line_to(35.0, -55.0);
    cr.move_to(44.0, -54.0);
    cr.line_to(46.0, -62.0);
    cr.line_to(41.0, -55.0);
    let _ = cr.fill();

    cr.restore().ok();
}

fn draw_hud(cr: &Context, sw: f64, status: &UfoStatus, t: f64) {
    let english = status.english;
    let measured = status.measured();
    let failed = status.stage == UfoStage::Failed;

    // Header.
    font(cr, 12.0);
    neon(cr, 0.55);
    text_at(
        cr,
        "RWR // X-FILES · THE TRUTH IS OUT THERE",
        24.0,
        22.0,
        0.0,
    );
    font(cr, 24.0);
    if failed {
        alarm(cr, 1.0);
    } else {
        neon(cr, 1.0);
    }
    text_at(cr, status.stage.title(english), 24.0, 50.0, 0.0);
    font(cr, 14.0);
    if status.stage == UfoStage::Install {
        let pulse = ((t * 4.0).sin() + 1.0) * 0.5;
        amber(cr, 0.65 + pulse * 0.35);
    } else {
        cr.set_source_rgba(0.75, 0.92, 0.80, 0.85);
    }
    text_at(cr, status.stage.hint(english), 24.0, 70.0, 0.0);

    // Percentage, only for measured progress.
    font(cr, 40.0);
    if let Some(p) = measured {
        neon(cr, 1.0);
        text_at(cr, &format!("{:.0}%", p * 100.0), sw - 24.0, 58.0, 1.0);
    } else if status.stage != UfoStage::Finished && !failed {
        neon(cr, 0.75);
        let dots = ["·  ", "·· ", "···"][((t * 2.5) as usize) % 3];
        text_at(cr, dots, sw - 24.0, 58.0, 1.0);
    }

    // Bottom console.
    cr.set_source_rgba(0.0, 0.0, 0.0, 0.78);
    cr.rectangle(0.0, HUD_TOP, sw, SCENE_HEIGHT - HUD_TOP);
    let _ = cr.fill();
    neon(cr, 0.55);
    cr.set_line_width(1.0);
    cr.move_to(0.0, HUD_TOP + 0.5);
    cr.line_to(sw, HUD_TOP + 0.5);
    let _ = cr.stroke();

    // Phase steps.
    font(cr, 13.0);
    let steps = status.stage.steps();
    let current = steps.iter().position(|step| *step == status.stage);
    let slot = (sw - 48.0) / steps.len() as f64;
    for (index, step) in steps.iter().enumerate() {
        let x = 24.0 + slot * index as f64 + slot / 2.0;
        let done = current.is_some_and(|c| index < c) || status.stage == UfoStage::Finished;
        let here = current == Some(index);
        if here && failed {
            alarm(cr, 1.0);
        } else if here {
            neon(cr, 1.0);
        } else if done {
            neon(cr, 0.55);
        } else {
            cr.set_source_rgba(0.55, 0.65, 0.58, 0.45);
        }
        let marker = if done && !here {
            "■ "
        } else if here {
            "▶ "
        } else {
            "□ "
        };
        text_at(
            cr,
            &format!("{marker}{}", step.step_label(english)),
            x,
            HUD_TOP + 22.0,
            0.5,
        );
    }

    // Segmented progress bar.
    let (bar_x, bar_y, bar_w, bar_h) = (24.0, HUD_TOP + 32.0, sw - 48.0, 14.0);
    if failed {
        alarm(cr, 0.8);
    } else {
        neon(cr, 0.8);
    }
    cr.set_line_width(1.2);
    cr.rectangle(bar_x, bar_y, bar_w, bar_h);
    let _ = cr.stroke();
    let segments = 48;
    let gap = 2.0;
    let seg_w = (bar_w - 4.0 - gap * f64::from(segments - 1)) / f64::from(segments);
    let filled = |index: i32| -> bool {
        match (measured, status.stage) {
            (_, UfoStage::Finished) => true,
            (Some(p), _) => f64::from(index) < (p * f64::from(segments)).round(),
            (None, UfoStage::Failed) => false,
            (None, _) => {
                // Indeterminate: a block sweeps back and forth.
                let span = f64::from(segments - 8);
                let head = ((t * 0.6) % 2.0 - 1.0).abs() * span;
                let i = f64::from(index);
                i >= head && i < head + 8.0
            }
        }
    };
    for index in 0..segments {
        if filled(index) {
            if failed {
                alarm(cr, 0.85);
            } else {
                neon(cr, 0.95);
            }
            cr.rectangle(
                bar_x + 2.0 + f64::from(index) * (seg_w + gap),
                bar_y + 2.0,
                seg_w,
                bar_h - 4.0,
            );
            let _ = cr.fill();
        }
    }

    // Detail line (package name, counts or message).
    font(cr, 15.0);
    cr.set_source_rgba(0.86, 0.96, 0.89, 0.95);
    let detail = if status.detail.trim().is_empty() {
        String::from("RWR PACKAGE INTELLIGENCE")
    } else {
        status.detail.replace('\n', " · ")
    };
    let detail = fit_text(cr, &detail, sw - 48.0);
    text_at(cr, &detail, 24.0, SCENE_HEIGHT - 16.0, 0.0);
}

fn draw_scanlines(cr: &Context, sw: f64) {
    cr.set_source_rgba(0.0, 0.0, 0.0, 0.18);
    let mut y = 0.0;
    while y < SCENE_HEIGHT {
        cr.rectangle(0.0, y, sw, 1.0);
        y += 3.0;
    }
    let _ = cr.fill();
}

/// Logical width for a widget: at least the base scene, wider for wide areas
/// (capped so very wide windows do not spread the HUD too far).
pub fn scene_width(width: f64, height: f64) -> f64 {
    if !(width > 0.0 && height > 0.0) {
        return SCENE_WIDTH;
    }
    (SCENE_HEIGHT * width / height).clamp(SCENE_WIDTH, SCENE_WIDTH * 2.2)
}

/// Renders the complete scene into a `width`×`height` area. Pure drawing:
/// used by the widget and by headless preview/tests.
pub fn draw_scene(cr: &Context, width: f64, height: f64, status: &UfoStatus, t: f64) {
    // Letterbox in the same black so the scene blends with any widget shape.
    cr.set_source_rgb(0.012, 0.024, 0.016);
    cr.rectangle(0.0, 0.0, width, height);
    let _ = cr.fill();
    // Wide areas extend the sky, ground and HUD instead of letterboxing;
    // the ship and cow keep their proportions.
    let sw = scene_width(width, height);
    let scale = (width / sw).min(height / SCENE_HEIGHT);
    if scale <= 0.0 || !scale.is_finite() {
        return;
    }
    cr.save().ok();
    cr.translate(
        (width - sw * scale) / 2.0,
        (height - SCENE_HEIGHT * scale) / 2.0,
    );
    cr.scale(scale, scale);
    cr.rectangle(0.0, 0.0, sw, SCENE_HEIGHT);
    cr.clip();

    let measured = status.measured();
    let center = sw / 2.0;
    // While scanning without measurements the ship sweeps like a searchlight.
    let searching =
        measured.is_none() && matches!(status.stage, UfoStage::Scanning | UfoStage::Changelogs);
    let ufo_x = if searching {
        center + (t * 0.8).sin() * (sw / 2.0 - 190.0).max(120.0)
    } else {
        center
    };
    let ufo_y = UFO_Y + (t * 1.6).sin() * 4.0;

    draw_sky(cr, sw, t, ufo_x);
    draw_ground(cr, sw);

    let (beam, cow_feet, cow_scale) = match (status.stage, measured) {
        (UfoStage::Finished, _) => (0.0, COW_SHIP, 0.0),
        (UfoStage::Failed, _) => (0.35, COW_GROUND, 1.0),
        (_, Some(p)) => {
            let shrink = if p < 0.85 {
                1.0 - p * 0.55
            } else {
                (1.0 - p) / 0.15 * 0.5325
            };
            (1.0, cow_height(p), shrink.max(0.0))
        }
        (_, None) => (if searching { 0.8 } else { 0.9 }, COW_GROUND, 1.0),
    };
    draw_beam(cr, ufo_x, t, beam, status.stage == UfoStage::Failed);
    let lifted = cow_feet < COW_GROUND - 1.0;
    let lift = if lifted { 1.0 } else { 0.0 };
    let tilt = if lifted { (t * 2.2).sin() * 0.14 } else { 0.0 };
    let bob = if lifted {
        0.0
    } else {
        (t * 3.0).sin().abs() * -1.5
    };
    draw_cow(cr, center, cow_feet + bob, cow_scale, tilt, lift, t);
    draw_ufo(cr, ufo_x, ufo_y, t, status.stage);
    draw_scanlines(cr, sw);
    draw_hud(cr, sw, status, t);
    cr.restore().ok();
}

/// Creates an animated scene widget bound to shared status. Several widgets
/// may share one status (e.g. compact scan strip and full transaction view).
pub fn build_ufo_scene(status: Rc<RefCell<UfoStatus>>) -> DrawingArea {
    let clock = Rc::new(Cell::new(0.0_f64));
    let area = DrawingArea::new();
    area.set_content_width(480);
    area.set_content_height(240);
    area.add_css_class("ufo-scene");

    let draw_clock = Rc::clone(&clock);
    area.set_draw_func(move |_, cr, width, height| {
        let current = status.borrow().clone();
        draw_scene(
            cr,
            f64::from(width),
            f64::from(height),
            &current,
            draw_clock.get(),
        );
    });

    // Frame-clock driven, ~30 fps; runs only while the widget is mapped.
    let last = Cell::new(0_i64);
    area.add_tick_callback(move |area, frame| {
        let now = frame.frame_time();
        if now - last.get() >= 33_000 {
            last.set(now);
            clock.set(now as f64 / 1_000_000.0);
            area.queue_draw();
        }
        gtk4::glib::ControlFlow::Continue
    });
    area
}

#[cfg(test)]
mod tests {
    use super::*;
    use gtk4::cairo::{Format, ImageSurface};

    #[test]
    fn cow_starts_on_ground() {
        assert_eq!(cow_height(0.0), COW_GROUND);
    }

    #[test]
    fn cow_reaches_ship() {
        assert_eq!(cow_height(1.0), COW_SHIP);
    }

    #[test]
    fn progress_is_clamped_and_monotonic() {
        assert_eq!(cow_height(-1.0), COW_GROUND);
        assert_eq!(cow_height(2.0), COW_SHIP);
        let mut previous = cow_height(0.0);
        for step in 1..=100 {
            let next = cow_height(f64::from(step) / 100.0);
            assert!(next <= previous);
            previous = next;
        }
    }

    #[test]
    fn unknown_progress_is_never_a_measurement() {
        for value in [None, Some(f64::NAN), Some(f64::INFINITY)] {
            let status = UfoStatus {
                progress: value,
                ..UfoStatus::default()
            };
            assert_eq!(status.measured(), None);
        }
        let status = UfoStatus {
            progress: Some(1.7),
            ..UfoStatus::default()
        };
        assert_eq!(status.measured(), Some(1.0));
    }

    #[test]
    fn every_stage_has_polish_and_english_text() {
        for stage in [
            UfoStage::Scanning,
            UfoStage::Changelogs,
            UfoStage::Preparing,
            UfoStage::Download,
            UfoStage::Verify,
            UfoStage::Install,
            UfoStage::Finished,
            UfoStage::Failed,
        ] {
            assert!(!stage.title(false).is_empty() && !stage.title(true).is_empty());
            assert_ne!(stage.title(false), stage.hint(false));
            assert!(stage.steps().len() >= 2);
        }
        assert_eq!(UfoStage::Install.hint(false), "NIE WYŁĄCZAJ KOMPUTERA");
        assert_eq!(UfoStage::Install.hint(true), "DO NOT POWER OFF");
    }

    fn render(status: &UfoStatus, width: i32, height: i32) -> ImageSurface {
        let mut surface = ImageSurface::create(Format::ARgb32, width, height).unwrap();
        {
            let cr = Context::new(&surface).unwrap();
            draw_scene(&cr, f64::from(width), f64::from(height), status, 1.25);
        }
        surface.flush();
        let _ = surface.data().unwrap();
        surface
    }

    fn green_pixels(surface: &mut ImageSurface, rows: std::ops::Range<i32>) -> usize {
        let width = surface.width();
        let stride = surface.stride() as usize;
        let data = surface.data().unwrap();
        let mut count = 0;
        for y in rows {
            for x in 0..width {
                let i = y as usize * stride + x as usize * 4;
                let (b, g, r) = (data[i], data[i + 1], data[i + 2]);
                if g > 150 && g > r.saturating_add(40) && g > b.saturating_add(20) {
                    count += 1;
                }
            }
        }
        count
    }

    #[test]
    fn wide_areas_extend_instead_of_letterboxing() {
        assert_eq!(scene_width(720.0, 360.0), SCENE_WIDTH);
        assert_eq!(scene_width(400.0, 400.0), SCENE_WIDTH);
        assert!((scene_width(900.0, 260.0) - 360.0 * 900.0 / 260.0).abs() < 1e-9);
        assert_eq!(scene_width(10_000.0, 100.0), SCENE_WIDTH * 2.2);
        assert_eq!(scene_width(0.0, 0.0), SCENE_WIDTH);
    }

    #[test]
    fn scene_renders_at_compact_and_full_sizes() {
        for (width, height) in [(900, 260), (900, 520), (360, 180), (1, 1)] {
            let status = UfoStatus {
                stage: UfoStage::Download,
                progress: Some(0.42),
                ..UfoStatus::default()
            };
            let surface = render(&status, width, height);
            assert_eq!(surface.width(), width);
        }
    }

    #[test]
    fn progress_bar_fill_follows_measured_progress() {
        // Bar row in a 720x360 render.
        let bar = (HUD_TOP + 36.0) as i32..(HUD_TOP + 42.0) as i32;
        let mut low = render(
            &UfoStatus {
                stage: UfoStage::Install,
                progress: Some(0.1),
                ..UfoStatus::default()
            },
            720,
            360,
        );
        let mut high = render(
            &UfoStatus {
                stage: UfoStage::Install,
                progress: Some(0.9),
                ..UfoStatus::default()
            },
            720,
            360,
        );
        let (low, high) = (
            green_pixels(&mut low, bar.clone()),
            green_pixels(&mut high, bar),
        );
        assert!(
            high > low * 4,
            "bar fill must grow with progress: {low} -> {high}"
        );
    }

    /// Writes PNG previews when RWR_UFO_PREVIEW_DIR is set (manual review only).
    #[test]
    fn write_previews_when_requested() {
        let Some(dir) = std::env::var_os("RWR_UFO_PREVIEW_DIR") else {
            return;
        };
        let dir = std::path::PathBuf::from(dir);
        let cases = [
            (
                "scan-strip-pl",
                UfoStatus {
                    stage: UfoStage::Scanning,
                    ..UfoStatus::default()
                },
                900,
                260,
            ),
            (
                "changelogs-strip-en",
                UfoStatus {
                    stage: UfoStage::Changelogs,
                    progress: Some(7.0 / 19.0),
                    detail: "7 / 19 · linux-firmware".into(),
                    english: true,
                },
                900,
                260,
            ),
            (
                "download-pl",
                UfoStatus {
                    stage: UfoStage::Download,
                    progress: Some(0.37),
                    detail: "POBIERANIE · linux-6.17.8.arch1-1-x86_64.pkg.tar.zst · 37%".into(),
                    english: false,
                },
                900,
                470,
            ),
            (
                "verify-en",
                UfoStatus {
                    stage: UfoStage::Verify,
                    progress: None,
                    detail: "VERIFYING SIGNATURES · archlinux-keyring".into(),
                    english: true,
                },
                900,
                470,
            ),
            (
                "install-pl",
                UfoStatus {
                    stage: UfoStage::Install,
                    progress: Some(0.82),
                    detail: "INSTALACJA PAKIETÓW · mesa · 82%".into(),
                    english: false,
                },
                900,
                470,
            ),
            (
                "finished-en",
                UfoStatus {
                    stage: UfoStage::Finished,
                    progress: Some(1.0),
                    detail: "RESULT SAVED".into(),
                    english: true,
                },
                900,
                470,
            ),
            (
                "failed-pl",
                UfoStatus {
                    stage: UfoStage::Failed,
                    progress: None,
                    detail: "Błąd podpisu pakietu — transakcja nie została wykonana".into(),
                    english: false,
                },
                900,
                470,
            ),
        ];
        for (name, status, width, height) in cases {
            let mut surface = render(&status, width, height);
            let data = surface.data().unwrap().to_vec();
            let bytes = gtk4::glib::Bytes::from_owned(data);
            let texture = gtk4::gdk::MemoryTexture::new(
                width,
                height,
                gtk4::gdk::MemoryFormat::B8g8r8a8Premultiplied,
                &bytes,
                surface.stride() as usize,
            );
            texture
                .save_to_png(dir.join(format!("{name}.png")))
                .unwrap();
        }
    }
}
