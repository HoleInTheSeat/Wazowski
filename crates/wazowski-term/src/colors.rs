use alacritty_terminal::term::color::Colors;
use alacritty_terminal::vte::ansi::{Color, NamedColor, Rgb};
use egui::Color32;

/// Colors used when the running program hasn't overridden them.
#[derive(Clone, Debug)]
pub struct Palette {
    /// The 16 ANSI colors: 8 normal followed by 8 bright.
    pub ansi: [Color32; 16],
    pub foreground: Color32,
    pub background: Color32,
    pub cursor: Color32,
    pub selection: Color32,
}

impl Default for Palette {
    fn default() -> Self {
        let hex = |v: u32| Color32::from_rgb((v >> 16) as u8, (v >> 8) as u8, v as u8);
        Self {
            ansi: [
                hex(0x1d1f21), hex(0xcc6666), hex(0xb5bd68), hex(0xf0c674),
                hex(0x81a2be), hex(0xb294bb), hex(0x8abeb7), hex(0xc5c8c6),
                hex(0x666666), hex(0xd54e53), hex(0xb9ca4a), hex(0xe7c547),
                hex(0x7aa6da), hex(0xc397d8), hex(0x70c0b1), hex(0xeaeaea),
            ],
            foreground: hex(0xc5c8c6),
            background: hex(0x161719),
            cursor: hex(0xc5c8c6),
            selection: hex(0x373b41),
        }
    }
}

impl Palette {
    /// Resolves a cell color. `overrides` are colors the program set with OSC 4/10/11.
    pub(crate) fn resolve(&self, color: Color, overrides: &Colors) -> Color32 {
        match color {
            Color::Spec(rgb) => to_color32(rgb),
            Color::Indexed(i) => self.indexed(i as usize, overrides),
            Color::Named(name) => self.named(name, overrides),
        }
    }

    /// The color for an index into alacritty's color table (0-255 palette, then named colors).
    pub(crate) fn indexed(&self, index: usize, overrides: &Colors) -> Color32 {
        if let Some(rgb) = overrides[index] {
            return to_color32(rgb);
        }
        match index {
            0..16 => self.ansi[index],
            16..232 => {
                let i = index - 16;
                let level = |v: usize| if v == 0 { 0 } else { (55 + v * 40) as u8 };
                Color32::from_rgb(level(i / 36), level(i / 6 % 6), level(i % 6))
            }
            232..256 => {
                let v = (8 + (index - 232) * 10) as u8;
                Color32::from_rgb(v, v, v)
            }
            _ => self.special(index),
        }
    }

    fn named(&self, name: NamedColor, overrides: &Colors) -> Color32 {
        self.indexed(name as usize, overrides)
    }

    fn special(&self, index: usize) -> Color32 {
        const DIM_BLACK: usize = NamedColor::DimBlack as usize;
        const DIM_WHITE: usize = NamedColor::DimWhite as usize;
        match index {
            i if i == NamedColor::Foreground as usize => self.foreground,
            i if i == NamedColor::Background as usize => self.background,
            i if i == NamedColor::Cursor as usize => self.cursor,
            i if i == NamedColor::BrightForeground as usize => self.foreground,
            i if i == NamedColor::DimForeground as usize => dim(self.foreground),
            DIM_BLACK..=DIM_WHITE => dim(self.ansi[index - DIM_BLACK]),
            _ => self.foreground,
        }
    }
}

pub(crate) fn dim(c: Color32) -> Color32 {
    let f = |v: u8| (v as f32 * 0.66) as u8;
    Color32::from_rgb(f(c.r()), f(c.g()), f(c.b()))
}

pub(crate) fn to_rgb(c: Color32) -> Rgb {
    Rgb { r: c.r(), g: c.g(), b: c.b() }
}

fn to_color32(rgb: Rgb) -> Color32 {
    Color32::from_rgb(rgb.r, rgb.g, rgb.b)
}
