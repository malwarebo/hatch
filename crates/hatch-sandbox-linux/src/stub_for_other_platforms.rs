use crate::LinuxCapabilities;

pub fn detect_capabilities() -> LinuxCapabilities {
    LinuxCapabilities::default()
}
