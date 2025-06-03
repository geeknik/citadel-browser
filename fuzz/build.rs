fn main() {
    // Only enable fuzzing on Linux
    #[cfg(target_os = "linux")]
    println!("cargo:rustc-cfg=fuzzing");

    // Print helpful message on non-Linux platforms
    #[cfg(not(target_os = "linux"))]
    eprintln!("Note: Fuzzing is only supported on Linux. Use Docker for fuzzing on other platforms.");
} 