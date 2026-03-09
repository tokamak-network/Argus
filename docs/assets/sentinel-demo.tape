# Argus Sentinel Demo — VHS recording script
# Pre-build first: cargo build --release --example sentinel_realtime_demo
# Then run: vhs docs/assets/sentinel-demo.tape

Output docs/assets/sentinel-demo.gif
Set Width 1000
Set Height 800
Set FontSize 13
Set FontFamily "JetBrains Mono"
Set Theme "Catppuccin Mocha"
Set Padding 15
Set TypingSpeed 40ms
Set PlaybackSpeed 1.5

Type "cargo run --release --example sentinel_realtime_demo 2>&1 | head -65"
Sleep 200ms
Enter

Sleep 6s

# Pause to let viewer read the output
Sleep 8s
