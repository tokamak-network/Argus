# Argus Sentinel Demo — VHS recording script
# Run: vhs docs/assets/demo.tape

Output docs/assets/demo.gif
Set Width 1000
Set Height 700
Set FontSize 14
Set FontFamily "JetBrains Mono"
Set Theme "Catppuccin Mocha"
Set Padding 15
Set TypingSpeed 50ms
Set PlaybackSpeed 1

# Show the command being typed
Type "cargo run --release --example sentinel_realtime_demo 2>&1 | head -50"
Sleep 300ms
Enter

# Wait for execution
Sleep 6s

# Pause to let viewer read the output
Sleep 6s
