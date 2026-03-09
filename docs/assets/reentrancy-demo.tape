# Argus Reentrancy Demo — VHS recording script
# Pre-build first: cargo build --release --example reentrancy_demo
# Then run: vhs docs/assets/reentrancy-demo.tape

Output docs/assets/reentrancy-demo.gif
Set Width 1000
Set Height 1300
Set FontSize 11
Set FontFamily "JetBrains Mono"
Set Theme "Catppuccin Mocha"
Set Padding 10
Set TypingSpeed 50ms
Set PlaybackSpeed 1

Type "cargo run --release --example reentrancy_demo"
Sleep 300ms
Enter

Sleep 6s

# Pause to let viewer read the output
Sleep 15s
