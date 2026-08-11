{ pkgs, lib, config, inputs, ... }:

{
  # zkDID-Cred: DID + Verifiable Credentials + zk-SNARK selective disclosure
  # Tech Stack: Rust + Noir + Foundry + Tauri
  # Architecture: DID Module + VC Module + ZK Proofs (Noir) + Smart Contracts (Foundry)

  env.PROJECT_NAME = "zkDID-Cred";
  env.RUST_BACKTRACE = "1";
  env.FOUNDRY_PROFILE = "default";

  # https://devenv.sh/languages/

  # Rust - Core language for the entire project
  languages.rust = {
    enable = true;
    channel = "stable";
    components = [ "rustc" "cargo" "clippy" "rustfmt" "rust-analyzer" ];
  };

  # JavaScript/Node.js - For Foundry tests, Tauri frontend, and tooling
  languages.javascript = {
    enable = true;
    package = pkgs.nodejs_22;  # LTS version
    pnpm.enable = true;
  };

  # Nix packages - Development tools and dependencies
  packages = with pkgs; [
    # === Core Development Tools ===
    git
    jq
    openssl
    pkg-config

    # === Rust Development ===
    cargo-watch      # Auto-rebuild on file changes
    cargo-expand     # Macro expansion debugging
    cargo-audit      # Security vulnerability scanner

    # === ZK Circuits (Noir) ===
    # Note: Noir (nargo) needs to be installed via cargo or from source
    # We'll add it as a manual step since it's not in nixpkgs yet

    # === Smart Contracts (Foundry) ===
    # Foundry suite: forge, cast, anvil, chisel
    # Note: Foundry needs foundryup or cargo install, adding placeholder
    foundry

    # === Blockchain Development ===
    solc             # Solidity compiler (backup, Foundry includes it)

    # === Tauri Dependencies ===
    # Linux-specific dependencies for Tauri
    webkitgtk_4_1    # WebView backend for Linux
    gtk3             # GTK3 for native UI
    libsoup_3        # HTTP library
    libayatana-appindicator  # System tray support

    # === Build Tools ===
    cmake
    gnumake

    # === Database (for local credential storage) ===
    sqlite

    # === Optional: Android Development ===
    # android-tools  # adb, fastboot (uncomment if building for Android)

    # === Code Quality ===
    prettier         # Code formatter (for JS/TS/JSON)
  ];

  # https://devenv.sh/scripts/
  scripts = {
    # Version check script
    versions.exec = ''
      echo "========================================"
      echo "  $PROJECT_NAME Development Environment"
      echo "========================================"
      echo ""
      echo "Core Tools:"
      echo "  Rust:    $(rustc --version)"
      echo "  Cargo:   $(cargo --version)"
      echo "  Node.js: $(node --version)"
      echo "  pnpm:    $(pnpm --version)"
      echo ""
      echo "Compilers:"
      echo "  Solidity: $(solc --version | head -n 1)"
      echo ""
      echo "Check installation status:"
      echo "  Nargo (Noir):   $(command -v nargo >/dev/null 2>&1 && nargo --version || echo 'NOT INSTALLED')"
      echo "  Forge (Foundry): $(command -v forge >/dev/null 2>&1 && forge --version || echo 'NOT INSTALLED')"
      echo "  Cast (Foundry):  $(command -v cast >/dev/null 2>&1 && cast --version || echo 'NOT INSTALLED')"
      echo "  Anvil (Foundry): $(command -v anvil >/dev/null 2>&1 && anvil --version || echo 'NOT INSTALLED')"
      echo ""
      echo "Run 'setup-tools' to install Noir and Foundry if not present."
      echo "========================================"
    '';

    # Setup additional tools not in nixpkgs
    install-noir.exec = ''
      echo "Install Noir (nargo)"

      # Install Noir (nargo) if not present
      if ! command -v nargo &> /dev/null; then
        echo "Installing Noir (nargo)..."
        echo "Downloading noirup installer..."
        curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash

        # Add to PATH for current session
        export PATH="$HOME/.nargo/bin:$PATH"

        noirup --version nightly
      else
        echo "✓ Nargo already installed: $(nargo --version)"
      fi

      echo ""



      echo ""
      echo "========================================"
      echo "✓ Tool setup complete!"
      echo ""
      echo "IMPORTANT: Add these to your shell profile (~/.bashrc or ~/.zshrc):"
      echo "  export PATH=\"\$HOME/.nargo/bin:\$PATH\""
      echo "  export PATH=\"\$HOME/.foundry/bin:\$PATH\""
      echo ""
      echo "Then run 'source ~/.bashrc' (or restart your shell)"
      echo "========================================"
    '';

    # Build all Rust workspaces
    build-rust.exec = ''
      echo "Building Rust workspace..."
      cargo build --workspace
    '';

    # Run all Rust tests
    test-rust.exec = ''
      echo "Running Rust tests..."
      cargo test --workspace
    '';

    # Format Rust code
    fmt-rust.exec = ''
      echo "Formatting Rust code..."
      cargo fmt --all
    '';

    # Lint Rust code
    lint-rust.exec = ''
      echo "Linting Rust code..."
      cargo clippy --workspace -- -D warnings
    '';

    # Compile Noir circuits
    compile-circuits.exec = ''
      if [ -d "circuits" ]; then
        echo "Compiling Noir circuits..."
        cd circuits
        nargo compile
        cd ..
      else
        echo "No circuits directory found. Run this from project root."
      fi
    '';

    # Test Noir circuits
    test-circuits.exec = ''
      if [ -d "circuits" ]; then
        echo "Testing Noir circuits..."
        cd circuits
        nargo test
        cd ..
      else
        echo "No circuits directory found."
      fi
    '';

    # Build Foundry contracts
    build-contracts.exec = ''
      if [ -d "contracts" ]; then
        echo "Building Foundry contracts..."
        cd contracts
        forge build
        cd ..
      else
        echo "No contracts directory found."
      fi
    '';

    # Test Foundry contracts
    test-contracts.exec = ''
      if [ -d "contracts" ]; then
        echo "Testing Foundry contracts..."
        cd contracts
        forge test -vvv
        cd ..
      else
        echo "No contracts directory found."
      fi
    '';

    # Run Foundry local node
    run-anvil.exec = ''
      echo "Starting Anvil (local Ethereum node)..."
      anvil
    '';

    # Build Tauri desktop app
    build-tauri.exec = ''
      if [ -d "holder-app" ]; then
        echo "Building Tauri application..."
        cd holder-app
        pnpm install
        pnpm tauri build
        cd ..
      else
        echo "No holder-app directory found."
      fi
    '';

    # Run Tauri app in dev mode
    dev-tauri.exec = ''
      if [ -d "holder-app" ]; then
        echo "Running Tauri app in dev mode..."
        cd holder-app
        pnpm tauri dev
        cd ..
      else
        echo "No holder-app directory found."
      fi
    '';

    # Full project check (format + lint + test)
    check-all.exec = ''
      echo "Running full project check..."
      echo ""
      echo "1/4 Formatting Rust..."
      cargo fmt --all --check
      echo ""
      echo "2/4 Linting Rust..."
      cargo clippy --workspace -- -D warnings
      echo ""
      echo "3/4 Testing Rust..."
      cargo test --workspace
      echo ""
      echo "4/4 Testing contracts (if present)..."
      if [ -d "contracts" ]; then
        cd contracts && forge test && cd ..
      fi
      echo ""
      echo "✓ All checks passed!"
    '';
  };

  # https://devenv.sh/pre-commit-hooks/
  pre-commit.hooks = {
    rustfmt.enable = true;
    clippy.enable = true;
  };

  # Shell initialization
  enterShell = ''
    cat << "EOF"

    ╔══════════════════════════════════════════════════════════════╗
    ║         zkDID-Cred Development Environment                   ║
    ║  DID + Verifiable Credentials + zk-SNARK (Noir)              ║
    ╚══════════════════════════════════════════════════════════════╝

    Quick Commands:
      versions          - Show tool versions
      install-noir      - Install Noir

      build-rust        - Build Rust workspace
      test-rust         - Run Rust tests
      fmt-rust          - Format Rust code
      lint-rust         - Lint Rust code

      compile-circuits  - Compile Noir circuits
      test-circuits     - Test Noir circuits

      build-contracts   - Build Foundry contracts
      test-contracts    - Test Foundry contracts
      run-anvil         - Start local Ethereum node

      build-tauri       - Build Tauri app
      dev-tauri         - Run Tauri in dev mode

      check-all         - Run all checks (format + lint + test)

    EOF

    # Auto-check if additional tools need setup
    if ! command -v nargo &> /dev/null; then
      echo "⚠️  Noir is not installed. Run 'install-noir' to install."
      echo ""
    fi
  '';

  # Test command for CI/CD
  enterTest = ''
    versions
    check-all
  '';
}
