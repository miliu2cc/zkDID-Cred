{ pkgs, lib, config, ... }:

{
  # zkDID-Cred: DID + Verifiable Credentials + zk-SNARK 选择性披露
  # 技术栈：Rust + Noir + Foundry + Tauri

  env.PROJECT_NAME = "zkDID-Cred";
  env.RUST_BACKTRACE = "1";

  # https://devenv.sh/languages/

  # Rust - 核心语言
  languages.rust = {
    enable = true;
    channel = "stable";
    components = [ "rustc" "cargo" "clippy" "rustfmt" "rust-analyzer" ];
  };

  # Node.js - Tauri 前端 / 脚本工具
  languages.javascript = {
    enable = true;
    package = pkgs.nodejs_22;
    pnpm.enable = true;
  };

  # Solidity + Foundry（forge / cast / anvil）
  languages.solidity = {
    enable = true;
    foundry.enable = true;
  };

  # 系统依赖：构建工具 + Tauri（webkitgtk/gtk）
  packages = with pkgs; [
    git
    jq
    openssl
    pkg-config
    cmake
    gnumake

    # Tauri 依赖
    webkitgtk_4_1
    gtk3
    libsoup_3
    libayatana-appindicator
    librsvg
  ];

  # https://devenv.sh/scripts/
  scripts = {
    # ---- 环境 ----
    versions.exec = ''
      echo "=== zkDID-Cred 工具版本 ==="
      echo "Rust:    $(rustc --version 2>/dev/null || echo '未安装')"
      echo "Cargo:   $(cargo --version 2>/dev/null || echo '未安装')"
      echo "Node:    $(node --version 2>/dev/null || echo '未安装')"
      echo "nargo:   $(command -v nargo >/dev/null 2>&1 && nargo --version || echo '未安装（setup-noir）')"
      echo "bb:      $(command -v bb >/dev/null 2>&1 && bb --version || echo '未安装（setup-bb）')"
      echo "forge:   $(command -v forge >/dev/null 2>&1 && forge --version || echo '未安装')"
      echo "tauri:   $(command -v tauri >/dev/null 2>&1 && tauri --version || echo '未安装（setup-tauri）')"
    '';

    # ---- 工具安装 ----
    setup-noir.exec = ''
      if command -v nargo >/dev/null 2>&1; then
        echo "nargo 已安装: $(nargo --version)"
      else
        echo "安装 nargo（noirup）..."
        curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash
        export PATH="$HOME/.nargo/bin:$PATH"
        noirup
      fi
    '';

    setup-bb.exec = ''
      if command -v bb >/dev/null 2>&1; then
        echo "bb 已安装: $(bb --version)"
      else
        echo "安装 bb（bbup）..."
        curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/refs/heads/next/barretenberg/bbup/install | bash
        export PATH="$HOME/.bb:$PATH"
        bbup
      fi
    '';

    setup-tauri.exec = ''
      if command -v tauri >/dev/null 2>&1; then
        echo "tauri-cli 已安装: $(tauri --version)"
      else
        echo "安装 tauri-cli（cargo install，需几分钟）..."
        cargo install tauri-cli --locked
      fi
    '';

    # ---- Rust ----
    build-rust.exec = "cargo build --workspace";
    test-rust.exec = "cargo test --workspace";
    fmt-rust.exec = "cargo fmt --all";
    lint-rust.exec = "cargo clippy --workspace -- -D warnings";
    check.exec = ''
      echo "[1/3] 格式检查"; cargo fmt --all --check
      echo "[2/3] Clippy"; cargo clippy --workspace -- -D warnings
      echo "[3/3] 测试"; cargo test --workspace
      echo "✓ 全部通过"
    '';

    # ---- 电路 / 合约 ----
    test-circuits.exec = "cd circuits && nargo test";
    test-contracts.exec = "cd contracts && forge test";
    anvil.exec = "anvil";

    # ---- 演示（对应 quickstart）----
    zkp-demo.exec = ''
      export PATH="$HOME/.nargo/bin:$HOME/.bb:$PATH"
      cargo run -p zkdid-core --example zkp_demo
    '';
    blockchain-demo.exec = "cargo run -p blockchain --example registry_demo";

    # ---- Tauri ----
    dev-tauri.exec = ''
      if ! command -v tauri >/dev/null 2>&1; then
        echo "tauri-cli 未安装，请先运行 setup-tauri"
        exit 1
      fi
      cd holder-app && tauri dev
    '';
    build-tauri.exec = ''
      if ! command -v tauri >/dev/null 2>&1; then
        echo "tauri-cli 未安装，请先运行 setup-tauri"
        exit 1
      fi
      cd holder-app && tauri build
    '';
  };

  # https://devenv.sh/pre-commit-hooks/
  pre-commit.hooks = {
    rustfmt.enable = true;
    clippy.enable = true;
  };

  enterShell = ''
    export PATH="$HOME/.nargo/bin:$HOME/.bb:$HOME/.cargo/bin:$PATH"

    cat << "EOF"

    ╔══════════════════════════════════════════════════════════════╗
    ║           zkDID-Cred 开发环境                               ║
    ║   DID + Verifiable Credentials + zk-SNARK 选择性披露         ║
    ╚══════════════════════════════════════════════════════════════╝

    环境：        versions
    工具安装：    setup-noir / setup-bb / setup-tauri

    Rust：        build-rust / test-rust / fmt-rust / lint-rust / check
    电路：        test-circuits
    合约：        test-contracts / anvil
    演示：        zkp-demo / blockchain-demo（需先 anvil）
    Tauri：       dev-tauri / build-tauri

    详见 docs/quickstart.md
    EOF
  '';
}
