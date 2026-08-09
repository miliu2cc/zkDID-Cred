{ pkgs, lib, config, inputs, ... }:

{
  # zkDID-Cred: DID + Verifiable Credentials + zk-SNARK selective disclosure.
  # Hardhat, React, TypeScript, circom/snarkjs and benchmark scripts all run from this shell.
  env.PROJECT_NAME = "zkDID-Cred";
  env.HARDHAT_NETWORK = "localhost";

  # https://devenv.sh/languages/
  languages.javascript = {
    enable = true;
    package = pkgs.nodejs_24;
    pnpm.enable = true;
  };

  languages.python = {
    enable = true;
    package = pkgs.python312;
  };

  # Project npm dependencies should still live in package.json. Keep global tools here
  # limited to compilers, CLIs and utilities needed before dependencies are installed.
  packages = with pkgs; [
    circom
    git
    jq
    prettier
    openssl
    pkg-config
    solc
    wasm-pack

    /*(python312.withPackages (ps: with ps; [
      matplotlib
      numpy
      pandas
      scipy
      scikit-learn
    ]))*/
  ];

  scripts.versions.exec = ''
    echo "Project: $PROJECT_NAME"
    node --version
    pnpm --version
    circom --version
    solc --version
  '';

  scripts.check-format.exec = ''
    prettier --check "**/*.{js,jsx,ts,tsx,json,md,sol,circom}" --ignore-path .gitignore
  '';

  enterShell = ''
    echo "Entered $PROJECT_NAME development shell"
    echo "Run 'versions' to inspect tool versions. Install JS dependencies with 'pnpm install' once package.json is created."
  '';

  enterTest = ''
    versions
  '';

  # See full reference at https://devenv.sh/reference/options/
}
