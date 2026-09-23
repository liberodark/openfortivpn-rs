{
  pkgs ? import <nixpkgs> { },
}:

pkgs.mkShell {
  buildInputs = with pkgs; [
    rustc
    cargo
    cargo-audit
    clippy
    rustfmt
    rust-analyzer
    git
    pkg-config
  ];

  shellHook = ''
    rustfmt --edition 2024 crates/*/src/*.rs
    cargo audit
  '';

  RUST_BACKTRACE = 1;
}
