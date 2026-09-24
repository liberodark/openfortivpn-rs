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
  ];

  shellHook = ''
    cargo fmt --all
    cargo audit
  '';

  RUST_BACKTRACE = 1;
}
