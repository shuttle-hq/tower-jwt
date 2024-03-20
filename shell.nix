let
  moz_overlay = import (builtins.fetchTarball https://github.com/mozilla/nixpkgs-mozilla/archive/master.tar.gz);
  # Pin to stable from https://status.nixos.org/
  nixpkgs = import (fetchTarball "https://github.com/NixOS/nixpkgs/archive/fa9f817df522ac294016af3d40ccff82f5fd3a63.tar.gz") { overlays = [ moz_overlay ]; };
in
  with nixpkgs;
  stdenv.mkDerivation {
    name = "moz_overlay_shell";
    buildInputs = with nixpkgs; [
      ((rustChannelOf{ channel = "1.76.0"; }).rust.override {
        extensions = ["rust-src"];
      })
      cargo-watch
    ];
  }
