let
    pkgs = import <nixpkgs> {};
in
    { stdenv ? pkgs.stdenv }:

    stdenv.mkDerivation {
        name = "C3I";
        buildInputs = [
            pkgs.python3
            pkgs.python36Packages.scapy
        ];
    }
