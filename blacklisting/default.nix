let
    pkgs = import <nixpkgs> {};
in
    { stdenv ? pkgs.stdenv }:

    stdenv.mkDerivation {
        name = "C3I";
        buildInputs = [
            pkgs.python2
            pkgs.python27Packages.virtualenv
        ];
    }
