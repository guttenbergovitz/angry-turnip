{
  description = "Angry Turnip (atnp) - Vulnerability scanner for JavaScript/TypeScript, Python, Rust, PHP, Go, and Java projects";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};

        version = if (self ? rev) then self.rev else "dev";

      in
      {
        packages.default = pkgs.buildGoModule {
          pname = "atnp";
          version = version;

          src = ./.;

          vendorHash = "sha256-/w/xyWnf/+aOmicu6K9AelN4D5QIPN7+SYwXyJ1lBsM=";

          ldflags = [
            "-X github.com/guttenbergovitz/angry-turnip/internal/version.Version=${version}"
            "-X github.com/guttenbergovitz/angry-turnip/internal/version.Commit=${version}"
            "-X github.com/guttenbergovitz/angry-turnip/internal/version.Date=1970-01-01T00:00:00Z"
          ];

          subPackages = [ "cmd/atnp" ];

          meta = with pkgs.lib; {
            description = "Angry Turnip (atnp) - Vulnerability scanner for JavaScript/TypeScript, Python, Rust, PHP, Go, and Java projects";
            homepage = "https://github.com/guttenbergovitz/angry-turnip";
            license = licenses.mit;
            maintainers = [ ];
          };
        };

        # Development shell with all tools
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            go_1_27
            go-task
            git
          ];

          shellHook = ''
            echo "Angry Turnip (atnp) development environment"
            echo "Go version: $(go version)"
            echo "Task version: $(task --version)"
          '';
        };

        # Apps for nix run
        apps.default = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/atnp";
        };
      }
    );
}
