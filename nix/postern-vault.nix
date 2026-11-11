{ lib, stdenvNoCC, makeWrapper, bash, cryptsetup, e2fsprogs, util-linux, coreutils, gnused }:

stdenvNoCC.mkDerivation {
  pname = "postern-vault";
  version = "0.1.0";
  src = ../tools/postern-vault;
  nativeBuildInputs = [ makeWrapper ];
  doCheck = true;

  checkPhase = ''
    runHook preCheck
    ${bash}/bin/bash -n postern-vault.sh
    runHook postCheck
  '';

  installPhase = ''
    runHook preInstall
    mkdir -p $out/libexec $out/bin $out/share/doc/postern-vault
    install -m 755 postern-vault.sh $out/libexec/postern-vault
    patchShebangs $out/libexec/postern-vault
    cp README.md $out/share/doc/postern-vault/
    # Prefix only: sudo must still come from the system's setuid wrappers.
    makeWrapper $out/libexec/postern-vault $out/bin/postern-vault \
      --prefix PATH : ${lib.makeBinPath [ cryptsetup e2fsprogs util-linux coreutils gnused ]}
    runHook postInstall
  '';

  meta = with lib; {
    description = "Encrypted LUKS2 container files for private data";
    license = with licenses; [ mit asl20 ];
    mainProgram = "postern-vault";
    platforms = platforms.linux;
  };
}
