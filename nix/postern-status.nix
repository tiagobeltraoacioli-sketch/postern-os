{ lib, stdenvNoCC, python3, makeWrapper }:

stdenvNoCC.mkDerivation {
  pname = "postern-status";
  version = "0.1.0";
  src = ../tools/postern-status;
  nativeBuildInputs = [ python3 makeWrapper ];
  doCheck = true;

  checkPhase = ''
    runHook preCheck
    ${python3.interpreter} -m unittest discover -s tests -v
    runHook postCheck
  '';

  installPhase = ''
    runHook preInstall
    mkdir -p $out/lib/postern-status $out/bin $out/share/doc/postern-status
    cp postern_status.py $out/lib/postern-status/
    cp README.md $out/share/doc/postern-status/
    makeWrapper ${python3.interpreter} $out/bin/postern-status \
      --add-flags "$out/lib/postern-status/postern_status.py"
    runHook postInstall
  '';

  meta = with lib; {
    description = "Read-only report of the observable Postern privacy baseline";
    license = with licenses; [ mit asl20 ];
    mainProgram = "postern-status";
    platforms = platforms.linux;
  };
}
