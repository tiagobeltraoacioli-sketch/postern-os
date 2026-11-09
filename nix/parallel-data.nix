{ lib, stdenvNoCC, python3, makeWrapper }:

stdenvNoCC.mkDerivation {
  pname = "postern-parallel-data";
  version = "0.1.0";
  src = ../tools/parallel-data;
  nativeBuildInputs = [ python3 makeWrapper ];
  doCheck = true;

  checkPhase = ''
    runHook preCheck
    ${python3.interpreter} -m unittest discover -s tests -v
    runHook postCheck
  '';

  installPhase = ''
    runHook preInstall
    mkdir -p $out/lib/postern-data $out/bin $out/share/doc/postern-parallel-data
    cp postern_data.py benchmark.py $out/lib/postern-data/
    cp README.md $out/share/doc/postern-parallel-data/
    makeWrapper ${python3.interpreter} $out/bin/postern-data \
      --add-flags "$out/lib/postern-data/postern_data.py"
    makeWrapper ${python3.interpreter} $out/bin/postern-data-benchmark \
      --add-flags "$out/lib/postern-data/benchmark.py"
    runHook postInstall
  '';

  meta = with lib; {
    description = "Offline deterministic integrity manifests with bounded parallel hashing";
    license = licenses.mit;
    mainProgram = "postern-data";
    platforms = platforms.unix;
  };
}
