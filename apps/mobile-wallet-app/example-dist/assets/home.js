// built screen chunk (example)
const HONESTY_COPY = "Reference prototype — UNAUDITED. Keys live in a software keystore (not hardware / StrongBox / Secure Enclave). The coin BLOCH has no value by design and is not a security. This app moves no real funds unless labelled.";
function honesty(){return h("p",{class:"honesty"},HONESTY_COPY);}
export function Home(){return h("section",{},[h("h1",{},"Balance (read via /rpc)"),honesty()]);}
