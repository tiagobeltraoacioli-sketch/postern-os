/* ===========================================================================
   Postern Mobile — pure wallet core (ESM)
   ---------------------------------------------------------------------------
   EXTRACTED VERBATIM (build-time) from apps/mobile-wallet index.html
   <script id="wallet-core">. DOM-free + deterministic: SHA3-256, JSON-RPC
   request builders / u64 parser, amount math, WYSIWYS render, address checks.

   The crypto is NOT reinvented here — the real hybrid post-quantum signing
   lives in the WASM core (bloch_wallet_wasm.wasm) + wallet-live.js. This
   module is only the pure, host-testable helpers the PWA shell needs.
   Faithfulness is guarded by test/wallet-core.test.mjs (NIST SHA3 vectors +
   byte-identical JSON-RPC bodies).
   =========================================================================== */
const WALLET = (function () {
  const root = {};
  (function (root) {
"use strict";

  // ── SHA3-256 (Keccak-f[1600]) ──────────────────────────────────────────
  const RC=[[0,1],[0,0x8082],[0x80000000,0x808a],[0x80000000,0x80008000],
    [0,0x808b],[0,0x80000001],[0x80000000,0x80008081],[0x80000000,0x8009],
    [0,0x8a],[0,0x88],[0,0x80008009],[0,0x8000000a],
    [0,0x8000808b],[0x80000000,0x8b],[0x80000000,0x8089],[0x80000000,0x8003],
    [0x80000000,0x8002],[0x80000000,0x80],[0,0x800a],[0x80000000,0x8000000a],
    [0x80000000,0x80008081],[0x80000000,0x8080],[0,0x80000001],[0x80000000,0x80008008]];
  const R=[0,1,62,28,27,36,44,6,55,20,3,10,43,25,39,41,45,15,21,8,18,2,61,56,14];
  function rotl(hi,lo,n){
    n&=63;
    if(n===0)return[hi>>>0,lo>>>0];
    if(n===32)return[lo>>>0,hi>>>0];
    if(n<32)return[((hi<<n)|(lo>>>(32-n)))>>>0,((lo<<n)|(hi>>>(32-n)))>>>0];
    n-=32;
    return[((lo<<n)|(hi>>>(32-n)))>>>0,((hi<<n)|(lo>>>(32-n)))>>>0];
  }
  function keccakf(sh,sl){
    const Ch=new Array(5),Cl=new Array(5),Dh=new Array(5),Dl=new Array(5),Bh=new Array(25),Bl=new Array(25);
    for(let round=0;round<24;round++){
      for(let x=0;x<5;x++){Ch[x]=sh[x]^sh[x+5]^sh[x+10]^sh[x+15]^sh[x+20];Cl[x]=sl[x]^sl[x+5]^sl[x+10]^sl[x+15]^sl[x+20];}
      for(let x=0;x<5;x++){const r=rotl(Ch[(x+1)%5],Cl[(x+1)%5],1);Dh[x]=Ch[(x+4)%5]^r[0];Dl[x]=Cl[(x+4)%5]^r[1];}
      for(let x=0;x<5;x++)for(let y=0;y<5;y++){const i=x+5*y;sh[i]^=Dh[x];sl[i]^=Dl[x];}
      for(let x=0;x<5;x++)for(let y=0;y<5;y++){const i=x+5*y;const ni=y+5*((2*x+3*y)%5);const r=rotl(sh[i],sl[i],R[i]);Bh[ni]=r[0];Bl[ni]=r[1];}
      for(let x=0;x<5;x++)for(let y=0;y<5;y++){const i=x+5*y;sh[i]=Bh[i]^((~Bh[(x+1)%5+5*y])&Bh[(x+2)%5+5*y]);sl[i]=Bl[i]^((~Bl[(x+1)%5+5*y])&Bl[(x+2)%5+5*y]);}
      sh[0]^=RC[round][0];sl[0]^=RC[round][1];
    }
  }
  function sha3_256(msg){
    const rate=136;const sh=new Array(25).fill(0),sl=new Array(25).fill(0);
    const len=msg.length;const padded=new Uint8Array(Math.ceil((len+1)/rate)*rate);
    padded.set(msg);padded[len]^=0x06;padded[padded.length-1]^=0x80;
    for(let off=0;off<padded.length;off+=rate){
      for(let i=0;i<rate/8;i++){
        const j=off+i*8;
        const lo=(padded[j])|(padded[j+1]<<8)|(padded[j+2]<<16)|(padded[j+3]<<24);
        const hi=(padded[j+4])|(padded[j+5]<<8)|(padded[j+6]<<16)|(padded[j+7]<<24);
        sl[i]^=lo>>>0;sh[i]^=hi>>>0;
      }
      keccakf(sh,sl);
    }
    const out=new Uint8Array(32);
    for(let i=0;i<4;i++){
      const lo=sl[i]>>>0,hi=sh[i]>>>0;
      out[i*8]=lo&0xff;out[i*8+1]=(lo>>>8)&0xff;out[i*8+2]=(lo>>>16)&0xff;out[i*8+3]=(lo>>>24)&0xff;
      out[i*8+4]=hi&0xff;out[i*8+5]=(hi>>>8)&0xff;out[i*8+6]=(hi>>>16)&0xff;out[i*8+7]=(hi>>>24)&0xff;
    }
    return out;
  }

  // ── byte / hex helpers ─────────────────────────────────────────────────
  const enc = (typeof TextEncoder!=="undefined") ? new TextEncoder() : { encode:s=>Uint8Array.from(Buffer.from(s,"utf8")) };
  function utf8(s){ return enc.encode(s); }
  function toHex(b){ let s=""; for(let i=0;i<b.length;i++) s+=b[i].toString(16).padStart(2,"0"); return s; }
  function concat(){ let n=0; for(const a of arguments) n+=a.length; const o=new Uint8Array(n); let k=0; for(const a of arguments){o.set(a,k);k+=a.length;} return o; }

  // ── JSON-RPC seam (byte-identical to bloch-mobile core builders) ────────
  // rpc_request => {"jsonrpc":"2.0","id":1,"method":M,"params":P}
  function rpcRequest(method, params){
    return JSON.stringify({ jsonrpc:"2.0", id:1, method:method, params:params });
  }
  function getbalanceRequest(address){ return rpcRequest("getbalance",[address]); }
  function getblockcountRequest(){ return rpcRequest("getblockcount",[]); }
  function sendrawtransactionRequest(signedTxHex){ return rpcRequest("sendrawtransaction",[signedTxHex]); }
  // parse_u64_result: reject on non-null error; accept result int OR result.balance.
  function parseU64Result(responseJson){
    const v = JSON.parse(responseJson);
    if(v && v.error!==undefined && v.error!==null) throw new Error("rpc error: "+JSON.stringify(v.error));
    const r = v ? v.result : undefined;
    if(typeof r==="number" && Number.isFinite(r)) return r;
    if(r && typeof r.balance==="number") return r.balance;
    throw new Error("no u64 result");
  }

  // ── amount formatting (sats <-> BLOCH; 1 BLOCH = 1e8 sats) ──────────────
  const SATS = 100000000;
  function fmtCoins(sats){
    const neg = sats<0; sats=Math.abs(sats);
    const whole = Math.floor(sats/SATS);
    const frac = String(sats%SATS).padStart(8,"0");
    return (neg?"-":"")+whole.toLocaleString("en-US")+"."+frac;
  }
  // parse a decimal BLOCH string -> integer sats (fail-closed on junk)
  function parseCoins(str){
    const s=String(str).trim();
    if(!/^\d+(\.\d{0,8})?$/.test(s)) throw new Error("amount must be a number with up to 8 decimals");
    const [w,f=""]=s.split(".");
    // Compute in BigInt so an oversized input never silently loses IEEE-754
    // precision (which would show/sign a DIFFERENT amount than was typed).
    // Range-check against a safe integer before returning a Number — fail
    // closed on overflow instead of quietly corrupting the amount.
    const sats = BigInt(w)*BigInt(SATS) + BigInt((f+"00000000").slice(0,8));
    if(sats > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error("amount is too large to represent safely");
    return Number(sats);
  }

  // ── WYSIWYS ─────────────────────────────────────────────────────────────
  const Tier = { SilentReadOnly:"SilentReadOnly", SingleTap:"SingleTap", ExplicitReview:"ExplicitReview" };
  const TIER_HEADLINE = {
    SilentReadOnly:"Read-only — no signature, no key use.",
    SingleTap:"Low-stakes — this signature can't move funds.",
    ExplicitReview:"Irreversible — review carefully before you confirm."
  };
  // confirmation fragment = SHA3-256("postern:approval-fragment:v1" ‖ session ‖ nonce)[..3]
  // session: Uint8Array/array (SessionId bytes); nonce: 32 bytes.
  function confirmationFragment(sessionBytes, nonceBytes){
    const d = sha3_256(concat(utf8("postern:approval-fragment:v1"), Uint8Array.from(sessionBytes), Uint8Array.from(nonceBytes)));
    return toHex(d.subarray(0,3)); // 6 hex chars
  }

  // Decode a SignPayload {type:"login"|"transfer", ...} into a WYSIWYS render.
  // Mirrors integration/signer-protocol wysiwys::render (pure, deterministic).
  // Throws WalletError for a payload the phone cannot honestly display (fail-closed).
  function WalletError(kind,msg){ const e=new Error(msg); e.kind=kind; return e; }

  function deriveTier(payload){
    if(!payload || typeof payload!=="object") throw WalletError("Undecodable","request did not decode to a payload");
    if(payload.type==="login")    return Tier.SingleTap;
    if(payload.type==="transfer") return Tier.ExplicitReview;
    throw WalletError("Undecodable","unknown payload type: "+String(payload.type));
  }

  // Reduce a decoded transfer to a single-recipient intent. Fail-closed:
  // a multi-output transfer cannot be honestly shown on a one-recipient card.
  function toTransferIntent(tx){
    if(!tx || !Array.isArray(tx.outputs)) throw WalletError("Undecodable","transfer has no outputs");
    if(tx.outputs.length===0) throw WalletError("NoOutputs","transaction has no outputs");
    if(tx.outputs.length>1) throw WalletError("MultiOutput","multi-output transaction ("+tx.outputs.length+" outputs) is not representable as a single-recipient transfer; refusing rather than under-displaying");
    const o = tx.outputs[0];
    return { to_address:o.recipient, amount_sats:o.value_sats, fee_sats:(tx.declared_fee_sats??null), chain:tx.chain, input_count:(tx.input_count??0) };
  }

  function render(payload, opts){
    opts = opts||{};
    const tier = deriveTier(payload);
    let sentence, can_move_funds, disclosures=[];
    if(payload.type==="login"){
      sentence = 'This signs a login challenge for "'+payload.user+'" at "'+payload.org+'". '+
                 "It proves you hold the wallet key — it can't move funds.";
      can_move_funds = false;
    } else {
      const it = toTransferIntent(payload);
      // SECURITY: the displayed network MUST come from this wallet's own local
      // state, never from the (possibly adversarial) request payload — a
      // malicious phone-as-signer peer must not be able to make a mainnet
      // signature look like a harmless testnet one, or vice versa. Fail
      // closed if the caller didn't supply it, rather than silently trusting
      // it.chain (payload-supplied) as earlier code mistakenly did.
      if(opts.wallet_chain!=="testnet" && opts.wallet_chain!=="mainnet"){
        throw WalletError("Undecodable","caller did not supply this wallet's network (wallet_chain) — refusing to trust a request-supplied chain for display");
      }
      const chain = opts.wallet_chain;
      sentence = "This moves "+fmtCoins(it.amount_sats)+" BLOCH to "+it.to_address+
                 " (fee "+(it.fee_sats==null?"unstated":fmtCoins(it.fee_sats)+" BLOCH")+", "+chain+"). "+
                 "A signature spends irreversibly — this cannot be undone.";
      can_move_funds = true;
      disclosures.push("Fee is NOT verifiable from the transaction bytes (inputs carry no amounts) — the "+
                       (it.fee_sats==null?"fee is unstated":"declared fee is shown as-is")+" and treated as unverifiable.");
      disclosures.push("Network is taken from THIS wallet ("+chain+"), not from the request — the tx format folds chain-id into the sighash, not the visible bytes.");
    }
    disclosures.push("Signature is hybrid post-quantum Falcon-1024 ‖ ML-DSA-65. In this prototype no real signature is computed — the software keystore is not hardware-backed.");
    return {
      tier, headline:TIER_HEADLINE[tier], sentence, can_move_funds,
      peer_device: opts.peer_device||"unknown device",
      confirmation_fragment: confirmationFragment(opts.session||[], opts.nonce||new Uint8Array(32)),
      disclosures
    };
  }

  // ── receive-fallback helpers ────────────────────────────────────────────
  // Split an address into numbered groups for manual, position-by-position check.
  function groupAddress(addr, size){
    size = size||4;
    const groups=[];
    for(let i=0;i<addr.length;i+=size) groups.push(addr.slice(i,i+size));
    return groups;
  }
  // 11x11 visual fingerprint cells (booleans) derived from SHA3 of the address.
  function fingerprintCells(addr){
    const d = sha3_256(utf8(addr));
    const cells=[]; // 11 rows x 11 cols, mirrored left-right for a stable glyph
    for(let y=0;y<11;y++){
      const row=[];
      for(let x=0;x<6;x++){
        const bitIx=y*6+x;
        const on=((d[bitIx%32]>>(bitIx%8))&1)===1;
        row[x]=on;
      }
      for(let x=6;x<11;x++) row[x]=row[10-x];
      cells.push(row);
    }
    return cells;
  }

  // ── address validation (fail-closed shape check) ─────────────────────────
  // The SEND flow previously only checked the recipient field was non-empty,
  // so arbitrary/malformed text could pass through "Review & sign" and be
  // rendered verbatim in the WYSIWYS sentence. Real address-format validation
  // belongs to Bloch core's address encoder (the address SHAPE here is
  // illustrative, per the in-app disclosure), but this baseline check keeps
  // the send flow honest about the shape it itself generates, and refuses
  // (fail-closed) rather than silently accepting junk — same discipline as
  // parseCoins and the multi-output refusal.
  const ADDR_BODY_CHARS = "0123456789abcdefghjkmnpqrstuvwxyz"; // no i,l,o
  function validateAddress(addr, testnet){
    const s = String(addr);
    if(!/^[a-z0-9]+$/.test(s)) throw new Error("contains characters outside the expected a-z0-9 charset");
    if(s.length<9 || s.length>90) throw new Error("length looks implausible for a Bloch address");
    const prefix = testnet ? "tblk1" : "blk1";
    const otherPrefix = testnet ? "blk1" : "tblk1";
    if(s.startsWith(otherPrefix) && !s.startsWith(prefix)){
      throw new Error("prefix is for the other network — this wallet is on "+(testnet?"testnet":"mainnet"));
    }
    if(!s.startsWith(prefix)) throw new Error('must start with "'+prefix+'" for this network');
    const body = s.slice(prefix.length);
    if(body.length<4) throw new Error("address body is too short");
    for(let i=0;i<body.length;i++){
      if(ADDR_BODY_CHARS.indexOf(body[i])===-1) throw new Error('invalid character "'+body[i]+'" in address body');
    }
    return true;
  }

  // ── illustrative (NOT real) wallet material for the demo ────────────────
  // Clearly labeled everywhere in the UI as illustrative. No real entropy/keys.
  const WORDS = ("anchor amber apple auburn basin beacon birch bishop cinder cobalt copper cove "+
    "delta ember fable falcon fern forge glacier granite harbor hazel indigo ivory "+
    "jasper kelp lagoon lattice marble meadow mica nomad nova onyx opal orbit "+
    "pebble pewter quartz quill raven reef sable saffron slate spruce timber topaz "+
    "umber vellum verde walnut willow xenon yarrow zephyr").split(" ");
  function demoMnemonic(seedHex, count){
    count=count||12;
    const d = sha3_256(utf8("demo-mnemonic:"+seedHex));
    const out=[];
    for(let i=0;i<count;i++) out.push(WORDS[d[i]%WORDS.length]);
    return out;
  }
  // illustrative address SHAPE (labeled illustrative in-app). prefix by network.
  function demoAddress(seedHex, index, testnet){
    const d = sha3_256(utf8("demo-addr:"+seedHex+":"+index));
    const b32 = "0123456789abcdefghjkmnpqrstuvwxyz"; // no i,l,o (illustrative shape)
    let body=""; for(let i=0;i<38;i++) body+=b32[d[i%32]%b32.length];
    return (testnet?"tblk1":"blk1")+body;
  }
  function demoPubKey(seedHex){
    const a=sha3_256(utf8("demo-pk-a:"+seedHex)), b=sha3_256(utf8("demo-pk-b:"+seedHex));
    return toHex(a)+toHex(b); // illustrative hybrid pubkey bytes
  }

  root.WALLET = {
    sha3_256, toHex, utf8, concat,
    rpcRequest, getbalanceRequest, getblockcountRequest, sendrawtransactionRequest, parseU64Result,
    SATS, fmtCoins, parseCoins, validateAddress,
    Tier, TIER_HEADLINE, confirmationFragment, deriveTier, toTransferIntent, render,
    groupAddress, fingerprintCells,
    demoMnemonic, demoAddress, demoPubKey, WORDS
  };
  })(root);
  return root.WALLET;
})();

export default WALLET;
