// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Postern CLOUD control plane — the persistence SEAM.
//
// STATUS: design / reference prototype, unaudited, pre-production.
//
// WHY THIS EXISTS
// ---------------
// The reference control plane kept every record in in-process Maps, so a
// restart lost all tenant/node state. That is honest for a demo but is not a
// property anyone should build on. This module turns "the store" into an
// INJECTED dependency with a tiny, explicit key/value contract, so an operator
// can wire a durable backend (a file, SQLite, a KV service, …) WITHOUT this
// package importing any database or claiming durability it does not have.
//
// The default remains [`createMemoryStore`] — volatile, and it says so
// (`durable: false`). Nothing here is a security boundary: a store an operator
// runs is as trustworthy as that operator (managed-node is "a promise, not a
// proof"). This seam adds no cryptography and provisions no infrastructure.
//
// THE CONTRACT a store must satisfy (all synchronous, string keys, any value):
//   get(key)      -> value | undefined
//   set(key, val) -> void      (write-through)
//   has(key)      -> boolean
//   delete(key)   -> boolean   (true if a value was removed)
//   keys()        -> string[]  (every key currently held)
// Keys are already tenant-namespaced by the isolation layer (`<tenantId>/…`)
// plus a reserved `__cp/…` control namespace, so a single FLAT key space is all
// a backend needs to implement.

/**
 * The volatile default: an in-memory key/value store. Identical semantics to
 * the Maps the control plane used before — but now behind the injectable
 * contract, and self-describing as NON-durable so posture can disclose it.
 *
 * @returns {import("./store.mjs").ControlPlaneStore}
 */
export function createMemoryStore() {
  const m = new Map();
  return {
    kind: "memory",
    durable: false,
    get: (k) => m.get(k),
    set: (k, v) => {
      m.set(k, v);
    },
    has: (k) => m.has(k),
    delete: (k) => m.delete(k),
    keys: () => [...m.keys()],
  };
}

/**
 * Validate that an injected object satisfies the store contract, so a broken
 * backend fails LOUDLY at construction instead of silently losing records.
 * Returns the store unchanged (with `kind`/`durable` defaulted) or throws.
 *
 * @param {any} store
 * @returns {import("./store.mjs").ControlPlaneStore}
 */
export function assertStore(store) {
  const required = ["get", "set", "has", "delete", "keys"];
  if (!store || typeof store !== "object") {
    throw new TypeError("store: an injected store must be an object implementing " + required.join("/"));
  }
  for (const m of required) {
    if (typeof store[m] !== "function") {
      throw new TypeError(`store: injected store is missing required method "${m}()"`);
    }
  }
  // An injected store is assumed durable unless it declares otherwise — an
  // operator only wires one to gain durability. Its own `durable` flag wins.
  if (typeof store.durable !== "boolean") store.durable = true;
  if (typeof store.kind !== "string") store.kind = "injected";
  return store;
}

/**
 * @typedef {object} ControlPlaneStore
 * @property {string}  kind      a short label for posture ("memory", "sqlite", …)
 * @property {boolean} durable   does state survive a process restart?
 * @property {(k:string)=>any}          get
 * @property {(k:string,v:any)=>void}   set
 * @property {(k:string)=>boolean}      has
 * @property {(k:string)=>boolean}      delete
 * @property {()=>string[]}             keys
 */

export default { createMemoryStore, assertStore };
