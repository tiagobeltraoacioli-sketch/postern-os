import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import "./styles.css";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);

// Register the offline-shell service worker (same-origin, app scope only).
if ("serviceWorker" in navigator) {
  window.addEventListener("load", () => {
    navigator.serviceWorker.register("sw.js", { scope: "/apps/mobile-wallet-pwa/" }).catch(() => {
      /* offline shell is an enhancement; app still runs without it */
    });
  });
}
