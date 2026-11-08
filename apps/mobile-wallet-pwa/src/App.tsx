import { useState } from "react";
import { TopBanner } from "./components";
import BalanceScreen from "./screens/BalanceScreen";
import ReceiveScreen from "./screens/ReceiveScreen";
import SendScreen from "./screens/SendScreen";
import ApproveScreen from "./screens/ApproveScreen";
import KeysScreen from "./screens/KeysScreen";
import AboutScreen from "./screens/AboutScreen";

type Tab = "balance" | "receive" | "send" | "approve" | "keys" | "about";

const TABS: { id: Tab; glyph: string; label: string }[] = [
  { id: "balance", glyph: "◈", label: "Balance" },
  { id: "receive", glyph: "↓", label: "Receive" },
  { id: "send", glyph: "↑", label: "Send" },
  { id: "approve", glyph: "✍", label: "Approve" },
  { id: "keys", glyph: "🔑", label: "Keys" },
  { id: "about", glyph: "ⓘ", label: "About" },
];

export default function App() {
  const [tab, setTab] = useState<Tab>("balance");

  return (
    <div className="phone" role="application" aria-label="Bloch mobile wallet reference prototype">
      <div className="appbar">
        <div className="brand">
          <div className="coin" aria-hidden="true">
            ß
          </div>
          <div>
            <div className="name">Postern Wallet</div>
            <div className="sub">ownerless base chain · PWA</div>
          </div>
        </div>
      </div>

      <TopBanner />

      <div className="screens">
        {tab === "balance" && <BalanceScreen />}
        {tab === "receive" && <ReceiveScreen />}
        {tab === "send" && <SendScreen />}
        {tab === "approve" && <ApproveScreen />}
        {tab === "keys" && <KeysScreen />}
        {tab === "about" && <AboutScreen />}
      </div>

      <nav className="tabbar" role="tablist" aria-label="Wallet sections">
        {TABS.map((t) => (
          <button
            key={t.id}
            className="tab"
            role="tab"
            aria-selected={tab === t.id}
            onClick={() => setTab(t.id)}
          >
            <span className="tg" aria-hidden="true">
              {t.glyph}
            </span>
            {t.label}
          </button>
        ))}
      </nav>
    </div>
  );
}
