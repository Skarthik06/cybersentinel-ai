import { useState } from "react";
import LandingPage from "./CyberSentinel_Landing";
import SOCDashboard from "./CyberSentinel_Dashboard";

export default function App() {
  const [view, setView] = useState("landing");

  return (
    <>
      {/* Floating nav pill to switch between Landing and Dashboard */}
      <div style={{
        position: "fixed", bottom: 24, left: "50%", transform: "translateX(-50%)",
        zIndex: 9999, display: "flex", gap: 4,
        background: "rgba(5,13,21,0.95)", border: "1px solid rgba(79,195,247,0.2)",
        borderRadius: 50, padding: "4px 6px",
        boxShadow: "0 8px 32px rgba(0,0,0,0.5)",
        backdropFilter: "blur(20px)",
      }}>
        {[["landing","🌐 Landing Page"],["dashboard","📊 SOC Dashboard"]].map(([v,l]) => (
          <button key={v} onClick={() => setView(v)} style={{
            padding: "8px 20px", border: "none", borderRadius: 50,
            background: view === v ? "#1565C0" : "transparent",
            color: view === v ? "#fff" : "#546E7A",
            fontFamily: "'Share Tech Mono', monospace", fontSize: 12, letterSpacing: 1,
            cursor: "pointer", transition: "all 0.2s",
          }}>{l}</button>
        ))}
      </div>
      {view === "landing" ? <LandingPage /> : <SOCDashboard />}
    </>
  );
}
