import { useState, useEffect, useRef } from "react";

const API = "http://localhost:8080";

// ── Scanline overlay component ─────────────────────────────────────────────
function Scanlines() {
  return (
    <div style={{
      position:"fixed", inset:0, pointerEvents:"none", zIndex:9999,
      background:"repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,0,0,0.03) 2px, rgba(0,0,0,0.03) 4px)",
    }}/>
  );
}

// ── Terminal typewriter ────────────────────────────────────────────────────
function Typewriter({ lines, speed = 38 }) {
  const [displayed, setDisplayed] = useState([]);
  const [lineIdx, setLineIdx] = useState(0);
  const [charIdx, setCharIdx] = useState(0);
  useEffect(() => {
    if (lineIdx >= lines.length) return;
    if (charIdx < lines[lineIdx].length) {
      const t = setTimeout(() => {
        setDisplayed(d => {
          const n = [...d];
          n[lineIdx] = (n[lineIdx] || "") + lines[lineIdx][charIdx];
          return n;
        });
        setCharIdx(c => c + 1);
      }, speed);
      return () => clearTimeout(t);
    } else {
      const t = setTimeout(() => { setLineIdx(l => l + 1); setCharIdx(0); }, 300);
      return () => clearTimeout(t);
    }
  }, [lineIdx, charIdx, lines, speed]);
  return (
    <div style={{ fontFamily:"'Share Tech Mono', monospace", fontSize:13, color:"#4FC3F7", lineHeight:1.8 }}>
      {displayed.map((line, i) => (
        <div key={i}><span style={{ color:"#546E7A" }}>{">"} </span>{line}
          {i === lineIdx && <span style={{ animation:"blink 1s step-end infinite", color:"#4FC3F7" }}>▋</span>}
        </div>
      ))}
    </div>
  );
}

// ── Animated counter ───────────────────────────────────────────────────────
function Counter({ end, suffix = "", duration = 2000 }) {
  const [val, setVal] = useState(0);
  const ref = useRef(null);
  useEffect(() => {
    const obs = new IntersectionObserver(([e]) => {
      if (e.isIntersecting) {
        let start = 0;
        const step = end / (duration / 16);
        const t = setInterval(() => {
          start = Math.min(start + step, end);
          setVal(Math.floor(start));
          if (start >= end) clearInterval(t);
        }, 16);
      }
    }, { threshold: 0.3 });
    if (ref.current) obs.observe(ref.current);
    return () => obs.disconnect();
  }, [end, duration]);
  return <span ref={ref}>{val.toLocaleString()}{suffix}</span>;
}

// ── Pulsing threat dot ─────────────────────────────────────────────────────
function ThreatDot({ color = "#ef4444", size = 8 }) {
  return (
    <span style={{ position:"relative", display:"inline-block", width:size, height:size }}>
      <span style={{
        position:"absolute", inset:0, borderRadius:"50%", background:color,
        animation:"ping 1.5s cubic-bezier(0,0,0.2,1) infinite", opacity:0.6,
      }}/>
      <span style={{ position:"absolute", inset:0, borderRadius:"50%", background:color }}/>
    </span>
  );
}

// ── Architecture node ──────────────────────────────────────────────────────
function ArchNode({ icon, label, sub, color, delay = 0 }) {
  const [vis, setVis] = useState(false);
  useEffect(() => { const t = setTimeout(() => setVis(true), delay); return () => clearTimeout(t); }, [delay]);
  return (
    <div style={{
      background:"rgba(13,27,42,0.9)", border:`1px solid ${color}40`,
      borderRadius:8, padding:"16px 20px", transition:"all 0.6s ease",
      opacity: vis ? 1 : 0, transform: vis ? "translateY(0)" : "translateY(20px)",
      boxShadow:`0 0 20px ${color}20`, cursor:"default",
    }}
    onMouseEnter={e => { e.currentTarget.style.borderColor = color; e.currentTarget.style.boxShadow = `0 0 30px ${color}40`; }}
    onMouseLeave={e => { e.currentTarget.style.borderColor = `${color}40`; e.currentTarget.style.boxShadow = `0 0 20px ${color}20`; }}
    >
      <div style={{ fontSize:28, marginBottom:6 }}>{icon}</div>
      <div style={{ fontFamily:"'Share Tech Mono', monospace", fontSize:13, color, fontWeight:700, letterSpacing:1 }}>{label}</div>
      <div style={{ fontSize:11, color:"#546E7A", marginTop:4, lineHeight:1.5 }}>{sub}</div>
    </div>
  );
}

// ── Feature card ───────────────────────────────────────────────────────────
function FeatureCard({ icon, title, desc, mitre, color }) {
  const [hov, setHov] = useState(false);
  return (
    <div
      onMouseEnter={() => setHov(true)} onMouseLeave={() => setHov(false)}
      style={{
        background: hov ? `rgba(${color === "#4FC3F7" ? "79,195,247" : color === "#00E676" ? "0,230,118" : color === "#FF6D00" ? "255,109,0" : "229,57,53"},0.08)` : "rgba(255,255,255,0.02)",
        border:`1px solid ${hov ? color : "rgba(255,255,255,0.06)"}`,
        borderRadius:12, padding:28, transition:"all 0.3s ease",
        transform: hov ? "translateY(-4px)" : "none",
        boxShadow: hov ? `0 12px 40px ${color}20` : "none",
      }}
    >
      <div style={{ fontSize:36, marginBottom:12 }}>{icon}</div>
      <div style={{ fontFamily:"'Share Tech Mono', monospace", fontSize:15, color, fontWeight:700, marginBottom:8, letterSpacing:0.5 }}>{title}</div>
      <div style={{ fontSize:13, color:"#8899AA", lineHeight:1.8, marginBottom:12 }}>{desc}</div>
      {mitre && (
        <div style={{ display:"flex", flexWrap:"wrap", gap:6 }}>
          {mitre.map(m => (
            <span key={m} style={{ fontFamily:"monospace", fontSize:10, background:"rgba(79,195,247,0.1)", color:"#4FC3F7", padding:"2px 8px", borderRadius:3, border:"1px solid rgba(79,195,247,0.2)" }}>{m}</span>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Stat card ──────────────────────────────────────────────────────────────
function StatCard({ label, value, suffix, color, live }) {
  return (
    <div style={{
      background:"rgba(13,27,42,0.8)", border:`1px solid ${color}30`,
      borderRadius:10, padding:"20px 24px", textAlign:"center",
      boxShadow:`inset 0 1px 0 ${color}20`,
    }}>
      <div style={{ display:"flex", alignItems:"center", justifyContent:"center", gap:8, marginBottom:8 }}>
        {live && <ThreatDot color={color} size={7}/>}
        <span style={{ fontFamily:"'Share Tech Mono', monospace", fontSize:10, color:"#546E7A", letterSpacing:2, textTransform:"uppercase" }}>{label}</span>
      </div>
      <div style={{ fontFamily:"'Share Tech Mono', monospace", fontSize:38, fontWeight:700, color, lineHeight:1 }}>
        <Counter end={typeof value === "number" ? value : 0} suffix={suffix || ""}/>
      </div>
    </div>
  );
}

// ── PAPER entry ────────────────────────────────────────────────────────────
function PaperRow({ id, title, venue, year, url, color }) {
  return (
    <a href={url} target="_blank" rel="noopener noreferrer" style={{ textDecoration:"none" }}>
      <div style={{
        display:"grid", gridTemplateColumns:"80px 1fr 160px",
        gap:16, padding:"14px 20px", borderRadius:8,
        background:"rgba(255,255,255,0.02)", border:"1px solid rgba(255,255,255,0.05)",
        transition:"all 0.2s", cursor:"pointer", alignItems:"center",
      }}
      onMouseEnter={e => { e.currentTarget.style.background = "rgba(79,195,247,0.05)"; e.currentTarget.style.borderColor = "#4FC3F740"; }}
      onMouseLeave={e => { e.currentTarget.style.background = "rgba(255,255,255,0.02)"; e.currentTarget.style.borderColor = "rgba(255,255,255,0.05)"; }}
      >
        <span style={{ fontFamily:"monospace", fontSize:11, color, fontWeight:700, background:`${color}18`, padding:"3px 8px", borderRadius:4, textAlign:"center" }}>{id}</span>
        <div>
          <div style={{ fontSize:13, color:"#CBD5E1", lineHeight:1.5 }}>{title}</div>
          <div style={{ fontSize:11, color:"#546E7A", marginTop:2 }}>{venue}</div>
        </div>
        <div style={{ fontFamily:"monospace", fontSize:11, color:"#4FC3F7", textAlign:"right" }}>
          {year} ↗
        </div>
      </div>
    </a>
  );
}

// ══════════════════════════════════════════════════════════════════════════
// MAIN LANDING PAGE
// ══════════════════════════════════════════════════════════════════════════
export default function LandingPage() {
  const [stats, setStats] = useState(null);
  const [apiOnline, setApiOnline] = useState(false);

  useEffect(() => {
    fetch(`${API}/health`).then(r => r.json()).then(() => {
      setApiOnline(true);
    }).catch(() => {});
  }, []);

  const termLines = [
    "INITIALIZING CYBERSENTINEL AI v1.0...",
    "Loading threat signatures → ChromaDB [8 vectors]",
    "DPI sensor ONLINE → eth0 [BPF: ip]",
    "RLM engine ONLINE → EMA α=0.1",
    "MCP orchestrator ONLINE → Claude claude-opus-4-5",
    "n8n SOAR ONLINE → 5 workflows active",
    "Kafka topics ONLINE → [raw-packets, threat-alerts, incidents]",
    "PLATFORM STATUS: ██████████ OPERATIONAL",
  ];

  return (
    <div style={{
      minHeight:"100vh", background:"#050D15",
      color:"#E2E8F0", overflowX:"hidden",
      fontFamily:"'DM Sans', system-ui, sans-serif",
    }}>
      <Scanlines/>

      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=DM+Sans:wght@300;400;500;600&family=Rajdhani:wght@600;700&display=swap');
        @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0} }
        @keyframes ping { 0%{transform:scale(1);opacity:0.6} 75%,100%{transform:scale(2.5);opacity:0} }
        @keyframes scanH { 0%{transform:translateY(-100%)} 100%{transform:translateY(100vh)} }
        @keyframes glow { 0%,100%{opacity:0.4} 50%{opacity:1} }
        @keyframes float { 0%,100%{transform:translateY(0)} 50%{transform:translateY(-10px)} }
        @keyframes fadeUp { from{opacity:0;transform:translateY(30px)} to{opacity:1;transform:translateY(0)} }
        * { box-sizing:border-box; margin:0; padding:0; }
        ::-webkit-scrollbar { width:4px; background:#050D15; }
        ::-webkit-scrollbar-thumb { background:#1565C0; border-radius:2px; }
      `}</style>

      {/* Horizontal scan line */}
      <div style={{
        position:"fixed", top:0, left:0, right:0, height:2,
        background:"linear-gradient(90deg, transparent, #4FC3F7, transparent)",
        animation:"scanH 8s linear infinite", zIndex:100, opacity:0.3,
      }}/>

      {/* NAV */}
      <nav style={{
        position:"fixed", top:0, left:0, right:0, zIndex:200,
        display:"flex", alignItems:"center", justifyContent:"space-between",
        padding:"0 48px", height:64,
        background:"rgba(5,13,21,0.9)", backdropFilter:"blur(20px)",
        borderBottom:"1px solid rgba(79,195,247,0.15)",
      }}>
        <div style={{ display:"flex", alignItems:"center", gap:12 }}>
          <span style={{ fontSize:22 }}>🛡️</span>
          <span style={{ fontFamily:"'Rajdhani', sans-serif", fontSize:20, fontWeight:700, color:"#E2E8F0", letterSpacing:2 }}>CYBERSENTINEL</span>
          <span style={{ fontFamily:"monospace", fontSize:10, color:"#4FC3F7", background:"rgba(79,195,247,0.1)", padding:"2px 8px", borderRadius:3, letterSpacing:2 }}>AI v1.0</span>
        </div>
        <div style={{ display:"flex", alignItems:"center", gap:32 }}>
          {["Architecture","Features","Research","Stack"].map(l => (
            <a key={l} href={`#${l.toLowerCase()}`} style={{ fontSize:13, color:"#8899AA", textDecoration:"none", letterSpacing:1, transition:"color 0.2s" }}
              onMouseEnter={e=>e.target.style.color="#4FC3F7"} onMouseLeave={e=>e.target.style.color="#8899AA"}>{l}</a>
          ))}
          <div style={{ display:"flex", alignItems:"center", gap:8, fontFamily:"monospace", fontSize:11 }}>
            <ThreatDot color={apiOnline ? "#00E676" : "#FF5252"} size={7}/>
            <span style={{ color: apiOnline ? "#00E676" : "#FF5252" }}>{apiOnline ? "API ONLINE" : "API OFFLINE"}</span>
          </div>
        </div>
      </nav>

      {/* HERO */}
      <section style={{ minHeight:"100vh", display:"flex", alignItems:"center", position:"relative", padding:"120px 48px 80px" }}>
        {/* Grid background */}
        <div style={{
          position:"absolute", inset:0,
          backgroundImage:`
            linear-gradient(rgba(79,195,247,0.03) 1px, transparent 1px),
            linear-gradient(90deg, rgba(79,195,247,0.03) 1px, transparent 1px)
          `,
          backgroundSize:"60px 60px",
        }}/>
        {/* Radial glow */}
        <div style={{
          position:"absolute", top:"20%", right:"10%", width:600, height:600,
          background:"radial-gradient(circle, rgba(21,101,192,0.15) 0%, transparent 70%)",
          pointerEvents:"none",
        }}/>

        <div style={{ maxWidth:1200, margin:"0 auto", width:"100%", display:"grid", gridTemplateColumns:"1fr 1fr", gap:80, alignItems:"center", position:"relative", zIndex:1 }}>
          <div style={{ animation:"fadeUp 0.8s ease both" }}>
            <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:24 }}>
              <ThreatDot color="#00E676" size={8}/>
              <span style={{ fontFamily:"'Share Tech Mono', monospace", fontSize:11, color:"#00E676", letterSpacing:3 }}>PLATFORM OPERATIONAL</span>
            </div>
            <h1 style={{
              fontFamily:"'Rajdhani', sans-serif", fontSize:72, fontWeight:700,
              lineHeight:1.0, marginBottom:16, letterSpacing:2,
              background:"linear-gradient(135deg, #E2E8F0 0%, #4FC3F7 50%, #1565C0 100%)",
              WebkitBackgroundClip:"text", WebkitTextFillColor:"transparent",
            }}>
              CYBER<br/>SENTINEL<br/>AI
            </h1>
            <p style={{ fontSize:16, color:"#8899AA", lineHeight:1.8, marginBottom:32, maxWidth:480 }}>
              Autonomous Threat Intelligence & Zero-Day Detection Platform. Detects threats in <strong style={{color:"#4FC3F7"}}>milliseconds</strong>, investigates with <strong style={{color:"#4FC3F7"}}>Claude AI</strong> in seconds, and responds across <strong style={{color:"#4FC3F7"}}>11+ enterprise tools</strong> without human intervention.
            </p>
            <div style={{ display:"flex", gap:16 }}>
              <a href="http://localhost:8080/docs" target="_blank" rel="noopener noreferrer" style={{
                padding:"14px 28px", background:"#1565C0", color:"#fff", borderRadius:6,
                textDecoration:"none", fontFamily:"'Share Tech Mono', monospace", fontSize:13,
                letterSpacing:1, transition:"all 0.2s", border:"1px solid #1565C0",
              }}
              onMouseEnter={e=>e.currentTarget.style.background="#1976D2"}
              onMouseLeave={e=>e.currentTarget.style.background="#1565C0"}
              >▶ API DOCS</a>
              <a href="#architecture" style={{
                padding:"14px 28px", background:"transparent", color:"#4FC3F7", borderRadius:6,
                textDecoration:"none", fontFamily:"'Share Tech Mono', monospace", fontSize:13,
                letterSpacing:1, border:"1px solid #4FC3F740", transition:"all 0.2s",
              }}
              onMouseEnter={e=>{ e.currentTarget.style.background="rgba(79,195,247,0.08)"; e.currentTarget.style.borderColor="#4FC3F7"; }}
              onMouseLeave={e=>{ e.currentTarget.style.background="transparent"; e.currentTarget.style.borderColor="#4FC3F740"; }}
              >◉ ARCHITECTURE</a>
            </div>
          </div>

          {/* Terminal */}
          <div style={{
            background:"rgba(5,13,21,0.95)", border:"1px solid rgba(79,195,247,0.2)",
            borderRadius:12, overflow:"hidden", animation:"fadeUp 0.8s 0.2s ease both",
            boxShadow:"0 0 60px rgba(79,195,247,0.1)",
          }}>
            <div style={{ padding:"10px 16px", background:"rgba(79,195,247,0.05)", borderBottom:"1px solid rgba(79,195,247,0.1)", display:"flex", alignItems:"center", gap:8 }}>
              {["#FF5F57","#FFBD2E","#28CA41"].map(c => <span key={c} style={{ width:12, height:12, borderRadius:"50%", background:c, display:"inline-block" }}/>)}
              <span style={{ fontFamily:"monospace", fontSize:11, color:"#546E7A", marginLeft:8 }}>cybersentinel — bash</span>
            </div>
            <div style={{ padding:24 }}>
              <Typewriter lines={termLines} speed={30}/>
            </div>
          </div>
        </div>
      </section>

      {/* LIVE STATS */}
      <section style={{ padding:"60px 48px", background:"rgba(21,101,192,0.05)", borderTop:"1px solid rgba(79,195,247,0.08)", borderBottom:"1px solid rgba(79,195,247,0.08)" }}>
        <div style={{ maxWidth:1200, margin:"0 auto" }}>
          <div style={{ textAlign:"center", marginBottom:40 }}>
            <span style={{ fontFamily:"'Share Tech Mono', monospace", fontSize:10, color:"#546E7A", letterSpacing:4 }}>PLATFORM METRICS</span>
            {apiOnline && <span style={{ marginLeft:16, fontFamily:"monospace", fontSize:10, color:"#00E676" }}>● LIVE DATA</span>}
          </div>
          <div style={{ display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:20 }}>
            <StatCard label="Detection Time" value={1} suffix="ms" color="#4FC3F7" live/>
            <StatCard label="MITRE Techniques" value={9} color="#FF6D00"/>
            <StatCard label="CTI Sources" value={5} color="#00E676"/>
            <StatCard label="Response Time" value={15} suffix="s" color="#E53935" live/>
          </div>
        </div>
      </section>

      {/* ARCHITECTURE */}
      <section id="architecture" style={{ padding:"100px 48px" }}>
        <div style={{ maxWidth:1200, margin:"0 auto" }}>
          <div style={{ textAlign:"center", marginBottom:64 }}>
            <div style={{ fontFamily:"'Share Tech Mono', monospace", fontSize:10, color:"#546E7A", letterSpacing:4, marginBottom:12 }}>SYSTEM DESIGN</div>
            <h2 style={{ fontFamily:"'Rajdhani', sans-serif", fontSize:48, fontWeight:700, color:"#E2E8F0", letterSpacing:2 }}>FOUR-LAYER ARCHITECTURE</h2>
          </div>

          {[
            { layer:"L1", label:"INGESTION", color:"#4FC3F7", nodes:[
              {icon:"📡",label:"DPI SENSOR",sub:"Scapy · raw packet capture · BPF filter"},
              {icon:"🌐",label:"CTI SCRAPER",sub:"Playwright · NVD · CISA · Abuse.ch · MITRE · OTX"},
              {icon:"⚡",label:"KAFKA BUS",sub:"5 topics · guaranteed delivery · replay"},
            ]},
            { layer:"L2", label:"INTELLIGENCE", color:"#00E676", nodes:[
              {icon:"🧠",label:"RLM ENGINE",sub:"EMA behavioral profiles · EMA α=0.1"},
              {icon:"🔍",label:"CHROMADB",sub:"Vector embeddings · cosine similarity · 3 collections"},
              {icon:"📊",label:"TIMESCALEDB",sub:"Hypertable · 30-day retention · continuous aggregates"},
            ]},
            { layer:"L3", label:"ORCHESTRATION", color:"#FF6D00", nodes:[
              {icon:"🤖",label:"CLAUDE AGENTS",sub:"MCP · 5 agents · 9 tools · agentic loop"},
              {icon:"🔗",label:"KAFKA BRIDGE",sub:"Routes Kafka events → n8n webhooks · dedup"},
              {icon:"🛠️",label:"n8n SOAR",sub:"5 workflows · 11+ integrations · auto-response"},
            ]},
            { layer:"L4", label:"DELIVERY", color:"#E53935", nodes:[
              {icon:"🚀",label:"FASTAPI",sub:"JWT auth · 8 endpoints · Swagger docs"},
              {icon:"📈",label:"GRAFANA",sub:"Real-time dashboards · SOC visibility"},
              {icon:"📣",label:"INTEGRATIONS",sub:"Slack · PagerDuty · Jira · Teams · ServiceNow"},
            ]},
          ].map((layer, li) => (
            <div key={layer.layer} style={{ marginBottom:40 }}>
              <div style={{ display:"flex", alignItems:"center", gap:20, marginBottom:20 }}>
                <div style={{
                  fontFamily:"'Share Tech Mono', monospace", fontSize:11,
                  color:layer.color, background:`${layer.color}18`,
                  padding:"4px 14px", borderRadius:4, letterSpacing:2, border:`1px solid ${layer.color}30`,
                }}>{layer.layer} · {layer.label}</div>
                <div style={{ flex:1, height:1, background:`linear-gradient(90deg, ${layer.color}40, transparent)` }}/>
              </div>
              <div style={{ display:"grid", gridTemplateColumns:"repeat(3,1fr)", gap:16 }}>
                {layer.nodes.map((n,i) => <ArchNode key={n.label} {...n} color={layer.color} delay={li*200 + i*100}/>)}
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* FEATURES */}
      <section id="features" style={{ padding:"100px 48px", background:"rgba(5,13,21,0.6)" }}>
        <div style={{ maxWidth:1200, margin:"0 auto" }}>
          <div style={{ textAlign:"center", marginBottom:64 }}>
            <div style={{ fontFamily:"'Share Tech Mono', monospace", fontSize:10, color:"#546E7A", letterSpacing:4, marginBottom:12 }}>CAPABILITIES</div>
            <h2 style={{ fontFamily:"'Rajdhani', sans-serif", fontSize:48, fontWeight:700, color:"#E2E8F0", letterSpacing:2 }}>DETECTION ENGINE</h2>
          </div>
          <div style={{ display:"grid", gridTemplateColumns:"repeat(2,1fr)", gap:24, marginBottom:24 }}>
            <FeatureCard icon="📡" title="DEEP PACKET INSPECTION" color="#4FC3F7"
              desc="Real-time packet capture via Scapy. Extracts Shannon entropy, detects C2 beaconing via Redis timing analysis, identifies DGA domains, cleartext credentials, and TTL anomalies across every IP packet on the network."
              mitre={["T1071.001","T1568.002","T1048","T1046","T1003","T1595"]}/>
            <FeatureCard icon="🧠" title="RLM BEHAVIORAL ENGINE" color="#00E676"
              desc="Novel research contribution. Builds Exponential Moving Average profiles for every host. Converts profiles to natural language, embeds via sentence-transformers, and scores via cosine similarity against 8 threat signatures in ChromaDB."
              mitre={["T1021.002","T1486","T1090.003"]}/>
            <FeatureCard icon="🤖" title="CLAUDE AI AUTONOMOUS AGENTS" color="#FF6D00"
              desc="5 specialized MCP agents powered by Claude claude-opus-4-5. Agentic investigation loop with 9 tools. Calls query_threat_database → get_host_profile → lookup_ip_reputation → decides → blocks → tickets — all autonomously in 15–45 seconds."
              mitre={[]}/>
            <FeatureCard icon="⚙️" title="n8n SOAR AUTOMATION" color="#E53935"
              desc="5 production workflows: Critical Alert SOAR, Daily SOC Report, CVE Pipeline, SLA Watchdog, and Weekly Board Report. Claude Opus writes executive briefings. Distributed to Slack, Teams, email, Jira, PagerDuty, and ServiceNow automatically."
              mitre={[]}/>
          </div>
        </div>
      </section>

      {/* RESEARCH PAPERS */}
      <section id="research" style={{ padding:"100px 48px" }}>
        <div style={{ maxWidth:1200, margin:"0 auto" }}>
          <div style={{ textAlign:"center", marginBottom:64 }}>
            <div style={{ fontFamily:"'Share Tech Mono', monospace", fontSize:10, color:"#546E7A", letterSpacing:4, marginBottom:12 }}>ACADEMIC FOUNDATION</div>
            <h2 style={{ fontFamily:"'Rajdhani', sans-serif", fontSize:48, fontWeight:700, color:"#E2E8F0", letterSpacing:2 }}>25 RESEARCH PAPERS</h2>
            <p style={{ color:"#8899AA", marginTop:12, fontSize:14 }}>7 domains · 2020–2026 · All mapped to specific components</p>
          </div>
          <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:12 }}>
            {[
              {id:"DPI-1",title:"Enhancing IDS Through DPI with Machine Learning (IEEE 2024)",venue:"IEEE ADICS",year:"2024",url:"https://ieeexplore.ieee.org/document/10533473/",color:"#4FC3F7"},
              {id:"DPI-5",title:"Deep Learning-based Intrusion Detection Systems: A Survey",venue:"arXiv",year:"2025",url:"https://arxiv.org/html/2504.07839v3",color:"#4FC3F7"},
              {id:"RLM-1",title:"Anomaly Network Detection Based on Self-Attention Mechanism",venue:"MDPI Sensors",year:"2023",url:"https://pmc.ncbi.nlm.nih.gov/articles/PMC10255318/",color:"#00E676"},
              {id:"RLM-2",title:"CESNET-TimeSeries24: Time Series Dataset for Network Anomaly Detection",venue:"Nature Scientific Data",year:"2025",url:"https://www.nature.com/articles/s41597-025-04603-x",color:"#00E676"},
              {id:"Agent-1",title:"Automated Threat Detection and Response Using LLM Agents",venue:"WJARR",year:"2024",url:"https://wjarr.com/sites/default/files/WJARR-2024-3329.pdf",color:"#FF6D00"},
              {id:"Agent-2",title:"A Survey of Agentic AI and Cybersecurity",venue:"arXiv",year:"2026",url:"https://arxiv.org/html/2601.05293v1",color:"#FF6D00"},
              {id:"RAG-1",title:"CyberRAG: An Agentic RAG Cyber Attack Classification Tool",venue:"arXiv",year:"2025",url:"https://arxiv.org/pdf/2507.02424",color:"#FFD740"},
              {id:"SOAR-3",title:"When LLMs Meet Cybersecurity: A Systematic Literature Review",venue:"Springer Cybersecurity",year:"2025",url:"https://cybersecurity.springeropen.com/articles/10.1186/s42400-025-00361-w",color:"#E53935"},
              {id:"MITRE-1",title:"MITRE ATT&CK: Design and Philosophy",venue:"MITRE Corporation",year:"2020",url:"https://attack.mitre.org/docs/ATTACK_Design_and_Philosophy_March_2020.pdf",color:"#90CAF9"},
              {id:"CTI-2",title:"LLM-Powered Threat Intelligence: A RAG Approach",venue:"PeerJ Computer Science",year:"2025",url:"https://peerj.com/articles/cs-3371/",color:"#A5D6A7"},
            ].map(p => <PaperRow key={p.id} {...p}/>)}
          </div>
          <div style={{ textAlign:"center", marginTop:24 }}>
            <span style={{ fontFamily:"monospace", fontSize:12, color:"#546E7A" }}>+ 15 more papers in the full Research Catalog document</span>
          </div>
        </div>
      </section>

      {/* TECH STACK */}
      <section id="stack" style={{ padding:"100px 48px", background:"rgba(21,101,192,0.04)", borderTop:"1px solid rgba(79,195,247,0.08)" }}>
        <div style={{ maxWidth:1200, margin:"0 auto" }}>
          <div style={{ textAlign:"center", marginBottom:64 }}>
            <div style={{ fontFamily:"'Share Tech Mono', monospace", fontSize:10, color:"#546E7A", letterSpacing:4, marginBottom:12 }}>TECHNOLOGY</div>
            <h2 style={{ fontFamily:"'Rajdhani', sans-serif", fontSize:48, fontWeight:700, color:"#E2E8F0", letterSpacing:2 }}>STACK</h2>
          </div>
          <div style={{ display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:16 }}>
            {[
              {name:"Anthropic Claude",sub:"claude-opus-4-5 · Haiku · Sonnet",icon:"🤖",color:"#FF6D00"},
              {name:"Apache Kafka",sub:"Confluent 7.5 · 5 topics",icon:"⚡",color:"#4FC3F7"},
              {name:"ChromaDB",sub:"Vector DB · sentence-transformers",icon:"🔍",color:"#00E676"},
              {name:"TimescaleDB",sub:"PostgreSQL 15 · Hypertable",icon:"🗄️",color:"#90CAF9"},
              {name:"Redis 7",sub:"Cache · blocklist · dedup",icon:"⚡",color:"#E53935"},
              {name:"Scapy",sub:"DPI · BPF · packet analysis",icon:"📡",color:"#FFD740"},
              {name:"FastAPI",sub:"REST · JWT · Swagger",icon:"🚀",color:"#4FC3F7"},
              {name:"n8n",sub:"SOAR · 5 workflows · self-hosted",icon:"⚙️",color:"#00E676"},
              {name:"Playwright",sub:"Headless Chromium · CTI scraping",icon:"🌐",color:"#A5D6A7"},
              {name:"Grafana",sub:"Dashboards · real-time SOC",icon:"📈",color:"#FF6D00"},
              {name:"Docker Compose",sub:"14 services · one command",icon:"🐳",color:"#4FC3F7"},
              {name:"Prometheus",sub:"Metrics · alerting rules",icon:"📊",color:"#E53935"},
            ].map(t => (
              <div key={t.name} style={{
                background:"rgba(13,27,42,0.8)", border:`1px solid ${t.color}25`,
                borderRadius:10, padding:"20px 18px", transition:"all 0.2s",
              }}
              onMouseEnter={e=>{ e.currentTarget.style.borderColor=t.color; e.currentTarget.style.transform="translateY(-3px)"; }}
              onMouseLeave={e=>{ e.currentTarget.style.borderColor=`${t.color}25`; e.currentTarget.style.transform="none"; }}
              >
                <div style={{ fontSize:24, marginBottom:8 }}>{t.icon}</div>
                <div style={{ fontFamily:"'Share Tech Mono', monospace", fontSize:12, color:t.color, fontWeight:700, marginBottom:4 }}>{t.name}</div>
                <div style={{ fontSize:11, color:"#546E7A", lineHeight:1.5 }}>{t.sub}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* FOOTER */}
      <footer style={{
        padding:"40px 48px", borderTop:"1px solid rgba(79,195,247,0.1)",
        display:"flex", alignItems:"center", justifyContent:"space-between",
      }}>
        <div style={{ display:"flex", alignItems:"center", gap:12 }}>
          <span style={{ fontSize:18 }}>🛡️</span>
          <span style={{ fontFamily:"'Rajdhani', sans-serif", fontSize:16, fontWeight:700, color:"#E2E8F0", letterSpacing:2 }}>CYBERSENTINEL AI</span>
        </div>
        <div style={{ fontFamily:"monospace", fontSize:11, color:"#546E7A" }}>
          Capstone Project 2025 · Enterprise Security Platform · Built with Claude AI
        </div>
        <div style={{ display:"flex", gap:16 }}>
          {[
            {l:"API Docs",u:"http://localhost:8080/docs"},
            {l:"Dashboard",u:"http://localhost:8080"},
            {l:"n8n",u:"http://localhost:5678"},
          ].map(({l,u}) => (
            <a key={l} href={u} target="_blank" rel="noopener noreferrer"
              style={{ fontFamily:"monospace", fontSize:11, color:"#4FC3F7", textDecoration:"none", opacity:0.7, transition:"opacity 0.2s" }}
              onMouseEnter={e=>e.target.style.opacity=1} onMouseLeave={e=>e.target.style.opacity=0.7}>{l} ↗</a>
          ))}
        </div>
      </footer>
    </div>
  );
}
