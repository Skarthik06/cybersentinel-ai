import { useState, useEffect, useRef, useCallback } from "react";

const API = "http://localhost:8080";

// ══════════════════════════════════════════════════════════════════════════
// LANDING PAGE — CyberSentinel AI
// Full scrollable showcase with scroll-reveal animations, water mosaic
// background, robot animation, kill chain, pipeline, features, integrations
// ══════════════════════════════════════════════════════════════════════════

// ── Animated counter (triggers on scroll into view) ────────────────────
function Counter({ end, suffix = "", prefix = "", duration = 2200 }) {
  const [val, setVal] = useState(0);
  const ref = useRef(null);
  const started = useRef(false);
  useEffect(() => {
    const obs = new IntersectionObserver(([e]) => {
      if (e.isIntersecting && !started.current) {
        started.current = true;
        const t0 = performance.now();
        const tick = (now) => {
          const p = Math.min((now - t0) / duration, 1);
          const ease = 1 - Math.pow(1 - p, 3);
          setVal(Math.floor(ease * end));
          if (p < 1) requestAnimationFrame(tick);
          else setVal(end);
        };
        requestAnimationFrame(tick);
      }
    }, { threshold: 0.4 });
    if (ref.current) obs.observe(ref.current);
    return () => obs.disconnect();
  }, [end, duration]);
  return <span ref={ref}>{prefix}{val.toLocaleString()}{suffix}</span>;
}

// ── Typewriter ──────────────────────────────────────────────────────────
function Typewriter({ lines, speed = 32 }) {
  const [displayed, setDisplayed] = useState([]);
  const [li, setLi] = useState(0);
  const [ci, setCi] = useState(0);
  useEffect(() => {
    if (li >= lines.length) return;
    if (ci < lines[li].length) {
      const t = setTimeout(() => {
        setDisplayed(d => { const n = [...d]; n[li] = (n[li] || "") + lines[li][ci]; return n; });
        setCi(c => c + 1);
      }, speed);
      return () => clearTimeout(t);
    } else {
      const t = setTimeout(() => { setLi(l => l + 1); setCi(0); }, 280);
      return () => clearTimeout(t);
    }
  }, [li, ci, lines, speed]);
  return (
    <div style={{ fontFamily:"'Share Tech Mono',monospace", fontSize:12, color:"#4FC3F7", lineHeight:2 }}>
      {displayed.map((line, i) => (
        <div key={i}>
          <span style={{ color:"#1565C0" }}>{">"} </span>
          <span>{line}</span>
          {i === li && <span style={{ animation:"blink 0.9s step-end infinite", color:"#00E5FF" }}>▋</span>}
        </div>
      ))}
    </div>
  );
}

// ── Pulsing status dot ──────────────────────────────────────────────────
function Dot({ color = "#00E676", size = 8 }) {
  return (
    <span style={{ position:"relative", display:"inline-flex", width:size, height:size, flexShrink:0 }}>
      <span style={{ position:"absolute", inset:0, borderRadius:"50%", background:color, animation:"pingDot 1.6s ease-out infinite", opacity:0.6 }}/>
      <span style={{ position:"absolute", inset:0, borderRadius:"50%", background:color }}/>
    </span>
  );
}

// ══════════════════════════════════════════════════════════════════════════
export default function LandingPage() {
  const canvasRef = useRef(null);
  const [apiOnline, setApiOnline] = useState(false);

  // ── Water mosaic canvas ─────────────────────────────────────────────
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    const TILE = 22;
    let t = 0, animId;
    const resize = () => { canvas.width = window.innerWidth; canvas.height = window.innerHeight; };
    resize();
    window.addEventListener("resize", resize);
    function draw() {
      t += 0.011;
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      const cols = Math.ceil(canvas.width / TILE) + 1;
      const rows = Math.ceil(canvas.height / TILE) + 1;
      for (let r = 0; r < rows; r++) {
        for (let c = 0; c < cols; c++) {
          const nx = c / cols - 0.5, ny = r / rows - 0.5;
          const dist = Math.sqrt(nx * nx + ny * ny);
          const w1 = Math.sin(dist * 13 - t * 2.1);
          const w2 = Math.sin(nx * 17 + t * 1.7) * Math.cos(ny * 13 - t * 0.85);
          const w3 = Math.cos((nx - ny) * 15 - t * 1.35);
          const w4 = Math.sin(dist * 7 + nx * 5 - t * 1.9);
          const wave = w1 * 0.35 + w2 * 0.28 + w3 * 0.22 + w4 * 0.15;
          const v = (wave + 1) / 2;
          const rr = Math.floor(v * 14), gg = Math.floor(18 + v * 95), bb = Math.floor(55 + v * 148);
          ctx.fillStyle = `rgba(${rr},${gg},${bb},${0.08 + v * 0.18})`;
          ctx.fillRect(c * TILE, r * TILE, TILE - 2, TILE - 2);
          if (v > 0.76) {
            const hi = (v - 0.76) / 0.24;
            ctx.fillStyle = `rgba(79,195,247,${hi * 0.28})`;
            ctx.fillRect(c * TILE + 4, r * TILE + 4, TILE - 9, TILE - 9);
          }
        }
      }
      animId = requestAnimationFrame(draw);
    }
    draw();
    return () => { cancelAnimationFrame(animId); window.removeEventListener("resize", resize); };
  }, []);

  // ── IntersectionObserver scroll-reveal ─────────────────────────────
  useEffect(() => {
    const timer = setTimeout(() => {
      const obs = new IntersectionObserver(entries => {
        entries.forEach(e => {
          if (e.isIntersecting) {
            e.target.classList.add("vis");
            obs.unobserve(e.target);
          }
        });
      }, { threshold: 0.08 });
      document.querySelectorAll(".sr,.sr-l,.sr-r,.sr-up,.sr-scale").forEach(el => obs.observe(el));
    }, 400);
    return () => clearTimeout(timer);
  }, []);

  // ── API health check ────────────────────────────────────────────────
  useEffect(() => {
    fetch(`${API}/health`).then(r => r.json()).then(() => setApiOnline(true)).catch(() => {});
  }, []);

  const termLines = [
    "INITIALIZING CYBERSENTINEL AI v1.1...",
    "DPI sensor ONLINE → Npcap [BPF: ip]",
    "RLM engine ONLINE → EMA α=0.1 · ChromaDB ready",
    "MCP orchestrator ONLINE → GPT-4o-mini · 9 tools",
    "Kafka BUS ONLINE → 5 topics · guaranteed delivery",
    "SOAR workflows ACTIVE → 5 n8n pipelines running",
    "Redis BLOCKLIST ACTIVE → 0 IPs blocked",
    "██████████ ALL SYSTEMS OPERATIONAL",
  ];

  return (
    <div style={{ background:"#020810", color:"#E2E8F0", overflowX:"hidden",
      fontFamily:"'DM Sans',system-ui,sans-serif", position:"relative" }}>

      {/* ── GLOBAL CSS ─────────────────────────────────────────────────── */}
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@600;700&family=Orbitron:wght@700;900&family=DM+Sans:wght@300;400;500;600&display=swap');
        *{box-sizing:border-box;margin:0;padding:0;}
        ::-webkit-scrollbar{width:4px;background:#020810;}
        ::-webkit-scrollbar-thumb{background:#1565C0;border-radius:2px;}

        /* ── Keyframes ── */
        @keyframes blink        {0%,100%{opacity:1}50%{opacity:0}}
        @keyframes pingDot      {0%{transform:scale(1);opacity:0.7}75%,100%{transform:scale(2.8);opacity:0}}
        @keyframes robotFloat   {0%,100%{transform:translateY(0)}50%{transform:translateY(-14px)}}
        @keyframes radarSpin    {from{transform:rotate(0deg)}to{transform:rotate(360deg)}}
        @keyframes pingOut      {0%{transform:scale(0.8);opacity:0.9}100%{transform:scale(2.6);opacity:0}}
        @keyframes eyePulse     {0%,100%{opacity:1}50%{opacity:0.55}}
        @keyframes antBlink     {0%,85%,100%{opacity:1}42%,58%{opacity:0.04}}
        @keyframes chestMove    {0%{transform:translateY(0);opacity:0.9}100%{transform:translateY(68px);opacity:0}}
        @keyframes topBarFlow   {0%{background-position:0% 0%}100%{background-position:200% 0%}}
        @keyframes hexGlow      {0%,100%{opacity:0.035}50%{opacity:0.075}}
        @keyframes hologram     {0%{background-position:200% center}100%{background-position:-200% center}}
        @keyframes scanBeam     {0%{top:-4px;opacity:0}8%{opacity:0.55}85%{opacity:0.55}100%{top:100%;opacity:0}}
        @keyframes cornerPulse  {0%,100%{opacity:0.5}50%{opacity:1}}
        @keyframes flowPulse    {0%{background-position:0% 0%}100%{background-position:200% 0%}}
        @keyframes pipeGlow     {0%,100%{box-shadow:0 0 8px rgba(0,176,255,0.15)}50%{box-shadow:0 0 22px rgba(0,176,255,0.55)}}
        @keyframes phaseActive  {0%,100%{box-shadow:0 0 12px rgba(0,176,255,0.4),inset 0 0 12px rgba(0,176,255,0.1)}50%{box-shadow:0 0 28px rgba(0,176,255,0.75),inset 0 0 18px rgba(0,176,255,0.18)}}
        @keyframes statGlow     {0%,100%{border-color:rgba(0,176,255,0.2)}50%{border-color:rgba(0,176,255,0.55)}}
        @keyframes neonCrit     {0%,100%{box-shadow:0 0 6px rgba(229,57,53,0.3)}50%{box-shadow:0 0 18px rgba(229,57,53,0.7)}}
        @keyframes scrollArrow  {0%,100%{transform:translateY(0);opacity:0.7}50%{transform:translateY(8px);opacity:1}}
        @keyframes fadeSlideUp  {from{opacity:0;transform:translateY(40px)}to{opacity:1;transform:translateY(0)}}
        @keyframes fadeSlideL   {from{opacity:0;transform:translateX(-50px)}to{opacity:1;transform:translateX(0)}}
        @keyframes fadeSlideR   {from{opacity:0;transform:translateX(50px)}to{opacity:1;transform:translateX(0)}}
        @keyframes scaleIn      {from{opacity:0;transform:scale(0.85)}to{opacity:1;transform:scale(1)}}

        /* ── Scroll-reveal base states ── */
        .sr        {opacity:0;transform:translateY(38px);transition:opacity 0.8s ease,transform 0.8s ease;}
        .sr.vis    {opacity:1;transform:none;}
        .sr-l      {opacity:0;transform:translateX(-52px);transition:opacity 0.8s ease,transform 0.8s ease;}
        .sr-l.vis  {opacity:1;transform:none;}
        .sr-r      {opacity:0;transform:translateX(52px);transition:opacity 0.8s ease,transform 0.8s ease;}
        .sr-r.vis  {opacity:1;transform:none;}
        .sr-up     {opacity:0;transform:translateY(28px);transition:opacity 0.65s ease,transform 0.65s ease;}
        .sr-up.vis {opacity:1;transform:none;}
        .sr-scale  {opacity:0;transform:scale(0.88);transition:opacity 0.7s ease,transform 0.7s ease;}
        .sr-scale.vis{opacity:1;transform:scale(1);}

        /* ── Stagger helpers ── */
        .d1{transition-delay:0.05s!important;}.d2{transition-delay:0.12s!important;}
        .d3{transition-delay:0.19s!important;}.d4{transition-delay:0.26s!important;}
        .d5{transition-delay:0.33s!important;}.d6{transition-delay:0.4s!important;}
        .d7{transition-delay:0.47s!important;}.d8{transition-delay:0.54s!important;}

        /* ── Component styles ── */
        .robot-float{animation:robotFloat 3.8s ease-in-out infinite;}
        .radar-arm  {animation:radarSpin 5.5s linear infinite;transform-origin:148px 184px;}
        .p-dot      {animation:pingOut 2.8s ease-out infinite;transform-box:fill-box;transform-origin:center;}
        .eye-p      {animation:eyePulse 2.1s ease-in-out infinite;}
        .eye-p2     {animation:eyePulse 2.1s ease-in-out 0.4s infinite;}
        .ant-led    {animation:antBlink 1.9s ease-in-out infinite;}
        .ant-led2   {animation:antBlink 1.9s ease-in-out 0.6s infinite;}
        .c-beam     {animation:chestMove 1.9s linear infinite;transform-box:fill-box;transform-origin:top center;}
        .top-bar    {background:linear-gradient(90deg,transparent,#0D47A1,#00B0FF,#00E5FF,#0097A7,#00B0FF,transparent);background-size:200% 100%;animation:topBarFlow 4s linear infinite;}
        .hex-bg     {animation:hexGlow 3.5s ease-in-out infinite;}
        .pipe-node  {animation:pipeGlow 2.5s ease-in-out infinite;}
        .phase-act  {animation:phaseActive 2.2s ease-in-out infinite;}
        .stat-ani   {animation:statGlow 3s ease-in-out infinite;}
        .scroll-arr {animation:scrollArrow 2s ease-in-out infinite;}
        .holo-text  {background:linear-gradient(90deg,#4FC3F7,#00E5FF,#80DEEA,#4FC3F7);background-size:200% auto;-webkit-background-clip:text;-webkit-text-fill-color:transparent;animation:hologram 3s linear infinite;}
        .corner     {animation:cornerPulse 2.5s ease-in-out infinite;}

        .feat-card{transition:all 0.28s!important;}
        .feat-card:hover{transform:translateY(-6px)!important;border-color:rgba(0,176,255,0.5)!important;box-shadow:0 14px 40px rgba(0,176,255,0.18)!important;}
        .tech-card{transition:all 0.22s!important;}
        .tech-card:hover{transform:translateY(-4px)!important;}
        .int-card{transition:all 0.22s!important;}
        .int-card:hover{transform:translateY(-3px) scale(1.03)!important;}
        .nav-link{transition:color 0.2s;}
        .nav-link:hover{color:#4FC3F7!important;}
        .cta-primary:hover{background:linear-gradient(135deg,rgba(0,140,255,0.45),rgba(0,80,180,0.55))!important;box-shadow:0 0 40px rgba(0,176,255,0.6)!important;}
        .cta-ghost:hover{background:rgba(0,176,255,0.1)!important;border-color:rgba(0,176,255,0.45)!important;}
      `}</style>

      {/* ── FIXED BACKGROUND LAYERS ──────────────────────────────────── */}
      <canvas ref={canvasRef} style={{ position:"fixed",inset:0,zIndex:0,width:"100%",height:"100%",pointerEvents:"none" }}/>
      <div className="hex-bg" style={{ position:"fixed",inset:0,zIndex:1,pointerEvents:"none",
        backgroundImage:`url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='56' height='100'%3E%3Cpolygon points='28,2 54,16 54,44 28,58 2,44 2,16' fill='none' stroke='%2300B0FF' stroke-width='0.5'/%3E%3Cpolygon points='28,52 54,66 54,94 28,108 2,94 2,66' fill='none' stroke='%2300B0FF' stroke-width='0.5'/%3E%3C/svg%3E")`,
        backgroundSize:"56px 100px" }}/>
      <div style={{ position:"fixed",inset:0,zIndex:2,pointerEvents:"none",
        background:"radial-gradient(ellipse at 50% 40%,rgba(2,8,18,0.0) 0%,rgba(2,8,18,0.5) 55%,rgba(2,8,18,0.88) 100%)" }}/>
      <div className="top-bar" style={{ position:"fixed",top:0,left:0,right:0,height:2,zIndex:200,pointerEvents:"none" }}/>

      {/* ── NAV ──────────────────────────────────────────────────────── */}
      <nav style={{ position:"fixed",top:0,left:0,right:0,zIndex:150,
        display:"flex",alignItems:"center",justifyContent:"space-between",
        padding:"0 48px",height:60,
        background:"rgba(2,8,18,0.88)",backdropFilter:"blur(20px)",
        borderBottom:"1px solid rgba(0,176,255,0.12)" }}>
        <div style={{ display:"flex",alignItems:"center",gap:12 }}>
          <div style={{ width:36,height:36,borderRadius:8,
            background:"linear-gradient(135deg,#1565C0,#0A2A60)",
            display:"flex",alignItems:"center",justifyContent:"center",fontSize:18,
            boxShadow:"0 0 20px rgba(21,101,192,0.5)" }}>🛡️</div>
          <span style={{ fontFamily:"'Orbitron',monospace",fontSize:15,fontWeight:700,
            color:"#E2E8F0",letterSpacing:4 }}>CYBERSENTINEL</span>
          <span style={{ fontFamily:"'Share Tech Mono',monospace",fontSize:9,color:"#4FC3F7",
            background:"rgba(79,195,247,0.08)",border:"1px solid rgba(79,195,247,0.2)",
            padding:"2px 8px",borderRadius:3,letterSpacing:2 }}>AI v1.1</span>
        </div>
        <div style={{ display:"flex",alignItems:"center",gap:28 }}>
          {[["#how-it-works","Pipeline"],["#features","Features"],["#killchain","Kill Chain"],["#integrations","Integrations"],["#stack","Stack"]].map(([href,label]) => (
            <a key={label} href={href} className="nav-link"
              style={{ fontSize:12,color:"#607D8B",textDecoration:"none",fontFamily:"'Share Tech Mono',monospace",letterSpacing:1 }}>{label}</a>
          ))}
          <div style={{ display:"flex",alignItems:"center",gap:7,fontFamily:"'Share Tech Mono',monospace",fontSize:10 }}>
            <Dot color={apiOnline ? "#00E676" : "#FF5252"} size={7}/>
            <span style={{ color:apiOnline ? "#00E676" : "#FF5252" }}>{apiOnline ? "API ONLINE" : "API OFFLINE"}</span>
          </div>
        </div>
      </nav>

      {/* ════════════════════════════════════════════════════════════════
          SECTION 1 — HERO
      ════════════════════════════════════════════════════════════════ */}
      <section style={{ position:"relative",zIndex:5,minHeight:"100vh",display:"flex",
        alignItems:"stretch",paddingTop:60 }}>
        <div style={{ display:"flex",width:"100%",minHeight:"calc(100vh - 60px)" }}>

          {/* LEFT — Text + CTA */}
          <div style={{ flex:"0 0 54%",display:"flex",flexDirection:"column",
            justifyContent:"center",padding:"60px 52px 60px 62px",
            background:"rgba(2,8,18,0.35)",backdropFilter:"blur(4px)",
            borderRight:"1px solid rgba(0,176,255,0.07)",
            animation:"fadeSlideL 0.85s ease both" }}>

            <div style={{ display:"flex",alignItems:"center",gap:10,marginBottom:28 }}>
              <Dot color="#00E676" size={8}/>
              <span style={{ fontFamily:"'Share Tech Mono',monospace",fontSize:10,
                color:"#00E676",letterSpacing:3 }}>ALL SYSTEMS OPERATIONAL</span>
            </div>

            <h1 style={{ fontFamily:"'Rajdhani',sans-serif",fontSize:"clamp(36px,4.5vw,58px)",
              fontWeight:700,lineHeight:1.1,marginBottom:18,letterSpacing:1 }}>
              <span style={{ color:"#E2E8F0" }}>AI-Powered Security</span><br/>
              <span style={{ color:"#E2E8F0" }}>Operations at</span><br/>
              <span style={{ background:"linear-gradient(90deg,#4FC3F7,#00B0FF 50%,#4DB6AC)",
                WebkitBackgroundClip:"text",WebkitTextFillColor:"transparent" }}>Machine Speed</span>
            </h1>

            <p style={{ fontSize:14,color:"#607D8B",lineHeight:1.85,maxWidth:500,
              marginBottom:32,fontFamily:"'DM Sans',sans-serif" }}>
              Real-time deep packet inspection, autonomous Claude AI-driven threat investigation,
              MITRE ATT&amp;CK-mapped incident response, and n8n SOAR automation — all unified in
              a single open-source SOC platform that detects, investigates, and responds without human
              intervention.
            </p>

            <div style={{ display:"flex",gap:14,flexWrap:"wrap",marginBottom:36 }}>
              <button className="cta-primary" onClick={() => document.getElementById("how-it-works")?.scrollIntoView({behavior:"smooth"})}
                style={{ padding:"13px 28px",
                  background:"linear-gradient(135deg,rgba(0,100,200,0.45),rgba(0,60,140,0.38))",
                  border:"1px solid rgba(0,176,255,0.5)",borderRadius:8,color:"#00E5FF",
                  fontFamily:"'Share Tech Mono',monospace",fontSize:11,letterSpacing:2,cursor:"pointer",
                  boxShadow:"0 0 22px rgba(0,176,255,0.22)",transition:"all 0.2s" }}>
                ▶ EXPLORE PLATFORM
              </button>
              <button className="cta-ghost" onClick={() => document.getElementById("features")?.scrollIntoView({behavior:"smooth"})}
                style={{ padding:"13px 28px",background:"rgba(0,176,255,0.04)",
                  border:"1px solid rgba(0,176,255,0.18)",borderRadius:8,color:"#4FC3F7",
                  fontFamily:"'Share Tech Mono',monospace",fontSize:11,letterSpacing:2,cursor:"pointer",
                  transition:"all 0.2s" }}>
                ↓ FEATURES
              </button>
            </div>

            <div style={{ display:"flex",gap:10,flexWrap:"wrap" }}>
              {["10K+ pkt/s DPI","<200ms detection","GPT-4o mini AI","MITRE ATT&CK","n8n SOAR"].map(s => (
                <span key={s} style={{ fontFamily:"'Share Tech Mono',monospace",fontSize:9,color:"#4FC3F7",
                  background:"rgba(79,195,247,0.06)",border:"1px solid rgba(79,195,247,0.15)",
                  padding:"5px 12px",borderRadius:20,letterSpacing:0.5 }}>{s}</span>
              ))}
            </div>
          </div>

          {/* RIGHT — Robot + Terminal */}
          <div style={{ flex:1,display:"flex",flexDirection:"column",
            alignItems:"center",justifyContent:"center",gap:28,padding:"60px 44px",
            animation:"fadeSlideR 0.85s 0.15s ease both" }}>

            {/* Robot */}
            <div style={{ position:"relative",width:220,height:290 }}>
              <svg style={{ position:"absolute",inset:"-38px",
                width:"calc(100% + 76px)",height:"calc(100% + 76px)",overflow:"visible",zIndex:1 }}
                viewBox="0 0 296 368">
                <circle cx="148" cy="184" r="132" fill="none" stroke="rgba(21,101,192,0.09)" strokeWidth="1"/>
                <circle cx="148" cy="184" r="106" fill="none" stroke="rgba(79,195,247,0.08)" strokeWidth="0.8"/>
                <circle cx="148" cy="184" r="80" fill="none" stroke="rgba(79,195,247,0.06)" strokeWidth="0.7"/>
                <g className="radar-arm">
                  <line x1="148" y1="184" x2="148" y2="78" stroke="rgba(79,195,247,0.4)" strokeWidth="1.5" strokeLinecap="round"/>
                  <path d="M148,184 L148,78 A106,106 0 0,1 240,222 Z" fill="rgba(79,195,247,0.04)"/>
                </g>
                <circle cx="148" cy="78" r="4.5" fill="#4FC3F7" className="p-dot" style={{ transformOrigin:"148px 78px" }}/>
                <circle cx="244" cy="202" r="3.5" fill="#4FC3F7" className="p-dot" style={{ transformOrigin:"244px 202px",animationDelay:"0.9s" }}/>
                <circle cx="76" cy="262" r="3" fill="#00E676" className="p-dot" style={{ transformOrigin:"76px 262px",animationDelay:"1.7s" }}/>
                <circle cx="222" cy="98" r="3" fill="#FF6D00" className="p-dot" style={{ transformOrigin:"222px 98px",animationDelay:"0.4s" }}/>
              </svg>

              <svg className="robot-float" viewBox="0 0 200 288"
                style={{ width:"100%",height:"100%",position:"relative",zIndex:2 }}>
                <defs>
                  <filter id="rf1"><feGaussianBlur stdDeviation="2.5" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
                  <filter id="rf2"><feGaussianBlur stdDeviation="4" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
                  <linearGradient id="rbG" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#0D2137"/><stop offset="100%" stopColor="#060F1A"/></linearGradient>
                  <linearGradient id="rsG" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#010C16"/><stop offset="100%" stopColor="#020810"/></linearGradient>
                  <clipPath id="rChest"><rect x="50" y="143" width="100" height="72"/></clipPath>
                </defs>
                {/* Antenna */}
                <line x1="100" y1="50" x2="100" y2="26" stroke="#263238" strokeWidth="2.5" strokeLinecap="round"/>
                <line x1="100" y1="34" x2="115" y2="24" stroke="#263238" strokeWidth="1.5" strokeLinecap="round"/>
                <circle cx="100" cy="22" r="5.5" fill="#FF1744" filter="url(#rf1)" className="ant-led"/>
                <circle cx="116" cy="21" r="3.2" fill="#FF6D00" filter="url(#rf1)" className="ant-led2"/>
                {/* Head */}
                <rect x="52" y="50" width="96" height="72" rx="11" fill="url(#rbG)" stroke="#1565C0" strokeWidth="1.5"/>
                <rect x="52" y="50" width="96" height="24" rx="11" fill="rgba(79,195,247,0.04)"/>
                <rect x="68" y="55" width="64" height="3" rx="1.5" fill="rgba(79,195,247,0.18)"/>
                <circle cx="100" cy="61" r="2.2" fill="rgba(79,195,247,0.45)"/>
                <line x1="68" y1="61" x2="90" y2="61" stroke="rgba(79,195,247,0.18)" strokeWidth="0.8"/>
                <line x1="110" y1="61" x2="132" y2="61" stroke="rgba(79,195,247,0.18)" strokeWidth="0.8"/>
                {/* Left eye */}
                <ellipse cx="78" cy="79" rx="13" ry="11" fill="#010E18" stroke="#00E676" strokeWidth="1.5" filter="url(#rf1)"/>
                <ellipse cx="78" cy="79" rx="8" ry="7" fill="#00C853" className="eye-p" filter="url(#rf1)"/>
                <circle cx="80" cy="77" r="2.5" fill="#AFFFCC" opacity="0.9"/>
                {/* Right eye */}
                <ellipse cx="122" cy="79" rx="13" ry="11" fill="#010E18" stroke="#00E676" strokeWidth="1.5" filter="url(#rf1)"/>
                <ellipse cx="122" cy="79" rx="8" ry="7" fill="#00C853" className="eye-p2" filter="url(#rf1)"/>
                <circle cx="124" cy="77" r="2.5" fill="#AFFFCC" opacity="0.9"/>
                {/* Mouth */}
                <rect x="66" y="103" width="68" height="11" rx="5.5" fill="#010E18" stroke="#0D47A1" strokeWidth="1"/>
                {[73,80,87,94,101,108,115,122,129].map((x,i) => (
                  <rect key={i} x={x} y="106" width="2.2" height="5" rx="1" fill={i%3===0?"#1565C0":"rgba(13,71,161,0.5)"}/>
                ))}
                {/* Neck */}
                <rect x="86" y="122" width="28" height="20" rx="4" fill="url(#rsG)" stroke="#0D47A1" strokeWidth="1"/>
                {[89,95,101,107].map((x,i) => <rect key={i} x={x} y="125" width="2" height="14" rx="1" fill="rgba(13,71,161,0.6)"/>)}
                {/* Body */}
                <rect x="34" y="140" width="132" height="96" rx="14" fill="url(#rbG)" stroke="#1565C0" strokeWidth="1.5"/>
                <rect x="50" y="143" width="100" height="72" rx="8" fill="#010C16" stroke="#0D47A1" strokeWidth="1" clipPath="url(#rChest)"/>
                <rect x="56" y="149" width="88" height="60" rx="6" fill="#020D1A" clipPath="url(#rChest)"/>
                {/* Chest beam */}
                <rect x="56" y="149" width="88" height="3" rx="1.5" fill="rgba(0,176,255,0.6)" className="c-beam"/>
                {/* Chest indicators */}
                <circle cx="66" cy="200" r="5" fill="#00E676" filter="url(#rf1)" style={{ animation:"eyePulse 1.4s ease-in-out infinite" }}/>
                <circle cx="80" cy="200" r="5" fill="#FF6D00" filter="url(#rf1)" style={{ animation:"eyePulse 1.4s ease-in-out 0.35s infinite" }}/>
                <circle cx="94" cy="200" r="5" fill="#1565C0" filter="url(#rf1)" style={{ animation:"eyePulse 1.4s ease-in-out 0.7s infinite" }}/>
                {/* Left arm */}
                <rect x="6" y="147" width="28" height="70" rx="10" fill="url(#rbG)" stroke="#1565C0" strokeWidth="1.2"/>
                <rect x="10" y="155" width="20" height="3" rx="1.5" fill="rgba(79,195,247,0.2)"/>
                <rect x="10" y="162" width="20" height="3" rx="1.5" fill="rgba(79,195,247,0.12)"/>
                <circle cx="20" cy="210" r="7" fill="#010E18" stroke="#0D47A1" strokeWidth="1"/>
                {/* Right arm */}
                <rect x="166" y="147" width="28" height="70" rx="10" fill="url(#rbG)" stroke="#1565C0" strokeWidth="1.2"/>
                <rect x="170" y="155" width="20" height="3" rx="1.5" fill="rgba(79,195,247,0.2)"/>
                <rect x="170" y="162" width="20" height="3" rx="1.5" fill="rgba(79,195,247,0.12)"/>
                <circle cx="180" cy="210" r="7" fill="#010E18" stroke="#0D47A1" strokeWidth="1"/>
                {/* Legs */}
                <rect x="52" y="234" width="40" height="46" rx="9" fill="url(#rbG)" stroke="#1565C0" strokeWidth="1.2"/>
                <rect x="108" y="234" width="40" height="46" rx="9" fill="url(#rbG)" stroke="#1565C0" strokeWidth="1.2"/>
                {/* Feet */}
                <rect x="46" y="276" width="50" height="14" rx="6" fill="url(#rsG)" stroke="#0D47A1" strokeWidth="1"/>
                <rect x="104" y="276" width="50" height="14" rx="6" fill="url(#rsG)" stroke="#0D47A1" strokeWidth="1"/>
              </svg>
            </div>

            {/* Mini terminal */}
            <div style={{ width:"100%",maxWidth:380,
              background:"rgba(2,8,20,0.95)",border:"1px solid rgba(0,176,255,0.2)",
              borderRadius:10,overflow:"hidden",boxShadow:"0 0 40px rgba(0,176,255,0.08)" }}>
              <div style={{ padding:"8px 14px",background:"rgba(0,176,255,0.05)",
                borderBottom:"1px solid rgba(0,176,255,0.1)",
                display:"flex",alignItems:"center",gap:7 }}>
                {["#FF5F57","#FFBD2E","#28CA41"].map(c => (
                  <span key={c} style={{ width:10,height:10,borderRadius:"50%",background:c,display:"inline-block" }}/>
                ))}
                <span style={{ fontFamily:"'Share Tech Mono',monospace",fontSize:10,color:"#455A64",marginLeft:6 }}>
                  cybersentinel — init
                </span>
              </div>
              <div style={{ padding:"16px 18px" }}>
                <Typewriter lines={termLines} speed={28}/>
              </div>
            </div>
          </div>
        </div>

        {/* Scroll indicator */}
        <div className="scroll-arr" style={{ position:"absolute",bottom:28,left:"50%",
          transform:"translateX(-50%)",zIndex:10,
          fontFamily:"'Share Tech Mono',monospace",fontSize:10,
          color:"rgba(79,195,247,0.5)",letterSpacing:2,textAlign:"center" }}>
          ↓ SCROLL TO EXPLORE
        </div>
      </section>

      {/* ════════════════════════════════════════════════════════════════
          SECTION 2 — LIVE STATS
      ════════════════════════════════════════════════════════════════ */}
      <section style={{ position:"relative",zIndex:5,padding:"70px 60px",
        background:"rgba(0,176,255,0.03)",borderTop:"1px solid rgba(0,176,255,0.07)",
        borderBottom:"1px solid rgba(0,176,255,0.07)" }}>
        <div style={{ maxWidth:1100,margin:"0 auto" }}>
          <div className="sr" style={{ textAlign:"center",marginBottom:48 }}>
            <div style={{ fontFamily:"'Share Tech Mono',monospace",fontSize:9,
              color:"#546E7A",letterSpacing:4,marginBottom:8 }}>PLATFORM METRICS</div>
            <div style={{ fontFamily:"'Rajdhani',sans-serif",fontSize:34,fontWeight:700,
              color:"#E2E8F0",letterSpacing:2 }}>BY THE NUMBERS</div>
          </div>
          <div style={{ display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:20 }}>
            {[
              { label:"Packets / Second",  val:10000,  suffix:"+" , color:"#4FC3F7", live:true  },
              { label:"Detection Latency", val:200,    suffix:"ms", color:"#00E676", live:true  },
              { label:"MITRE Techniques",  val:9,      suffix:"",   color:"#FF6D00", live:false },
              { label:"Auto Response Time",val:15,     suffix:"s",  color:"#E53935", live:true  },
            ].map((s,i) => (
              <div key={s.label} className={`sr-up d${i+1} stat-ani`}
                style={{ background:"rgba(5,12,22,0.9)",border:"1px solid rgba(0,176,255,0.15)",
                  borderRadius:12,padding:"28px 20px",textAlign:"center",
                  boxShadow:"0 4px 24px rgba(0,0,0,0.4)" }}>
                <div style={{ display:"flex",alignItems:"center",justifyContent:"center",gap:8,marginBottom:12 }}>
                  {s.live && <Dot color={s.color} size={6}/>}
                  <span style={{ fontFamily:"'Share Tech Mono',monospace",fontSize:9,
                    color:"#546E7A",letterSpacing:2 }}>{s.label.toUpperCase()}</span>
                </div>
                <div style={{ fontFamily:"'Orbitron',monospace",fontSize:38,fontWeight:700,
                  color:s.color,lineHeight:1,marginBottom:6 }}>
                  <Counter end={s.val} suffix={s.suffix}/>
                </div>
                <div style={{ width:40,height:2,margin:"0 auto",borderRadius:2,
                  background:`linear-gradient(90deg,transparent,${s.color},transparent)` }}/>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ════════════════════════════════════════════════════════════════
          SECTION 3 — HOW IT WORKS (pipeline)
      ════════════════════════════════════════════════════════════════ */}
      <section id="how-it-works" style={{ position:"relative",zIndex:5,padding:"90px 60px" }}>
        <div style={{ maxWidth:1100,margin:"0 auto" }}>
          <div className="sr" style={{ textAlign:"center",marginBottom:56 }}>
            <div style={{ fontFamily:"'Share Tech Mono',monospace",fontSize:9,
              color:"#546E7A",letterSpacing:4,marginBottom:10 }}>SYSTEM DESIGN</div>
            <div style={{ fontFamily:"'Rajdhani',sans-serif",fontSize:38,fontWeight:700,
              color:"#E2E8F0",letterSpacing:2,marginBottom:12 }}>HOW IT WORKS</div>
            <div style={{ fontSize:13,color:"#546E7A",maxWidth:560,margin:"0 auto",lineHeight:1.8 }}>
              Every packet flows through a deterministic 5-stage pipeline from wire capture to SOC dashboard — entirely automated.
            </div>
          </div>

          {/* Pipeline nodes */}
          <div className="sr" style={{ display:"flex",alignItems:"center",justifyContent:"center",
            gap:0,flexWrap:"nowrap",overflowX:"auto",marginBottom:40,paddingBottom:8 }}>
            {[
              { icon:"📡", title:"DPI SENSOR",      sub:"Npcap · Scapy · BPF",  color:"#4FC3F7" },
              { icon:"🚌", title:"KAFKA BUS",        sub:"5 topics · ordered",    color:"#FFD740" },
              { icon:"🧠", title:"RLM ENGINE",       sub:"EMA · ChromaDB · cosine",color:"#00E676" },
              { icon:"🤖", title:"MCP ORCHESTRATOR", sub:"GPT-4o · 9 tools",     color:"#FF6D00" },
              { icon:"📊", title:"SOC DASHBOARD",    sub:"React · FastAPI · JWT", color:"#E53935" },
            ].map((node, i, arr) => (
              <div key={i} style={{ display:"flex",alignItems:"center" }}>
                <div className="pipe-node"
                  style={{ background:"rgba(5,12,24,0.95)",
                    border:`1px solid ${node.color}35`,borderRadius:12,
                    padding:"20px 18px",textAlign:"center",minWidth:138,
                    flexShrink:0,transition:"box-shadow 0.3s" }}
                  onMouseEnter={e=>{ e.currentTarget.style.borderColor=node.color; e.currentTarget.style.boxShadow=`0 0 28px ${node.color}40`; }}
                  onMouseLeave={e=>{ e.currentTarget.style.borderColor=`${node.color}35`; e.currentTarget.style.boxShadow=""; }}>
                  <div style={{ fontSize:26,marginBottom:10 }}>{node.icon}</div>
                  <div style={{ fontFamily:"'Share Tech Mono',monospace",fontSize:9,
                    color:node.color,letterSpacing:1.5,marginBottom:5 }}>{node.title}</div>
                  <div style={{ fontFamily:"'DM Sans',sans-serif",fontSize:9,color:"#3D5465" }}>{node.sub}</div>
                </div>
                {i < arr.length - 1 && (
                  <div style={{ width:44,height:2,flexShrink:0,position:"relative",
                    background:"linear-gradient(90deg,rgba(0,176,255,0.4),rgba(0,229,255,0.85),rgba(0,176,255,0.4))",
                    backgroundSize:"200% 100%",animation:"flowPulse 1.8s linear infinite" }}>
                    <span style={{ position:"absolute",right:-7,top:"50%",transform:"translateY(-50%)",
                      color:"#4FC3F7",fontSize:12 }}>▶</span>
                  </div>
                )}
              </div>
            ))}
          </div>

          {/* Storage layer */}
          <div className="sr" style={{ display:"flex",justifyContent:"center",gap:14,flexWrap:"wrap" }}>
            <div style={{ fontFamily:"'Share Tech Mono',monospace",fontSize:9,color:"#3D5465",
              display:"flex",alignItems:"center",gap:10,marginRight:10 }}>
              STORAGE LAYER →
            </div>
            {[
              { label:"TimescaleDB",    color:"rgba(79,195,247,0.35)" },
              { label:"Redis Cache",    color:"rgba(255,82,82,0.35)"  },
              { label:"ChromaDB Vector",color:"rgba(206,147,216,0.35)"},
              { label:"PostgreSQL",     color:"rgba(0,230,118,0.35)"  },
            ].map(s => (
              <div key={s.label} style={{ background:"rgba(5,12,22,0.9)",
                border:`1px solid ${s.color}`,borderRadius:8,padding:"9px 18px",
                fontFamily:"'Share Tech Mono',monospace",fontSize:9,color:"#607D8B",letterSpacing:1 }}>
                {s.label}
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ════════════════════════════════════════════════════════════════
          SECTION 4 — FEATURES (6 alternating feature rows)
      ════════════════════════════════════════════════════════════════ */}
      <section id="features" style={{ position:"relative",zIndex:5 }}>

        {/* ── Feature 1: DPI Sensor ── */}
        <div style={{ padding:"80px 64px",background:"rgba(2,6,16,0.7)",
          borderTop:"1px solid rgba(0,176,255,0.06)",borderBottom:"1px solid rgba(0,176,255,0.05)" }}>
          <div style={{ display:"flex",gap:64,alignItems:"center",maxWidth:1100,margin:"0 auto" }}>
            <div className="sr-l" style={{ flex:"0 0 47%" }}>
              <div style={{ fontFamily:"'Share Tech Mono',monospace",fontSize:9,
                color:"#4FC3F7",letterSpacing:4,marginBottom:12 }}>LAYER 1 · CAPTURE</div>
              <h3 style={{ fontFamily:"'Rajdhani',sans-serif",fontSize:30,fontWeight:700,
                color:"#E2E8F0",marginBottom:16,letterSpacing:0.5 }}>Deep Packet Inspection</h3>
              <p style={{ fontSize:13,color:"#607D8B",lineHeight:1.85,marginBottom:22,
                fontFamily:"'DM Sans',sans-serif" }}>
                Real-time network packet capture using Npcap on Windows with Scapy. Every packet is fully decoded —
                extracting Shannon entropy, TLS indicators, DNS queries, HTTP headers, user agents, and protocol anomalies
                at over 10,000 packets per second.
              </p>
              <div style={{ display:"flex",flexDirection:"column",gap:9 }}>
                {["Shannon entropy analysis (7.4+ bits = encrypted C2)",
                  "TLS/SSL fingerprinting + SNI extraction",
                  "DNS query extraction + DGA detection",
                  "HTTP method / host / URI parsing",
                  "Suspicious port detection (4444, 8443, 31337)",
                  "TTL anomaly + hop-count profiling"].map(f => (
                  <div key={f} style={{ display:"flex",alignItems:"flex-start",gap:10,
                    fontFamily:"'Share Tech Mono',monospace",fontSize:10,color:"#78909C" }}>
                    <span style={{ color:"#4FC3F7",fontSize:14,marginTop:-1 }}>›</span>{f}
                  </div>
                ))}
              </div>
            </div>
            <div className="sr-r" style={{ flex:1 }}>
              <div style={{ background:"rgba(3,10,20,0.97)",border:"1px solid rgba(0,176,255,0.2)",
                borderRadius:12,padding:"22px 24px",fontFamily:"'Share Tech Mono',monospace",
                fontSize:10,boxShadow:"0 0 40px rgba(0,176,255,0.07)" }}>
                <div style={{ color:"#4FC3F7",marginBottom:10,fontSize:9,letterSpacing:2 }}>
                  PACKET #48291 │ 192.168.1.45 → 5.188.86.211:443
                </div>
                <div style={{ color:"rgba(0,176,255,0.25)",marginBottom:8 }}>──────────────────────────────────────</div>
                <div style={{ color:"#455A64",lineHeight:2,fontSize:9 }}>
                  0000: 45 00 00 3c 1c 46 40 00  40 06 b1 e6 c0 a8 01 2d<br/>
                  0010: 05 bc 56 d3 c7 8a 01 bb  f3 4a 82 11 00 00 00 00
                </div>
                <div style={{ color:"rgba(0,176,255,0.25)",margin:"8px 0" }}>──────────────────────────────────────</div>
                <div style={{ lineHeight:2.2,fontSize:9 }}>
                  <div><span style={{ color:"#4FC3F7" }}>ENTROPY: </span><span style={{ color:"#FF6D00" }}> 7.42 bits  ████████████ HIGH</span></div>
                  <div><span style={{ color:"#4FC3F7" }}>TLS SNI: </span><span style={{ color:"#E2E8F0" }}> cdn.update-service.net</span></div>
                  <div><span style={{ color:"#4FC3F7" }}>PROTOCOL:</span><span style={{ color:"#E2E8F0" }}> TCP/443 HTTPS</span></div>
                  <div><span style={{ color:"#4FC3F7" }}>DGA:     </span><span style={{ color:"#FF5252" }}> ▲ SUSPICIOUS — DGA HOSTNAME</span></div>
                  <div><span style={{ color:"#4FC3F7" }}>ACTION:  </span><span style={{ color:"#FF1744" }}> → FORWARDED TO KAFKA</span></div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* ── Feature 2: RLM Engine ── */}
        <div style={{ padding:"80px 64px",background:"rgba(0,230,118,0.02)",
          borderBottom:"1px solid rgba(0,230,118,0.05)" }}>
          <div style={{ display:"flex",gap:64,alignItems:"center",maxWidth:1100,margin:"0 auto" }}>
            <div className="sr-l" style={{ flex:1 }}>
              <div style={{ background:"rgba(3,10,20,0.97)",border:"1px solid rgba(0,230,118,0.2)",
                borderRadius:12,padding:"24px",fontFamily:"'Share Tech Mono',monospace",fontSize:10,
                boxShadow:"0 0 40px rgba(0,230,118,0.05)" }}>
                <div style={{ color:"#00E676",marginBottom:12,fontSize:9,letterSpacing:2 }}>HOST PROFILE: 192.168.1.45</div>
                <div style={{ display:"grid",gridTemplateColumns:"1fr 1fr",gap:10,marginBottom:16 }}>
                  {[
                    { k:"avg_bytes",   v:"1,248",    bar:0.42, c:"#4FC3F7" },
                    { k:"avg_entropy", v:"6.8 bits", bar:0.68, c:"#FF6D00" },
                    { k:"dns_queries", v:"34/hr",    bar:0.55, c:"#00E676" },
                    { k:"unique_ips",  v:"12",        bar:0.24, c:"#FFD740" },
                  ].map(r => (
                    <div key={r.k}>
                      <div style={{ color:"#546E7A",fontSize:9,marginBottom:4 }}>{r.k}</div>
                      <div style={{ height:4,background:"rgba(255,255,255,0.05)",borderRadius:2,marginBottom:3 }}>
                        <div style={{ height:"100%",width:`${r.bar*100}%`,background:r.c,borderRadius:2 }}/>
                      </div>
                      <div style={{ color:r.c,fontSize:10 }}>{r.v}</div>
                    </div>
                  ))}
                </div>
                <div style={{ color:"rgba(0,230,118,0.3)",marginBottom:8 }}>──────────────────────────────────────</div>
                <div style={{ color:"#00E676",fontSize:9 }}>
                  SIMILARITY SCORE: 0.847 → "Ransomware C2 Beaconing Pattern"<br/>
                  <span style={{ color:"#FF5252" }}>THREAT LEVEL: CRITICAL — ESCALATING TO MCP</span>
                </div>
              </div>
            </div>
            <div className="sr-r" style={{ flex:"0 0 47%" }}>
              <div style={{ fontFamily:"'Share Tech Mono',monospace",fontSize:9,
                color:"#00E676",letterSpacing:4,marginBottom:12 }}>LAYER 2 · INTELLIGENCE</div>
              <h3 style={{ fontFamily:"'Rajdhani',sans-serif",fontSize:30,fontWeight:700,
                color:"#E2E8F0",marginBottom:16 }}>RLM Behavioral Engine</h3>
              <p style={{ fontSize:13,color:"#607D8B",lineHeight:1.85,marginBottom:22,
                fontFamily:"'DM Sans',sans-serif" }}>
                A novel research contribution. Builds Exponential Moving Average (EMA) behavioral profiles
                for every host on the network. Converts profiles into natural language, embeds via
                sentence-transformers, then scores via cosine similarity against 8 threat signature vectors in ChromaDB.
              </p>
              <div style={{ display:"flex",flexDirection:"column",gap:9 }}>
                {["EMA α=0.1 — low-pass filter for baseline drift",
                  "8 threat signatures (ransomware, C2, exfil, scan…)",
                  "ChromaDB cosine similarity scoring",
                  "Natural language profile conversion",
                  "Continuous scoring — no batch windows",
                  "0.7+ similarity triggers MCP investigation"].map(f => (
                  <div key={f} style={{ display:"flex",alignItems:"flex-start",gap:10,
                    fontFamily:"'Share Tech Mono',monospace",fontSize:10,color:"#78909C" }}>
                    <span style={{ color:"#00E676",fontSize:14,marginTop:-1 }}>›</span>{f}
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* ── Feature 3: Claude AI Agents ── */}
        <div style={{ padding:"80px 64px",background:"rgba(255,109,0,0.02)",
          borderBottom:"1px solid rgba(255,109,0,0.05)" }}>
          <div style={{ display:"flex",gap:64,alignItems:"center",maxWidth:1100,margin:"0 auto" }}>
            <div className="sr-l" style={{ flex:"0 0 47%" }}>
              <div style={{ fontFamily:"'Share Tech Mono',monospace",fontSize:9,
                color:"#FF6D00",letterSpacing:4,marginBottom:12 }}>LAYER 3 · ORCHESTRATION</div>
              <h3 style={{ fontFamily:"'Rajdhani',sans-serif",fontSize:30,fontWeight:700,
                color:"#E2E8F0",marginBottom:16 }}>Claude AI Autonomous Agents</h3>
              <p style={{ fontSize:13,color:"#607D8B",lineHeight:1.85,marginBottom:22,
                fontFamily:"'DM Sans',sans-serif" }}>
                5 specialized MCP agents powered by GPT-4o mini with an agentic investigation loop using
                9 tools. From alert received to IP blocked and Jira ticket created — fully automated in
                under 45 seconds, with zero human intervention required.
              </p>
              <div style={{ display:"grid",gridTemplateColumns:"1fr 1fr",gap:8 }}>
                {[
                  "query_threat_database","get_host_profile",
                  "lookup_ip_reputation","create_jira_ticket",
                  "block_ip_address","send_slack_alert",
                  "escalate_to_pagerduty","generate_remediation",
                  "get_network_context",
                ].map(tool => (
                  <div key={tool} style={{ fontFamily:"'Share Tech Mono',monospace",fontSize:9,
                    color:"#78909C",display:"flex",alignItems:"center",gap:6 }}>
                    <span style={{ color:"#FF6D00" }}>⚙</span>{tool}
                  </div>
                ))}
              </div>
            </div>
            <div className="sr-r" style={{ flex:1 }}>
              <div style={{ background:"rgba(3,10,20,0.97)",border:"1px solid rgba(255,109,0,0.2)",
                borderRadius:12,padding:"20px 22px",fontFamily:"'Share Tech Mono',monospace",fontSize:10,
                boxShadow:"0 0 40px rgba(255,109,0,0.05)" }}>
                <div style={{ color:"#FF6D00",marginBottom:10,fontSize:9,letterSpacing:2 }}>
                  MCP AGENT INVESTIGATION LOG
                </div>
                {[
                  { t:"00:00", color:"#4FC3F7",  msg:'[AGENT] Received alert: CRITICAL threat on 192.168.1.45' },
                  { t:"00:02", color:"#4FC3F7",  msg:'[TOOL]  query_threat_database("ransomware C2 beaconing")' },
                  { t:"00:04", color:"#00E676",  msg:'[RESP]  Found 3 matches — confidence 0.847' },
                  { t:"00:06", color:"#4FC3F7",  msg:'[TOOL]  lookup_ip_reputation("5.188.86.211")' },
                  { t:"00:08", color:"#FF5252",  msg:'[RESP]  AbuseIPDB score: 94 — KNOWN MALICIOUS' },
                  { t:"00:12", color:"#4FC3F7",  msg:'[TOOL]  block_ip_address("5.188.86.211")' },
                  { t:"00:13", color:"#00E676",  msg:'[RESP]  Blocked. Redis TTL: 86400s. DB updated.' },
                  { t:"00:15", color:"#4FC3F7",  msg:'[TOOL]  create_jira_ticket(severity=CRITICAL)' },
                  { t:"00:18", color:"#00E676",  msg:'[DONE]  Investigation complete. Ticket: CS-2847' },
                ].map((line,i) => (
                  <div key={i} style={{ display:"flex",gap:12,lineHeight:1.9,fontSize:9 }}>
                    <span style={{ color:"#3D5465",flexShrink:0 }}>{line.t}</span>
                    <span style={{ color:line.color }}>{line.msg}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* ── Feature 4: n8n SOAR ── */}
        <div style={{ padding:"80px 64px",background:"rgba(229,57,53,0.02)",
          borderBottom:"1px solid rgba(229,57,53,0.05)" }}>
          <div style={{ display:"flex",gap:64,alignItems:"center",maxWidth:1100,margin:"0 auto" }}>
            <div className="sr-l" style={{ flex:1 }}>
              <div style={{ background:"rgba(3,10,20,0.97)",border:"1px solid rgba(229,57,53,0.2)",
                borderRadius:12,padding:"22px 24px",boxShadow:"0 0 40px rgba(229,57,53,0.05)" }}>
                <div style={{ fontFamily:"'Share Tech Mono',monospace",fontSize:9,
                  color:"#E53935",letterSpacing:2,marginBottom:16 }}>n8n SOAR WORKFLOWS</div>
                {[
                  { name:"Critical Alert SOAR",   status:"ACTIVE",  color:"#E53935", runs:"1,247 runs" },
                  { name:"Daily SOC Report",       status:"ACTIVE",  color:"#FF6D00", runs:"360 runs"   },
                  { name:"CVE Intelligence Feed",  status:"ACTIVE",  color:"#FFD740", runs:"892 runs"   },
                  { name:"SLA Watchdog",           status:"ACTIVE",  color:"#4FC3F7", runs:"2,891 runs" },
                  { name:"Weekly Board Report",    status:"ACTIVE",  color:"#00E676", runs:"52 runs"    },
                ].map(w => (
                  <div key={w.name} style={{ display:"flex",alignItems:"center",justifyContent:"space-between",
                    padding:"11px 0",borderBottom:"1px solid rgba(255,255,255,0.04)" }}>
                    <div style={{ display:"flex",alignItems:"center",gap:10 }}>
                      <Dot color={w.color} size={6}/>
                      <span style={{ fontFamily:"'Share Tech Mono',monospace",fontSize:10,color:"#B0BEC5" }}>{w.name}</span>
                    </div>
                    <div style={{ display:"flex",alignItems:"center",gap:14 }}>
                      <span style={{ fontFamily:"'Share Tech Mono',monospace",fontSize:9,color:"#546E7A" }}>{w.runs}</span>
                      <span style={{ fontFamily:"'Share Tech Mono',monospace",fontSize:9,
                        color:w.color,background:`${w.color}18`,
                        padding:"2px 8px",borderRadius:3 }}>{w.status}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
            <div className="sr-r" style={{ flex:"0 0 47%" }}>
              <div style={{ fontFamily:"'Share Tech Mono',monospace",fontSize:9,
                color:"#E53935",letterSpacing:4,marginBottom:12 }}>LAYER 4 · AUTOMATION</div>
              <h3 style={{ fontFamily:"'Rajdhani',sans-serif",fontSize:30,fontWeight:700,
                color:"#E2E8F0",marginBottom:16 }}>n8n SOAR Automation</h3>
              <p style={{ fontSize:13,color:"#607D8B",lineHeight:1.85,marginBottom:22,
                fontFamily:"'DM Sans',sans-serif" }}>
                5 production-grade workflows running in n8n: Critical alerts trigger a full SOAR chain —
                Slack notification, Jira ticket, PagerDuty page, and ServiceNow incident — all within
                30 seconds. Claude Opus writes executive briefings for weekly board reports automatically.
              </p>
              <div style={{ display:"flex",flexDirection:"column",gap:9 }}>
                {["Slack #security-alerts + @oncall mention",
                  "Jira CRITICAL ticket with full context",
                  "PagerDuty escalation for P0/P1 severity",
                  "ServiceNow incident auto-creation",
                  "Microsoft Teams adaptive card alerts",
                  "AI-written weekly board security briefs"].map(f => (
                  <div key={f} style={{ display:"flex",alignItems:"flex-start",gap:10,
                    fontFamily:"'Share Tech Mono',monospace",fontSize:10,color:"#78909C" }}>
                    <span style={{ color:"#E53935",fontSize:14,marginTop:-1 }}>›</span>{f}
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* ── Feature 5: Dual Mode ── */}
        <div style={{ padding:"80px 64px",background:"rgba(79,195,247,0.02)",
          borderBottom:"1px solid rgba(79,195,247,0.06)" }}>
          <div style={{ maxWidth:1100,margin:"0 auto" }}>
            <div className="sr" style={{ textAlign:"center",marginBottom:48 }}>
              <div style={{ fontFamily:"'Share Tech Mono',monospace",fontSize:9,
                color:"#546E7A",letterSpacing:4,marginBottom:10 }}>OPERATIONAL MODES</div>
              <h3 style={{ fontFamily:"'Rajdhani',sans-serif",fontSize:34,fontWeight:700,
                color:"#E2E8F0",letterSpacing:2 }}>SIMULATOR LAB vs LIVE SOC</h3>
            </div>
            <div style={{ display:"grid",gridTemplateColumns:"1fr 1fr",gap:24 }}>
              {[
                {
                  mode:"SIMULATOR LAB", icon:"🧪", color:"#FFD740",
                  desc:"Safe training environment that injects synthetic attack traffic — C2 beaconing, port scans, data exfiltration — so analysts can practice investigation workflows without touching live traffic.",
                  items:["Synthetic C2 beaconing traffic","Port scan simulations","Ransomware data exfiltration","DNS tunneling scenarios","Full MCP AI investigation loop","Isolated Redis/Kafka namespace"],
                },
                {
                  mode:"LIVE SOC",       icon:"⚡", color:"#E53935",
                  desc:"Production mode capturing real network traffic via Npcap. All detections, investigations, and responses act on actual network events. Analyst-approved IP blocking writes to Redis and the firewall rules database.",
                  items:["Real Npcap packet capture","Live threat scoring (EMA)","Actual IP block enforcement","Production incident database","Human-in-the-loop approval","Audit trail for every action"],
                },
              ].map(m => (
                <div key={m.mode} className="sr-up feat-card"
                  style={{ background:"rgba(5,12,22,0.9)",border:`1px solid ${m.color}25`,
                    borderRadius:14,padding:"32px 28px" }}>
                  <div style={{ display:"flex",alignItems:"center",gap:12,marginBottom:16 }}>
                    <span style={{ fontSize:28 }}>{m.icon}</span>
                    <div>
                      <div style={{ fontFamily:"'Share Tech Mono',monospace",fontSize:12,
                        color:m.color,letterSpacing:2,fontWeight:700 }}>{m.mode}</div>
                    </div>
                  </div>
                  <p style={{ fontSize:13,color:"#607D8B",lineHeight:1.8,marginBottom:20,
                    fontFamily:"'DM Sans',sans-serif" }}>{m.desc}</p>
                  {m.items.map(item => (
                    <div key={item} style={{ display:"flex",alignItems:"center",gap:9,
                      fontFamily:"'Share Tech Mono',monospace",fontSize:10,color:"#78909C",marginBottom:8 }}>
                      <span style={{ color:m.color,fontSize:12 }}>›</span>{item}
                    </div>
                  ))}
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* ════════════════════════════════════════════════════════════════
          SECTION 5 — MITRE ATT&CK KILL CHAIN
      ════════════════════════════════════════════════════════════════ */}
      <section id="killchain" style={{ position:"relative",zIndex:5,padding:"90px 60px",
        background:"rgba(2,6,16,0.8)" }}>
        <div style={{ maxWidth:1100,margin:"0 auto" }}>
          <div className="sr" style={{ textAlign:"center",marginBottom:52 }}>
            <div style={{ fontFamily:"'Share Tech Mono',monospace",fontSize:9,
              color:"#546E7A",letterSpacing:4,marginBottom:10 }}>MITRE ATT&CK FRAMEWORK</div>
            <h3 style={{ fontFamily:"'Rajdhani',sans-serif",fontSize:36,fontWeight:700,
              color:"#E2E8F0",letterSpacing:2,marginBottom:10 }}>KILL CHAIN COVERAGE</h3>
            <p style={{ fontSize:13,color:"#546E7A",maxWidth:560,margin:"0 auto",lineHeight:1.8 }}>
              CyberSentinel detects threats across all 9 MITRE ATT&amp;CK phases.
              Phase highlighted in cyan represents active detections in this demo session.
            </p>
          </div>

          <div style={{ display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:14 }}>
            {[
              { phase:"TA0001", name:"Initial Access",       icon:"🔓", active:false, techs:["T1190","T1133","T1078"]     },
              { phase:"TA0002", name:"Execution",            icon:"⚙️",  active:false, techs:["T1059","T1203","T1204"]     },
              { phase:"TA0003", name:"Persistence",          icon:"⚓",  active:false, techs:["T1547","T1543","T1053"]     },
              { phase:"TA0007", name:"Discovery",            icon:"🔍", active:false, techs:["T1046","T1083","T1057"]     },
              { phase:"TA0010", name:"Exfiltration",         icon:"📤", active:false, techs:["T1048","T1041","T1567"]     },
              { phase:"TA0011", name:"Command & Control",    icon:"📡", active:true,  techs:["T1071","T1090","T1568"]     },
              { phase:"TA0009", name:"Collection",           icon:"🗂️",  active:false, techs:["T1005","T1039","T1114"]     },
              { phase:"TA0040", name:"Impact",               icon:"💥", active:false, techs:["T1486","T1490","T1485"]     },
              { phase:"TA0006", name:"Credential Access",    icon:"🔑", active:false, techs:["T1003","T1110","T1555"]     },
            ].map((p,i) => (
              <div key={p.phase} className={`sr-up d${(i%4)+1}${p.active?" phase-act":""}`}
                style={{ background:p.active ? "rgba(0,176,255,0.06)" : "rgba(5,12,22,0.9)",
                  border:`1px solid ${p.active ? "rgba(0,176,255,0.5)" : "rgba(255,255,255,0.06)"}`,
                  borderRadius:10,padding:"20px 18px",transition:"all 0.25s" }}
                onMouseEnter={e=>{ if(!p.active){ e.currentTarget.style.borderColor="rgba(0,176,255,0.3)"; e.currentTarget.style.background="rgba(0,176,255,0.03)"; }}}
                onMouseLeave={e=>{ if(!p.active){ e.currentTarget.style.borderColor="rgba(255,255,255,0.06)"; e.currentTarget.style.background="rgba(5,12,22,0.9)"; }}}>
                <div style={{ display:"flex",alignItems:"center",gap:10,marginBottom:10 }}>
                  <span style={{ fontSize:20 }}>{p.icon}</span>
                  <div>
                    <div style={{ fontFamily:"'Share Tech Mono',monospace",fontSize:8,
                      color:p.active?"#00E5FF":"#3D5465",letterSpacing:1.5 }}>{p.phase}</div>
                    <div style={{ fontFamily:"'Rajdhani',sans-serif",fontSize:14,fontWeight:700,
                      color:p.active?"#E2E8F0":"#B0BEC5",marginTop:1 }}>{p.name}</div>
                  </div>
                  {p.active && (
                    <div style={{ marginLeft:"auto" }}>
                      <Dot color="#00E5FF" size={7}/>
                    </div>
                  )}
                </div>
                <div style={{ display:"flex",flexWrap:"wrap",gap:5 }}>
                  {p.techs.map(t => (
                    <span key={t} style={{ fontFamily:"'Share Tech Mono',monospace",fontSize:9,
                      color:p.active?"#4FC3F7":"#455A64",
                      background:p.active?"rgba(79,195,247,0.1)":"rgba(255,255,255,0.03)",
                      border:`1px solid ${p.active?"rgba(79,195,247,0.25)":"rgba(255,255,255,0.06)"}`,
                      padding:"2px 7px",borderRadius:3 }}>{t}</span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ════════════════════════════════════════════════════════════════
          SECTION 6 — INTEGRATIONS
      ════════════════════════════════════════════════════════════════ */}
      <section id="integrations" style={{ position:"relative",zIndex:5,padding:"90px 60px",
        background:"rgba(0,176,255,0.02)",borderTop:"1px solid rgba(0,176,255,0.07)" }}>
        <div style={{ maxWidth:1100,margin:"0 auto" }}>
          <div className="sr" style={{ textAlign:"center",marginBottom:52 }}>
            <div style={{ fontFamily:"'Share Tech Mono',monospace",fontSize:9,
              color:"#546E7A",letterSpacing:4,marginBottom:10 }}>ECOSYSTEM</div>
            <h3 style={{ fontFamily:"'Rajdhani',sans-serif",fontSize:36,fontWeight:700,
              color:"#E2E8F0",letterSpacing:2 }}>11+ INTEGRATIONS</h3>
          </div>
          <div style={{ display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:14 }}>
            {[
              { name:"Slack",         icon:"💬", color:"#4FC3F7", desc:"Real-time threat alerts + @oncall"     },
              { name:"PagerDuty",     icon:"🚨", color:"#E53935", desc:"P0/P1 on-call escalation"             },
              { name:"Jira",          icon:"📋", color:"#4FC3F7", desc:"Auto ticket creation + linking"       },
              { name:"ServiceNow",    icon:"🔧", color:"#00E676", desc:"ITSM incident auto-creation"          },
              { name:"Microsoft Teams",icon:"💼",color:"#4FC3F7", desc:"Adaptive card threat notifications"   },
              { name:"Grafana",       icon:"📈", color:"#FF6D00", desc:"Real-time SOC dashboards"             },
              { name:"AbuseIPDB",     icon:"🛡️", color:"#E53935", desc:"Live IP reputation lookup"            },
              { name:"NVD / CISA",    icon:"📋", color:"#FFD740", desc:"CVE intelligence feed"                },
              { name:"MITRE ATT&CK",  icon:"🎯", color:"#FF6D00", desc:"Technique mapping + TTP coverage"    },
              { name:"OTX AlienVault",icon:"🔭", color:"#00E676", desc:"Open threat exchange IOCs"           },
              { name:"Prometheus",    icon:"📊", color:"#E53935", desc:"Metrics collection + alerting"        },
              { name:"n8n SOAR",      icon:"⚙️",  color:"#4FC3F7", desc:"5 automation workflows"              },
            ].map((item,i) => (
              <div key={item.name} className={`sr-up d${(i%4)+1} int-card`}
                style={{ background:"rgba(5,12,22,0.92)",border:`1px solid ${item.color}20`,
                  borderRadius:10,padding:"18px 16px",cursor:"default" }}
                onMouseEnter={e=>{ e.currentTarget.style.borderColor=item.color; e.currentTarget.style.boxShadow=`0 0 20px ${item.color}20`; }}
                onMouseLeave={e=>{ e.currentTarget.style.borderColor=`${item.color}20`; e.currentTarget.style.boxShadow=""; }}>
                <div style={{ fontSize:22,marginBottom:8 }}>{item.icon}</div>
                <div style={{ fontFamily:"'Share Tech Mono',monospace",fontSize:11,
                  color:item.color,marginBottom:5,letterSpacing:0.5 }}>{item.name}</div>
                <div style={{ fontSize:11,color:"#546E7A",lineHeight:1.5,
                  fontFamily:"'DM Sans',sans-serif" }}>{item.desc}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ════════════════════════════════════════════════════════════════
          SECTION 7 — TECH STACK
      ════════════════════════════════════════════════════════════════ */}
      <section id="stack" style={{ position:"relative",zIndex:5,padding:"90px 60px",
        borderTop:"1px solid rgba(0,176,255,0.07)" }}>
        <div style={{ maxWidth:1100,margin:"0 auto" }}>
          <div className="sr" style={{ textAlign:"center",marginBottom:52 }}>
            <div style={{ fontFamily:"'Share Tech Mono',monospace",fontSize:9,
              color:"#546E7A",letterSpacing:4,marginBottom:10 }}>TECHNOLOGY</div>
            <h3 style={{ fontFamily:"'Rajdhani',sans-serif",fontSize:36,fontWeight:700,
              color:"#E2E8F0",letterSpacing:2 }}>TECH STACK</h3>
          </div>
          <div style={{ display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:14 }}>
            {[
              { name:"GPT-4o Mini",      sub:"AI agent backbone · 9 tools",   icon:"🤖", color:"#FF6D00" },
              { name:"Apache Kafka",     sub:"5 topics · guaranteed delivery", icon:"⚡", color:"#4FC3F7" },
              { name:"ChromaDB",         sub:"Vector DB · cosine similarity",  icon:"🔍", color:"#00E676" },
              { name:"TimescaleDB",      sub:"PostgreSQL · hypertable · 30d",  icon:"🗄️", color:"#90CAF9" },
              { name:"Redis 7",          sub:"Blocklist · cache · dedup TTL",  icon:"⚡", color:"#E53935" },
              { name:"Scapy + Npcap",    sub:"DPI · BPF filter · raw socket", icon:"📡", color:"#FFD740" },
              { name:"FastAPI",          sub:"REST · JWT auth · Swagger",      icon:"🚀", color:"#4FC3F7" },
              { name:"n8n",              sub:"SOAR · self-hosted · 5 flows",   icon:"⚙️",  color:"#00E676" },
              { name:"Playwright",       sub:"Headless CTI scraping",          icon:"🌐", color:"#A5D6A7" },
              { name:"Grafana",          sub:"Real-time SOC dashboards",       icon:"📈", color:"#FF6D00" },
              { name:"Docker Compose",   sub:"14 services · one command up",   icon:"🐳", color:"#4FC3F7" },
              { name:"React + Vite",     sub:"SOC dashboard · hot reload",     icon:"⚛️",  color:"#61DAFB" },
            ].map((t,i) => (
              <div key={t.name} className={`sr-up d${(i%4)+1} tech-card`}
                style={{ background:"rgba(5,12,22,0.92)",border:`1px solid ${t.color}20`,
                  borderRadius:10,padding:"20px 16px" }}
                onMouseEnter={e=>{ e.currentTarget.style.borderColor=t.color; e.currentTarget.style.boxShadow=`0 8px 28px ${t.color}18`; }}
                onMouseLeave={e=>{ e.currentTarget.style.borderColor=`${t.color}20`; e.currentTarget.style.boxShadow=""; }}>
                <div style={{ fontSize:24,marginBottom:8 }}>{t.icon}</div>
                <div style={{ fontFamily:"'Share Tech Mono',monospace",fontSize:11,
                  color:t.color,fontWeight:700,marginBottom:4 }}>{t.name}</div>
                <div style={{ fontSize:11,color:"#546E7A",lineHeight:1.5 }}>{t.sub}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ════════════════════════════════════════════════════════════════
          SECTION 8 — ARCHITECTURE LAYERS
      ════════════════════════════════════════════════════════════════ */}
      <section style={{ position:"relative",zIndex:5,padding:"90px 60px",
        background:"rgba(2,6,16,0.8)",borderTop:"1px solid rgba(0,176,255,0.07)" }}>
        <div style={{ maxWidth:1100,margin:"0 auto" }}>
          <div className="sr" style={{ textAlign:"center",marginBottom:52 }}>
            <div style={{ fontFamily:"'Share Tech Mono',monospace",fontSize:9,
              color:"#546E7A",letterSpacing:4,marginBottom:10 }}>SYSTEM DESIGN</div>
            <h3 style={{ fontFamily:"'Rajdhani',sans-serif",fontSize:36,fontWeight:700,
              color:"#E2E8F0",letterSpacing:2 }}>FOUR-LAYER ARCHITECTURE</h3>
          </div>
          {[
            { layer:"L1", label:"INGESTION",     color:"#4FC3F7", nodes:[
              { icon:"📡", title:"DPI SENSOR",     sub:"Scapy · Npcap · BPF · raw socket capture" },
              { icon:"🌐", title:"CTI SCRAPER",    sub:"Playwright · NVD · CISA · Abuse.ch · MITRE · OTX" },
              { icon:"⚡", title:"KAFKA BUS",      sub:"5 topics · ordered delivery · replay buffer" },
            ]},
            { layer:"L2", label:"INTELLIGENCE",  color:"#00E676", nodes:[
              { icon:"🧠", title:"RLM ENGINE",     sub:"EMA behavioral profiles · α=0.1 low-pass filter" },
              { icon:"🔍", title:"CHROMADB",       sub:"Vector embeddings · cosine similarity · 3 collections" },
              { icon:"📊", title:"TIMESCALEDB",    sub:"Hypertable · 30-day retention · continuous aggregates" },
            ]},
            { layer:"L3", label:"ORCHESTRATION", color:"#FF6D00", nodes:[
              { icon:"🤖", title:"MCP AGENTS",     sub:"GPT-4o mini · 5 agents · 9 tools · agentic loop" },
              { icon:"🔗", title:"KAFKA BRIDGE",   sub:"Routes events → n8n webhooks · dedup filter" },
              { icon:"🛠️", title:"n8n SOAR",        sub:"5 workflows · 11+ integrations · auto-response" },
            ]},
            { layer:"L4", label:"DELIVERY",      color:"#E53935", nodes:[
              { icon:"🚀", title:"FASTAPI",        sub:"JWT auth · 12 endpoints · Swagger · WebSocket" },
              { icon:"📈", title:"GRAFANA",        sub:"Real-time SOC dashboards · Prometheus metrics" },
              { icon:"📣", title:"INTEGRATIONS",   sub:"Slack · PagerDuty · Jira · Teams · ServiceNow" },
            ]},
          ].map((layer) => (
            <div key={layer.layer} className="sr" style={{ marginBottom:32 }}>
              <div style={{ display:"flex",alignItems:"center",gap:18,marginBottom:14 }}>
                <div style={{ fontFamily:"'Share Tech Mono',monospace",fontSize:10,
                  color:layer.color,background:`${layer.color}14`,
                  padding:"4px 14px",borderRadius:4,letterSpacing:2,
                  border:`1px solid ${layer.color}28` }}>{layer.layer} · {layer.label}</div>
                <div style={{ flex:1,height:1,
                  background:`linear-gradient(90deg,${layer.color}38,transparent)` }}/>
              </div>
              <div style={{ display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:14 }}>
                {layer.nodes.map(n => (
                  <div key={n.title}
                    style={{ background:"rgba(7,16,27,0.95)",border:`1px solid ${layer.color}25`,
                      borderRadius:9,padding:"18px 16px",transition:"all 0.22s" }}
                    onMouseEnter={e=>{ e.currentTarget.style.borderColor=layer.color; e.currentTarget.style.boxShadow=`0 0 22px ${layer.color}25`; }}
                    onMouseLeave={e=>{ e.currentTarget.style.borderColor=`${layer.color}25`; e.currentTarget.style.boxShadow=""; }}>
                    <div style={{ fontSize:24,marginBottom:8 }}>{n.icon}</div>
                    <div style={{ fontFamily:"'Share Tech Mono',monospace",fontSize:10,
                      color:layer.color,letterSpacing:1,marginBottom:5 }}>{n.title}</div>
                    <div style={{ fontSize:11,color:"#546E7A",lineHeight:1.55 }}>{n.sub}</div>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* ════════════════════════════════════════════════════════════════
          FOOTER
      ════════════════════════════════════════════════════════════════ */}
      <footer style={{ position:"relative",zIndex:5,padding:"44px 60px",
        borderTop:"1px solid rgba(0,176,255,0.1)",
        background:"rgba(2,8,18,0.95)",
        display:"flex",alignItems:"center",justifyContent:"space-between",flexWrap:"wrap",gap:20 }}>
        <div style={{ display:"flex",alignItems:"center",gap:12 }}>
          <div style={{ width:32,height:32,borderRadius:7,
            background:"linear-gradient(135deg,#1565C0,#0A2A60)",
            display:"flex",alignItems:"center",justifyContent:"center",fontSize:16,
            boxShadow:"0 0 16px rgba(21,101,192,0.4)" }}>🛡️</div>
          <div>
            <div style={{ fontFamily:"'Orbitron',monospace",fontSize:12,fontWeight:700,
              color:"#E2E8F0",letterSpacing:3 }}>CYBERSENTINEL AI</div>
            <div style={{ fontFamily:"'Share Tech Mono',monospace",fontSize:8,
              color:"#4FC3F7",letterSpacing:2,marginTop:2 }}>AUTONOMOUS SOC PLATFORM v1.1</div>
          </div>
        </div>
        <div style={{ fontFamily:"'Share Tech Mono',monospace",fontSize:10,color:"#3D5465" }}>
          Capstone 2025 · Built with Claude AI + GPT-4o mini · Open Source
        </div>
        <div style={{ display:"flex",gap:20 }}>
          {[["API Docs","http://localhost:8080/docs"],["Dashboard","http://localhost:8080"],["n8n","http://localhost:5678"],["Grafana","http://localhost:3001"]].map(([l,u]) => (
            <a key={l} href={u} target="_blank" rel="noopener noreferrer"
              style={{ fontFamily:"'Share Tech Mono',monospace",fontSize:10,
                color:"#4FC3F7",textDecoration:"none",opacity:0.65,transition:"opacity 0.2s" }}
              onMouseEnter={e=>e.target.style.opacity=1}
              onMouseLeave={e=>e.target.style.opacity=0.65}>{l} ↗</a>
          ))}
        </div>
      </footer>
    </div>
  );
}
