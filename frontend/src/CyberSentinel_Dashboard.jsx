import { useState, useEffect, useCallback, useRef } from "react";
import { LineChart, Line, AreaChart, Area, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, RadarChart, Radar, PolarGrid, PolarAngleAxis } from "recharts";

const API = "";

// ── Mock data for offline demo ─────────────────────────────────────────────
const MOCK = {
  dashboard: { total_alerts_24h:1247, critical_alerts_24h:23, high_alerts_24h:89, active_incidents:7, blocked_ips:34, unique_ips_seen:2841, risk_score:0.62,
    top_threat_types:[{type:"C2_BEACON_DETECTED",count:23},{type:"PORT_SCAN_DETECTED",count:67},{type:"DGA_MALWARE_DETECTED",count:31},{type:"DATA_EXFILTRATION",count:12},{type:"HIGH_ENTROPY_PAYLOAD",count:89}]
  },
  alerts: [
    {id:"a1",type:"C2_BEACON_DETECTED",severity:"CRITICAL",src_ip:"10.0.0.55",dst_ip:"185.220.101.47",timestamp:new Date(Date.now()-120000).toISOString(),mitre_technique:"T1071.001",anomaly_score:0.91},
    {id:"a2",type:"DGA_MALWARE_DETECTED",severity:"HIGH",src_ip:"10.0.1.23",dst_ip:"8.8.8.8",timestamp:new Date(Date.now()-340000).toISOString(),mitre_technique:"T1568.002",anomaly_score:0.78},
    {id:"a3",type:"PORT_SCAN_DETECTED",severity:"MEDIUM",src_ip:"192.168.5.10",dst_ip:"10.0.0.1",timestamp:new Date(Date.now()-600000).toISOString(),mitre_technique:"T1046",anomaly_score:0.54},
    {id:"a4",type:"DATA_EXFILTRATION_DETECTED",severity:"CRITICAL",src_ip:"10.0.2.88",dst_ip:"203.0.113.45",timestamp:new Date(Date.now()-900000).toISOString(),mitre_technique:"T1048",anomaly_score:0.87},
    {id:"a5",type:"HIGH_ENTROPY_PAYLOAD",severity:"HIGH",src_ip:"10.0.0.71",dst_ip:"45.33.32.156",timestamp:new Date(Date.now()-1200000).toISOString(),mitre_technique:"T1071.001",anomaly_score:0.73},
    {id:"a6",type:"CLEARTEXT_CREDENTIALS",severity:"HIGH",src_ip:"10.0.3.12",dst_ip:"10.0.0.1",timestamp:new Date(Date.now()-1800000).toISOString(),mitre_technique:"T1003",anomaly_score:0.69},
    {id:"a7",type:"TTL_ANOMALY",severity:"LOW",src_ip:"172.16.0.5",dst_ip:"10.0.0.254",timestamp:new Date(Date.now()-2400000).toISOString(),mitre_technique:"T1595",anomaly_score:0.31},
    {id:"a8",type:"LATERAL_MOVEMENT_DETECTED",severity:"CRITICAL",src_ip:"10.0.1.45",dst_ip:"10.0.1.200",timestamp:new Date(Date.now()-3000000).toISOString(),mitre_technique:"T1021.002",anomaly_score:0.94},
  ],
  incidents: [
    {incident_id:"INC-001",title:"C2 Beacon Detected — 10.0.0.55",severity:"CRITICAL",status:"INVESTIGATING",affected_ips:["10.0.0.55"],mitre_techniques:["T1071.001"],created_at:new Date(Date.now()-7200000).toISOString()},
    {incident_id:"INC-002",title:"Data Exfiltration Attempt — 10.0.2.88",severity:"CRITICAL",status:"OPEN",affected_ips:["10.0.2.88"],mitre_techniques:["T1048"],created_at:new Date(Date.now()-3600000).toISOString()},
    {incident_id:"INC-003",title:"Lateral Movement — Finance Subnet",severity:"HIGH",status:"OPEN",affected_ips:["10.0.1.45","10.0.1.200"],mitre_techniques:["T1021.002"],created_at:new Date(Date.now()-1800000).toISOString()},
    {incident_id:"INC-004",title:"DGA Malware Activity — 10.0.1.23",severity:"HIGH",status:"RESOLVED",affected_ips:["10.0.1.23"],mitre_techniques:["T1568.002"],created_at:new Date(Date.now()-86400000).toISOString()},
  ],
  campaigns: [
    {campaign_id:"CAMP-001",src_ip:"10.0.0.55",max_severity:"CRITICAL",incident_count:4,first_seen:new Date(Date.now()-18000000).toISOString(),last_seen:new Date(Date.now()-120000).toISOString(),mitre_stages:["T1190","T1059.004","T1071.001","T1041"],campaign_summary:"Multi-stage intrusion: initial exploitation via public-facing application, followed by C2 beacon establishment and data exfiltration."},
    {campaign_id:"CAMP-002",src_ip:"10.0.2.88",max_severity:"CRITICAL",incident_count:3,first_seen:new Date(Date.now()-14400000).toISOString(),last_seen:new Date(Date.now()-900000).toISOString(),mitre_stages:["T1046","T1021.002","T1048"],campaign_summary:"Reconnaissance scan escalated to lateral movement across Finance subnet with attempted data exfiltration."},
    {campaign_id:"CAMP-003",src_ip:"192.168.5.10",max_severity:"HIGH",incident_count:2,first_seen:new Date(Date.now()-7200000).toISOString(),last_seen:new Date(Date.now()-3600000).toISOString(),mitre_stages:["T1110.003","T1078"],campaign_summary:"Credential access attempt via password spraying. One account may be compromised."},
  ],
};

const MITRE_PLAYBOOK = {
  "T1071.001": {
    name: "Application Layer Protocol: Web Protocols",
    steps: [
      "Immediate: Block destination IP on perimeter firewall. Isolate source host from network.",
      "Immediate: Kill any suspicious outbound processes on source host (check Task Manager / ps aux).",
      "Short-term: Review all outbound HTTPS/HTTP connections from source host over past 24h.",
      "Short-term: Scan source host for malware — run EDR full scan or ClamAV.",
      "Verify resolved when: No further connections from source IP to destination for 2+ hours.",
    ]
  },
  "T1071.004": {
    name: "Application Layer Protocol: DNS",
    steps: [
      "Immediate: Block source IP's DNS traffic at the recursive resolver level.",
      "Immediate: Sinkhole the destination DNS server if controlled by attacker.",
      "Short-term: Review all DNS queries from source host — look for long subdomain strings.",
      "Short-term: Enable DNS logging and set alerts for queries > 40 chars.",
      "Verify resolved when: DNS query rate from source drops to normal baseline (< 5/min).",
    ]
  },
  "T1048.003": {
    name: "Exfiltration Over Asymmetric Encrypted Non-C2 Protocol",
    steps: [
      "Immediate: Block destination IP on firewall. Stop any active transfer immediately.",
      "Immediate: Identify what data directories were accessible from the source host.",
      "Short-term: Review outbound transfer logs — determine total data volume exfiltrated.",
      "Short-term: Check for staging directories (Temp, Downloads, /tmp) on source host.",
      "Verify resolved when: No further large outbound transfers (> 10MB) from source host.",
    ]
  },
  "T1021.002": {
    name: "Remote Services: SMB/Windows Admin Shares",
    steps: [
      "Immediate: Reset credentials on source host — assume password is compromised.",
      "Immediate: Block SMB (port 445) between workstations at network level.",
      "Short-term: Audit all hosts the source IP connected to — check for persistence.",
      "Short-term: Review SMB share access logs on destination hosts.",
      "Verify resolved when: No further internal SMB connections from source host.",
    ]
  },
  "T1021.001": {
    name: "Remote Services: Remote Desktop Protocol",
    steps: [
      "Immediate: Terminate active RDP session. Block RDP (port 3389) from source IP.",
      "Immediate: Reset password for any account used in the RDP session.",
      "Short-term: Review RDP event logs on destination host (Event ID 4624, 4625).",
      "Short-term: Check for persistence mechanisms installed during the RDP session.",
      "Verify resolved when: No further RDP attempts from source IP.",
    ]
  },
  "T1046": {
    name: "Network Service Discovery",
    steps: [
      "Immediate: Block source IP at perimeter firewall.",
      "Immediate: Review what ports were scanned — prioritize securing any open ones found.",
      "Short-term: Check if source IP is an internal compromised host or external attacker.",
      "Short-term: Review firewall logs for follow-up exploitation attempts from same IP.",
      "Verify resolved when: No further scan traffic from source IP.",
    ]
  },
  "T1110.001": {
    name: "Brute Force: Password Guessing",
    steps: [
      "Immediate: Block source IP at firewall. Enable account lockout if not already active.",
      "Immediate: Check if any account was successfully compromised — review auth success logs.",
      "Short-term: Force password reset on any accounts targeted by the brute force.",
      "Short-term: Enable MFA on SSH/targeted service.",
      "Verify resolved when: Zero authentication attempts from source IP.",
    ]
  },
  "T1110.003": {
    name: "Brute Force: Password Spraying",
    steps: [
      "Immediate: Block source IP. Identify all accounts targeted in the spray.",
      "Immediate: Check authentication logs for any successful logins from source IP.",
      "Short-term: Force password reset for all targeted accounts as precaution.",
      "Short-term: Implement MFA on the targeted service (LDAP/web login).",
      "Verify resolved when: No auth attempts from source IP, all targeted accounts secured.",
    ]
  },
  "T1190": {
    name: "Exploit Public-Facing Application",
    steps: [
      "Immediate: Block source IP at WAF/firewall. Check if exploit succeeded (review app logs).",
      "Immediate: If exploited — isolate the affected server immediately.",
      "Short-term: Apply vendor patch or virtual patch via WAF rule.",
      "Short-term: Review application logs for signs of post-exploitation (file writes, new processes).",
      "Verify resolved when: Source IP blocked, application patched, no anomalous server behavior.",
    ]
  },
  "T1027": {
    name: "Obfuscated Files or Information",
    steps: [
      "Immediate: Block destination IP. Isolate source host for forensic analysis.",
      "Immediate: Capture memory dump of source host before clearing.",
      "Short-term: Submit suspicious payload samples to sandbox (Any.run, VirusTotal).",
      "Short-term: Check source host for new processes, scheduled tasks, or registry run keys.",
      "Verify resolved when: Source host clean on full AV scan, no further encrypted outbound traffic.",
    ]
  },
  "T1572": {
    name: "Protocol Tunneling",
    steps: [
      "Immediate: Block the tunnel traffic (ICMP/DNS) to/from the destination IP.",
      "Immediate: Isolate source host — tunneling indicates established attacker access.",
      "Short-term: Review all traffic from source host for additional covert channels.",
      "Short-term: Check for installed tools (iodine, dnscat2, ptunnel) on source host.",
      "Verify resolved when: No abnormal ICMP/DNS payloads from source for 1+ hour.",
    ]
  },
  "T1059.004": {
    name: "Command and Scripting Interpreter: Unix Shell",
    steps: [
      "Immediate: ISOLATE source host immediately — attacker has interactive shell access.",
      "Immediate: Block all outbound traffic from source host at network level.",
      "Short-term: Forensic analysis — review bash history, cron jobs, /tmp, new user accounts.",
      "Short-term: Re-image the host — assume full compromise, do not trust existing OS.",
      "Verify resolved when: Host reimaged and re-deployed, no further outbound shell traffic.",
    ]
  },
};
const MITRE_FALLBACK = {
  name: "Unknown Technique",
  steps: [
    "Immediate: Isolate the affected host from the network.",
    "Immediate: Preserve logs and take a memory snapshot before any remediation.",
    "Short-term: Check for persistence mechanisms (scheduled tasks, registry run keys, startup items, cron jobs).",
    "Short-term: Review all network connections from the affected host.",
    "Verify resolved when: Host is clean on full security scan and no anomalous network activity.",
  ]
};

function genTimeData() {
  return Array.from({length:24},(_,i)=>({ h:`${String(i).padStart(2,"0")}:00`, critical:Math.floor(Math.random()*8), high:Math.floor(Math.random()*20), medium:Math.floor(Math.random()*40) }));
}

function buildTimeData(alertsByHour) {
  // Always start with zeroed buckets — never use random data when API is live
  const buckets = {};
  for (let i=0;i<24;i++) buckets[String(i).padStart(2,"0")] = {critical:0,high:0,medium:0};
  if (alertsByHour && alertsByHour.length) {
    for (const row of alertsByHour) {
      const h = String(new Date(row.hour).getUTCHours()).padStart(2,"0");
      const sev = (row.severity||"").toUpperCase();
      if (sev==="CRITICAL") buckets[h].critical += row.count;
      else if (sev==="HIGH") buckets[h].high += row.count;
      else buckets[h].medium += row.count;
    }
  }
  return Object.entries(buckets).map(([h,v])=>({h:`${h}:00`,...v}));
}

// ── Helpers ────────────────────────────────────────────────────────────────
const SEV_COLOR = { CRITICAL:"#E53935", HIGH:"#FF6D00", MEDIUM:"#FFD740", LOW:"#4FC3F7", INFO:"#78909C" };
const SEV_BG =    { CRITICAL:"rgba(229,57,53,0.15)", HIGH:"rgba(255,109,0,0.12)", MEDIUM:"rgba(255,215,64,0.12)", LOW:"rgba(79,195,247,0.12)", INFO:"rgba(120,144,156,0.1)" };
const STATUS_COLOR = { OPEN:"#E53935", INVESTIGATING:"#FF6D00", RESOLVED:"#00E676", CLOSED:"#546E7A" };

function ago(ts) {
  const s = Math.floor((Date.now()-new Date(ts))/1000);
  if (s<60) return `${s}s ago`;
  if (s<3600) return `${Math.floor(s/60)}m ago`;
  return `${Math.floor(s/3600)}h ago`;
}

function SevBadge({ s }) {
  return <span style={{ fontFamily:"monospace", fontSize:10, fontWeight:700, color:SEV_COLOR[s]||"#fff", background:SEV_BG[s]||"transparent", padding:"2px 8px", borderRadius:3, border:`1px solid ${SEV_COLOR[s]||"#fff"}40`, letterSpacing:1 }}>{s}</span>;
}

function ThreatDot({ color="#E53935", size=7 }) {
  return (
    <span style={{ position:"relative", display:"inline-flex", alignItems:"center", justifyContent:"center", width:size+6, height:size+6 }}>
      <span style={{ position:"absolute", width:size+6, height:size+6, borderRadius:"50%", background:color, opacity:0.3, animation:"ping 1.5s infinite" }}/>
      <span style={{ width:size, height:size, borderRadius:"50%", background:color, display:"block" }}/>
    </span>
  );
}

function MetricCard({ label, value, sub, color, live, icon }) {
  const [display, setDisplay] = useState(0);
  const raf = useRef(null);
  useEffect(() => {
    const target = Number(value) || 0;
    const duration = 600;
    const start = performance.now();
    const from = display;
    cancelAnimationFrame(raf.current);
    function step(now) {
      const p = Math.min((now - start) / duration, 1);
      const ease = 1 - Math.pow(1 - p, 3);
      setDisplay(Math.round(from + (target - from) * ease));
      if (p < 1) raf.current = requestAnimationFrame(step);
    }
    raf.current = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf.current);
  }, [value]);
  return (
    <div style={{
      background:"rgba(8,18,30,0.82)", backdropFilter:"blur(10px)",
      border:`1px solid ${color}28`, borderRadius:10, padding:"20px 22px",
      boxShadow:`inset 0 1px 0 ${color}18, 0 6px 24px rgba(0,0,0,0.4)`,
      transition:"border-color 0.3s, box-shadow 0.3s",
    }}
    onMouseEnter={e=>{ e.currentTarget.style.borderColor=`${color}55`; e.currentTarget.style.boxShadow=`inset 0 1px 0 ${color}25, 0 6px 32px rgba(0,0,0,0.5), 0 0 20px ${color}18`; }}
    onMouseLeave={e=>{ e.currentTarget.style.borderColor=`${color}28`; e.currentTarget.style.boxShadow=`inset 0 1px 0 ${color}18, 0 6px 24px rgba(0,0,0,0.4)`; }}>
      <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start", marginBottom:12 }}>
        <div style={{ display:"flex", alignItems:"center", gap:6 }}>
          {live && <ThreatDot color={color} size={5}/>}
          <span style={{ fontFamily:"'Share Tech Mono',monospace", fontSize:9, color:"#546E7A", letterSpacing:2, textTransform:"uppercase" }}>{label}</span>
        </div>
        <span style={{ fontSize:18, opacity:0.55 }}>{icon}</span>
      </div>
      <div className="metric-val" style={{ fontFamily:"'Share Tech Mono',monospace", fontSize:34, fontWeight:700, color, lineHeight:1, marginBottom:4 }}>{display}</div>
      {sub && <div style={{ fontSize:11, color:"#546E7A" }}>{sub}</div>}
    </div>
  );
}

function Panel({ title, badge, children, style={} }) {
  return (
    <div className="dash-panel panel-in" style={{
      background:"rgba(7,16,27,0.8)", backdropFilter:"blur(12px)",
      border:"1px solid rgba(79,195,247,0.1)",
      borderRadius:12, overflow:"hidden", display:"flex", flexDirection:"column", ...style
    }}>
      <div style={{
        padding:"12px 18px", borderBottom:"1px solid rgba(79,195,247,0.07)",
        display:"flex", alignItems:"center", justifyContent:"space-between",
        background:"rgba(79,195,247,0.025)",
      }}>
        <span style={{ fontFamily:"'Share Tech Mono',monospace", fontSize:10, color:"#4FC3F7", letterSpacing:2, textTransform:"uppercase" }}>{title}</span>
        {badge && <span style={{ fontFamily:"monospace", fontSize:10, color:"#546E7A" }}>{badge}</span>}
      </div>
      <div style={{ flex:1, overflow:"auto" }}>{children}</div>
    </div>
  );
}

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div style={{ background:"rgba(5,13,21,0.95)", border:"1px solid rgba(79,195,247,0.3)", borderRadius:6, padding:"10px 14px" }}>
      <div style={{ fontFamily:"monospace", fontSize:11, color:"#4FC3F7", marginBottom:6 }}>{label}</div>
      {payload.map(p => (
        <div key={p.name} style={{ fontSize:11, color:p.color, fontFamily:"monospace" }}>{p.name}: {p.value}</div>
      ))}
    </div>
  );
};

// ══════════════════════════════════════════════════════════════════════════
// MAIN SOC DASHBOARD
// ══════════════════════════════════════════════════════════════════════════
export default function SOCDashboard() {
  const [tab, setTab] = useState("overview");
  const [activeMode, setActiveMode] = useState("simulator"); // "simulator" | "dpi"
  const [data, setData] = useState({ dash:MOCK.dashboard, alerts:[], incidents:[] });
  const [apiLive, setApiLive] = useState(false);
  const [timeData, setTimeData] = useState(genTimeData);
  const [investigationsPaused, setInvestigationsPaused] = useState({ simulator: false, dpi: false });
  const [searchIp, setSearchIp] = useState("");
  const [hostProfile, setHostProfile] = useState(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [threatResults, setThreatResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [token, setToken] = useState("");
  const [loginUser, setLoginUser] = useState("admin");
  const [loginPass, setLoginPass] = useState("cybersentinel2025");
  const [loginError, setLoginError] = useState("");
  const [authed, setAuthed] = useState(false);
  const [tick, setTick] = useState(0);
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [feedFilter, setFeedFilter] = useState("ALL");   // severity filter for threat feed
  const [feedSearch, setFeedSearch] = useState("");       // free-text search for threat feed
  const [expandedCard, setExpandedCard] = useState(null); // expanded threat card id
  const [incidentDetail, setIncidentDetail] = useState(null);
  const [threatSigs, setThreatSigs] = useState([]);
  const [drawerLoading, setDrawerLoading] = useState(false);
  const [incidentNotes, setIncidentNotes] = useState('');
  const [remediationLoading, setRemediationLoading] = useState(false);
  const [generatedRemediation, setGeneratedRemediation] = useState(null);
  const [blockRecs, setBlockRecs] = useState([]);
  const [blockAction, setBlockAction] = useState({});
  const [firewallRules, setFirewallRules] = useState([]);
  const [firewallFilter, setFirewallFilter] = useState("all"); // all | active | expired
  const [unblockAction, setUnblockAction] = useState({});
  const [n8nUrl, setN8nUrl] = useState(() => localStorage.getItem("cs_n8n_url") || "http://localhost:5678");
  const [wfStatus, setWfStatus] = useState({}); // { wfId: "idle"|"running"|"done"|"error" }
  const [pendingReports, setPendingReports] = useState([]);
  const [reportAction, setReportAction] = useState({}); // { reportId: "approving"|"denying"|"done"|"error" }
  const [campaigns, setCampaigns] = useState([]);
  const waterCanvasRef = useRef(null);

  // Water mosaic animation (login screen only)
  useEffect(() => {
    if (authed) return;
    const canvas = waterCanvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const TILE = 22;
    let t = 0, animId;
    const resize = () => { canvas.width = window.innerWidth; canvas.height = window.innerHeight; };
    resize();
    window.addEventListener('resize', resize);
    function draw() {
      t += 0.011;
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      const cols = Math.ceil(canvas.width / TILE) + 1;
      const rows = Math.ceil(canvas.height / TILE) + 1;
      for (let r = 0; r < rows; r++) {
        for (let c = 0; c < cols; c++) {
          const nx = c / cols - 0.5, ny = r / rows - 0.5;
          const dist = Math.sqrt(nx*nx + ny*ny);
          const w1 = Math.sin(dist * 13 - t * 2.1);
          const w2 = Math.sin(nx * 17 + t * 1.7) * Math.cos(ny * 13 - t * 0.85);
          const w3 = Math.cos((nx - ny) * 15 - t * 1.35);
          const w4 = Math.sin(dist * 7 + nx * 5 - t * 1.9);
          const wave = (w1 * 0.35 + w2 * 0.28 + w3 * 0.22 + w4 * 0.15);
          const v = (wave + 1) / 2;
          const rr = Math.floor(v * 14);
          const gg = Math.floor(18 + v * 95);
          const bb = Math.floor(55 + v * 148);
          ctx.fillStyle = `rgba(${rr},${gg},${bb},${0.1 + v * 0.25})`;
          ctx.fillRect(c * TILE, r * TILE, TILE - 2, TILE - 2);
          if (v > 0.76) {
            const hi = (v - 0.76) / 0.24;
            ctx.fillStyle = `rgba(79,195,247,${hi * 0.38})`;
            ctx.fillRect(c * TILE + 4, r * TILE + 4, TILE - 9, TILE - 9);
          }
          if (v < 0.22) {
            ctx.fillStyle = `rgba(2,8,18,${(0.22 - v) * 0.5})`;
            ctx.fillRect(c * TILE, r * TILE, TILE - 2, TILE - 2);
          }
        }
      }
      animId = requestAnimationFrame(draw);
    }
    draw();
    return () => { cancelAnimationFrame(animId); window.removeEventListener('resize', resize); };
  }, [authed]);

  // Scroll-reveal IntersectionObserver (landing page only)
  useEffect(() => {
    if (authed) return;
    const timer = setTimeout(() => {
      const obs = new IntersectionObserver(entries => {
        entries.forEach(e => {
          if (e.isIntersecting) {
            e.target.classList.add('visible');
            obs.unobserve(e.target);
          }
        });
      }, { threshold: 0.1 });
      document.querySelectorAll('.sr,.sr-l,.sr-r').forEach(el => obs.observe(el));
    }, 300);
    return () => clearTimeout(timer);
  }, [authed]);

  // Live clock
  useEffect(() => { const t = setInterval(()=>setTick(x=>x+1), 1000); return ()=>clearInterval(t); }, []);

  const fetchData = useCallback(async (tok, mode) => {
    const t = tok || token;
    const m = mode || activeMode;
    if (!t) return;
    const h = { Authorization:`Bearer ${t}` };
    try {
      const [d, a, i, ctrlSim, ctrlDpi] = await Promise.all([
        fetch(`${API}/api/v1/dashboard?source=${m}`, {headers:h}).then(r=>r.json()),
        fetch(`${API}/api/v1/alerts?limit=1000&source=${m}`, {headers:h}).then(r=>r.json()),
        fetch(`${API}/api/v1/incidents?limit=500&source=${m}`, {headers:h}).then(r=>r.json()),
        fetch(`${API}/api/v1/control?source=simulator`, {headers:h}).then(r=>r.json()).catch(()=>({})),
        fetch(`${API}/api/v1/control?source=dpi`, {headers:h}).then(r=>r.json()).catch(()=>({})),
      ]);
      setData({
        dash: d,
        alerts: Array.isArray(a) ? a : [],
        incidents: Array.isArray(i) ? i : [],
      });
      setTimeData(buildTimeData(d.alerts_by_hour));
      setInvestigationsPaused({
        simulator: ctrlSim.investigations_paused ?? false,
        dpi:       ctrlDpi.investigations_paused ?? false,
      });
      setApiLive(true);
    } catch { setApiLive(false); }
  }, [token, activeMode]);

  useEffect(() => { if (authed) { fetchData(); const t = setInterval(()=>fetchData(), 30000); return ()=>clearInterval(t); } }, [authed, fetchData]);

  const fetchBlockRecs = useCallback(async (mode) => {
    if (!token) return;
    const src = mode || activeMode;
    try {
      const r = await fetch(`${API}/api/v1/block-recommendations?source=${src}`, { headers:{ Authorization:`Bearer ${token}` } });
      if (r.ok) {
        const recs = await r.json();
        setBlockRecs(recs.filter(rec => rec.investigation_summary && !rec.investigation_summary.startsWith('⏸')));
      }
    } catch {}
  }, [token, activeMode]);

  const fetchFirewallRules = useCallback(async () => {
    if (!token) return;
    try {
      const r = await fetch(`${API}/api/v1/firewall-rules`, { headers:{ Authorization:`Bearer ${token}` } });
      if (r.ok) setFirewallRules(await r.json());
    } catch {}
  }, [token]);

  useEffect(() => { if (authed) { fetchBlockRecs(); const t = setInterval(()=>fetchBlockRecs(), 30000); return ()=>clearInterval(t); } }, [authed, fetchBlockRecs]);
  useEffect(() => { if (authed) { fetchFirewallRules(); const t = setInterval(()=>fetchFirewallRules(), 30000); return ()=>clearInterval(t); } }, [authed, fetchFirewallRules]);

  const fetchPendingReports = useCallback(async () => {
    if (!token) return;
    try {
      const r = await fetch(`${API}/api/v1/reports/pending?status=PENDING`, { headers: { Authorization: `Bearer ${token}` } });
      if (r.ok) setPendingReports(await r.json());
    } catch {}
  }, [token]);
  useEffect(() => { if (authed) { fetchPendingReports(); const t = setInterval(fetchPendingReports, 20000); return ()=>clearInterval(t); } }, [authed, fetchPendingReports]);

  const fetchCampaigns = useCallback(async (mode) => {
    if (!token) return;
    const src = mode || activeMode;
    try {
      const r = await fetch(`${API}/api/v1/campaigns?source=${src}`, { headers:{ Authorization:`Bearer ${token}` } });
      if (r.ok) setCampaigns(await r.json());
    } catch {}
  }, [token, activeMode]);
  useEffect(() => { if (authed) { fetchCampaigns(); const t = setInterval(fetchCampaigns, 30000); return ()=>clearInterval(t); } }, [authed, fetchCampaigns]);

  async function login() {
    setLoading(true); setLoginError("");
    try {
      const r = await fetch(`${API}/auth/token`, { method:"POST", headers:{"Content-Type":"application/x-www-form-urlencoded"}, body:`username=${loginUser}&password=${loginPass}` });
      if (r.ok) { const j = await r.json(); setToken(j.access_token); setAuthed(true); fetchData(j.access_token); }
      else { setLoginError("Invalid credentials. Check username and password."); }
    } catch { setLoginError("API offline — ensure all containers are running."); }
    setLoading(false);
  }

  async function toggleInvestigations(src) {
    const source = src || activeMode;
    const newState = !investigationsPaused[source];
    try {
      await fetch(`${API}/api/v1/control?source=${source}`, {
        method: "POST",
        headers: { Authorization:`Bearer ${token}`, "Content-Type":"application/json" },
        body: JSON.stringify({ investigations_paused: newState }),
      });
      setInvestigationsPaused(prev => ({ ...prev, [source]: newState }));
    } catch { setInvestigationsPaused(prev => ({ ...prev, [source]: newState })); }
  }

  async function searchHost() {
    if (!searchIp.trim()) return;
    setHostProfile(null); setLoading(true);
    try {
      const r = await fetch(`${API}/api/v1/hosts/${searchIp}`, { headers:{ Authorization:`Bearer ${token}` } });
      setHostProfile(r.ok ? await r.json() : null);
    } catch { setHostProfile(null); }
    setLoading(false);
  }

  async function runThreatSearch() {
    if (!searchQuery.trim()) return;
    setThreatResults([]); setLoading(true);
    try {
      const r = await fetch(`${API}/api/v1/threat-search`, { method:"POST", headers:{ Authorization:`Bearer ${token}`, "Content-Type":"application/json" }, body:JSON.stringify({query:searchQuery,n_results:5}) });
      setThreatResults(r.ok ? (await r.json()).results || [] : []);
    } catch { setThreatResults([]); }
    setLoading(false);
  }

  const openIncidentDrawer = async (inc) => {
    setSelectedIncident(inc);
    setIncidentNotes(inc.notes || '');
    setGeneratedRemediation(null);
    setThreatSigs([]);
    setIncidentDetail(null);
    setDrawerLoading(true);
    try {
      const h = { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' };
      const [detail, sigs] = await Promise.all([
        fetch(`${API}/api/v1/incidents/${inc.incident_id}/detail`, { headers: h }).then(r => r.json()),
        fetch(`${API}/api/v1/threat-search`, {
          method: 'POST', headers: h,
          body: JSON.stringify({ query: `${(inc.mitre_techniques||[]).join(' ')} ${inc.title}`, n_results: 3 })
        }).then(r => r.json()),
      ]);
      setIncidentDetail(detail);
      setThreatSigs(Array.isArray(sigs?.results) ? sigs.results : []);
    } catch(e) { console.error('Drawer load error:', e); }
    finally { setDrawerLoading(false); }
  };

  const updateIncidentStatus = async (incidentId, newStatus) => {
    try {
      const h = { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' };
      await fetch(`${API}/api/v1/incidents/${incidentId}/status`, {
        method: 'PATCH', headers: h,
        body: JSON.stringify({ status: newStatus, notes: incidentNotes }),
      });
      // Refresh incident list and detail
      const [detail, incidents] = await Promise.all([
        fetch(`${API}/api/v1/incidents/${incidentId}/detail`, { headers: h }).then(r => r.json()),
        fetch(`${API}/api/v1/incidents?limit=500&source=${activeMode}`, { headers: h }).then(r => r.json()),
      ]);
      setIncidentDetail(detail);
      setSelectedIncident(prev => ({ ...prev, status: newStatus }));
      setData(prev => ({ ...prev, incidents: Array.isArray(incidents) ? incidents : prev.incidents }));
    } catch(e) { console.error('Status update error:', e); }
  };

  const handleBlockIP = async (incidentId) => {
    setBlockAction(prev => ({ ...prev, [incidentId]: 'blocking' }));
    try {
      await fetch(`${API}/api/v1/incidents/${incidentId}/block`, {
        method: 'POST', headers: { Authorization:`Bearer ${token}` }
      });
      setBlockRecs(prev => prev.filter(r => r.incident_id !== incidentId));
      fetchData();
    } catch(e) { console.error('Block failed:', e); }
    setBlockAction(prev => { const n = {...prev}; delete n[incidentId]; return n; });
  };

  const handleDismissRec = async (incidentId) => {
    setBlockAction(prev => ({ ...prev, [incidentId]: 'dismissing' }));
    try {
      await fetch(`${API}/api/v1/incidents/${incidentId}/dismiss`, {
        method: 'POST', headers: { Authorization:`Bearer ${token}` }
      });
      setBlockRecs(prev => prev.filter(r => r.incident_id !== incidentId));
      fetchData();
    } catch(e) { console.error('Dismiss failed:', e); }
    setBlockAction(prev => { const n = {...prev}; delete n[incidentId]; return n; });
  };

  const handleUnblockIP = async (ip) => {
    // Strip CIDR suffix (e.g. /32) — pass as query param to avoid path-routing issues
    const cleanIp = ip.replace(/\/\d+$/, '');
    setUnblockAction(prev => ({ ...prev, [ip]: true }));
    try {
      const res = await fetch(`${API}/api/v1/firewall-rules?ip=${encodeURIComponent(cleanIp)}`, {
        method: 'DELETE', headers: { Authorization:`Bearer ${token}` }
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        console.error('Unblock failed:', err.detail || res.status);
      }
      await fetchFirewallRules();
      await fetchData(token, activeMode);
    } catch(e) { console.error('Unblock error:', e); }
    setUnblockAction(prev => { const n = {...prev}; delete n[ip]; return n; });
  };

  const generateAIRemediation = async () => {
    if (!selectedIncident) return;
    setRemediationLoading(true);
    try {
      const h = { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' };
      const mitre = (selectedIncident.mitre_techniques || []).join(', ') || 'Unknown';
      const context = `src: ${selectedIncident.affected_ips?.[0] || 'unknown'}, mitre: ${mitre}, type: ${selectedIncident.title}`;
      const res = await fetch(`${API}/api/v1/incidents/${selectedIncident.incident_id}/remediation`, {
        method: 'POST', headers: h,
        body: JSON.stringify({ mitre_technique: mitre, alert_context: context }),
      });
      const data = await res.json();
      setGeneratedRemediation(data.remediation);
    } catch(e) { console.error('Remediation error:', e); }
    finally { setRemediationLoading(false); }
  };

  const now = new Date();
  const timeStr = now.toTimeString().slice(0,8);
  const dateStr = now.toLocaleDateString("en-US",{weekday:"short",month:"short",day:"numeric"});
  const riskPct = Math.round((data.dash.risk_score??0)*100);
  const riskColor = riskPct>70?"#E53935":riskPct>40?"#FF6D00":"#00E676";

  const radarData = [
    {subject:"DPI",value:90},{subject:"RLM",value:78},{subject:"CTI",value:85},
    {subject:"SOAR",value:92},{subject:"AI Agents",value:88},{subject:"API",value:95},
  ];

  // ── Login screen (standalone — landing page is in CyberSentinel_Landing.jsx) ──
  if (!authed) return (
    <div style={{ background:"#020810", position:"relative", width:"100vw", height:"100vh",
      overflow:"hidden", display:"flex", alignItems:"center", justifyContent:"center",
      fontFamily:"'Share Tech Mono',monospace" }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;700;900&family=DM+Sans:wght@400;500&display=swap');
        *{box-sizing:border-box;margin:0;padding:0;}
        @keyframes waterBorder {0%{border-color:rgba(0,176,255,0.35)}33%{border-color:rgba(79,195,247,0.6)}66%{border-color:rgba(0,229,255,0.4)}100%{border-color:rgba(0,176,255,0.35)}}
        @keyframes cardScan    {0%{top:-4px;opacity:0}10%{opacity:0.6}85%{opacity:0.6}100%{top:100%;opacity:0}}
        @keyframes hologram    {0%{background-position:200% center}100%{background-position:-200% center}}
        @keyframes cornerPulse {0%,100%{opacity:0.55}50%{opacity:1}}
        @keyframes shimmerFlow {0%{transform:translateX(-100%)}100%{transform:translateX(200%)}}
        @keyframes hexGlow     {0%,100%{opacity:0.04}50%{opacity:0.09}}
        @keyframes topBar      {0%{background-position:0% 0%}100%{background-position:200% 0%}}
        @keyframes statusBlink {0%,100%{opacity:1}50%{opacity:0.3}}
        .water-card  {animation:waterBorder 4s ease-in-out infinite;}
        .holo-title  {background:linear-gradient(90deg,#4FC3F7,#00E5FF,#80DEEA,#00B0FF,#4FC3F7);background-size:200% auto;-webkit-background-clip:text;-webkit-text-fill-color:transparent;animation:hologram 3s linear infinite;}
        .s-dot       {animation:statusBlink 2s ease-in-out infinite;}
        .corner-br   {animation:cornerPulse 2.5s ease-in-out infinite;}
        .hex-bg      {animation:hexGlow 3s ease-in-out infinite;}
        .top-bar     {background:linear-gradient(90deg,transparent,#0D47A1,#00B0FF,#00E5FF,#0097A7,#00B0FF,transparent);background-size:200% 100%;animation:topBar 4s linear infinite;}
        .login-input:focus{border-color:rgba(0,229,255,0.6)!important;box-shadow:0 0 0 3px rgba(0,176,255,0.12),0 0 16px rgba(0,176,255,0.2)!important;outline:none!important;}
      `}</style>

      {/* Background */}
      <canvas ref={waterCanvasRef} style={{ position:"fixed",inset:0,zIndex:0,width:"100%",height:"100%",pointerEvents:"none" }}/>
      <div className="hex-bg" style={{ position:"fixed",inset:0,zIndex:1,pointerEvents:"none",
        backgroundImage:`url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='56' height='100'%3E%3Cpolygon points='28,2 54,16 54,44 28,58 2,44 2,16' fill='none' stroke='%2300B0FF' stroke-width='0.6'/%3E%3Cpolygon points='28,52 54,66 54,94 28,108 2,94 2,66' fill='none' stroke='%2300B0FF' stroke-width='0.6'/%3E%3C/svg%3E")`,
        backgroundSize:"56px 100px" }}/>
      <div style={{ position:"fixed",inset:0,zIndex:2,pointerEvents:"none",
        background:"radial-gradient(ellipse at 50% 50%,rgba(2,8,18,0.1) 0%,rgba(2,8,18,0.6) 60%,rgba(2,8,18,0.88) 100%)" }}/>
      <div className="top-bar" style={{ position:"fixed",top:0,left:0,right:0,height:2,zIndex:20,pointerEvents:"none" }}/>

      {/* Centered login card */}
      <div style={{ position:"relative",zIndex:5 }}>
        <div className="water-card" style={{
          width:"100%", maxWidth:400, position:"relative",
          background:"rgba(2,10,22,0.88)", backdropFilter:"blur(24px) saturate(160%)",
          WebkitBackdropFilter:"blur(24px) saturate(160%)",
          border:"1px solid rgba(0,176,255,0.35)", borderRadius:14,
          overflow:"hidden",
          boxShadow:"0 8px 40px rgba(0,0,0,0.7), 0 0 60px rgba(0,100,200,0.15), inset 0 1px 0 rgba(0,229,255,0.08)",
        }}>
          {/* Scan beam */}
          <div style={{ position:"absolute",left:0,right:0,height:2,zIndex:10,pointerEvents:"none",
            background:"linear-gradient(90deg,transparent,rgba(0,229,255,0.6),transparent)",
            animation:"cardScan 3.5s linear infinite" }}/>
          {/* Shimmer */}
          <div style={{ position:"absolute",inset:0,zIndex:1,pointerEvents:"none",overflow:"hidden",borderRadius:14 }}>
            <div style={{ position:"absolute",top:0,bottom:0,width:"40%",
              background:"linear-gradient(90deg,transparent,rgba(0,176,255,0.04),transparent)",
              animation:"shimmerFlow 4s ease-in-out infinite" }}/>
          </div>
          {/* HUD corners */}
          {[{top:0,left:0,bT:true,bL:true},{top:0,right:0,bT:true,bR:true},
            {bottom:0,left:0,bB:true,bL:true},{bottom:0,right:0,bB:true,bR:true}
          ].map((pos,i) => (
            <div key={i} className="corner-br" style={{
              position:"absolute", width:14, height:14, zIndex:12,
              top:pos.top, right:pos.right, bottom:pos.bottom, left:pos.left,
              borderTop:    pos.bT ? "2px solid rgba(0,229,255,0.8)" : "none",
              borderBottom: pos.bB ? "2px solid rgba(0,229,255,0.8)" : "none",
              borderLeft:   pos.bL ? "2px solid rgba(0,229,255,0.8)" : "none",
              borderRight:  pos.bR ? "2px solid rgba(0,229,255,0.8)" : "none",
            }}/>
          ))}
          {/* Header */}
          <div style={{ position:"relative",zIndex:5,padding:"14px 22px",
            borderBottom:"1px solid rgba(0,176,255,0.1)",
            background:"linear-gradient(180deg,rgba(0,50,100,0.2),rgba(0,20,50,0.1))",
            display:"flex",alignItems:"center",gap:10 }}>
            <div className="s-dot" style={{ width:7,height:7,borderRadius:"50%",flexShrink:0,
              background:"#00E5FF",boxShadow:"0 0 10px #00E5FF,0 0 20px rgba(0,229,255,0.4)" }}/>
            <span className="holo-title" style={{ fontFamily:"'Orbitron',monospace",fontSize:9,
              letterSpacing:3,fontWeight:700 }}>SECURE ACCESS TERMINAL</span>
            <span style={{ marginLeft:"auto",fontFamily:"monospace",fontSize:7,
              color:"rgba(0,176,255,0.4)",letterSpacing:1 }}>v1.3.0</span>
          </div>
          <div style={{ position:"relative",zIndex:5,padding:"22px 24px 20px" }}>
            {/* Security stats */}
            <div style={{ display:"flex",gap:12,marginBottom:18 }}>
              {[["ENCRYPT","AES-256"],["PROTO","TLS 1.3"],["AUTH","JWT"]].map(([k,v]) => (
                <div key={k} style={{ flex:1,background:"rgba(0,100,180,0.08)",
                  border:"1px solid rgba(0,176,255,0.12)",borderRadius:5,padding:"5px 8px",textAlign:"center" }}>
                  <div style={{ fontFamily:"'Share Tech Mono',monospace",fontSize:7,
                    color:"rgba(0,176,255,0.5)",letterSpacing:1,marginBottom:2 }}>{k}</div>
                  <div style={{ fontFamily:"'Share Tech Mono',monospace",fontSize:8,
                    color:"rgba(0,229,255,0.7)" }}>{v}</div>
                </div>
              ))}
            </div>
            {/* Inputs */}
            {[["USERNAME",loginUser,false],["PASSWORD",loginPass,true]].map(([lbl,val,isPass]) => (
              <div key={lbl} style={{ marginBottom:14 }}>
                <div style={{ display:"flex",justifyContent:"space-between",marginBottom:5 }}>
                  <span style={{ fontSize:8,color:"rgba(0,176,255,0.5)",letterSpacing:2,
                    fontFamily:"'Share Tech Mono',monospace" }}>{lbl}</span>
                  <span style={{ fontSize:7,color:"rgba(0,176,255,0.25)",fontFamily:"monospace" }}>
                    {isPass?"&#x2022;&#x2022;&#x2022;&#x2022;&#x2022;&#x2022;":"REQUIRED"}
                  </span>
                </div>
                <input
                  type={isPass?"password":"text"} value={val}
                  onChange={e => isPass ? setLoginPass(e.target.value) : setLoginUser(e.target.value)}
                  onKeyDown={e => e.key==="Enter" && login()}
                  className="login-input"
                  style={{ width:"100%",background:"rgba(0,20,45,0.7)",
                    border:"1px solid rgba(0,176,255,0.2)",borderRadius:7,
                    padding:"11px 14px",color:"#B0D8F0",
                    fontFamily:"'Share Tech Mono',monospace",fontSize:12,
                    transition:"border-color 0.2s,box-shadow 0.2s",
                    boxShadow:"inset 0 1px 4px rgba(0,0,0,0.4)" }}
                />
              </div>
            ))}
            {loginError && (
              <div style={{ fontSize:10,color:"#FF6D00",marginBottom:14,fontFamily:"monospace",
                background:"rgba(255,109,0,0.07)",border:"1px solid rgba(255,109,0,0.25)",
                borderRadius:5,padding:"7px 12px",display:"flex",alignItems:"center",gap:6 }}>
                <span style={{ fontSize:14 }}>!</span> {loginError}
              </div>
            )}
            <button onClick={login} disabled={loading}
              onMouseEnter={e=>{ e.currentTarget.style.background="linear-gradient(135deg,rgba(0,176,255,0.25),rgba(0,100,200,0.3))"; e.currentTarget.style.boxShadow="0 0 32px rgba(0,176,255,0.5)"; }}
              onMouseLeave={e=>{ e.currentTarget.style.background="linear-gradient(135deg,rgba(0,80,160,0.3),rgba(0,40,100,0.2))"; e.currentTarget.style.boxShadow="0 0 16px rgba(0,176,255,0.2)"; }}
              style={{ width:"100%",padding:"13px",cursor:loading?"wait":"pointer",
                background:"linear-gradient(135deg,rgba(0,80,160,0.3),rgba(0,40,100,0.2))",
                border:"1px solid rgba(0,176,255,0.45)",borderRadius:7,
                color:"#00E5FF",fontFamily:"'Share Tech Mono',monospace",
                fontSize:11,letterSpacing:3,
                boxShadow:"0 0 16px rgba(0,176,255,0.2)",
                transition:"all 0.2s",position:"relative",overflow:"hidden" }}>
              {loading ? "AUTHENTICATING..." : "INITIALIZE ACCESS"}
            </button>
            <div style={{ display:"flex",justifyContent:"space-between",alignItems:"center",
              marginTop:14,paddingTop:12,borderTop:"1px solid rgba(0,176,255,0.08)" }}>
              <div>
                <div style={{ fontSize:8,color:"rgba(0,176,255,0.35)",fontFamily:"monospace",marginBottom:2 }}>DEFAULT CREDENTIALS</div>
                <div style={{ fontSize:9,color:"rgba(0,176,255,0.5)",fontFamily:"'Share Tech Mono',monospace" }}>admin / cybersentinel2025</div>
              </div>
              <div style={{ textAlign:"right" }}>
                <div style={{ fontSize:7,color:"rgba(0,176,255,0.25)",fontFamily:"monospace",letterSpacing:1 }}>SESSION</div>
                <div style={{ fontSize:8,color:"rgba(0,229,255,0.35)",fontFamily:"monospace" }}>ENCRYPTED</div>
              </div>
            </div>
          </div>
        </div>
      </div>

    </div>
  );

  // ── Mode accent colors ────────────────────────────────────────────────
  const ACCENT      = activeMode === "simulator" ? "#1565C0" : "#00897B";
  const ACCENT_LITE = activeMode === "simulator" ? "#4FC3F7" : "#4DB6AC";
  const MODE_LABEL  = activeMode === "simulator" ? "SIMULATED THREAT LAB" : "LIVE NETWORK SOC";
  const MODE_ICON   = activeMode === "simulator" ? "🔬" : "📡";
  const invPaused   = investigationsPaused[activeMode];

  // ── Main dashboard ────────────────────────────────────────────────────
  return (
    <div style={{ minHeight:"100vh", background:"#050D15", color:"#E2E8F0", display:"flex", flexDirection:"column", position:"relative" }}>
      {/* Dot-grid background */}
      <div style={{ position:"fixed",inset:0,zIndex:0,pointerEvents:"none",
        backgroundImage:"radial-gradient(circle,rgba(79,195,247,0.07) 1px,transparent 1px)",
        backgroundSize:"28px 28px" }}/>
      {/* Animated top bar */}
      <div style={{ position:"fixed",top:0,left:0,right:0,height:2,zIndex:200,pointerEvents:"none",
        background:`linear-gradient(90deg,transparent,${ACCENT},${ACCENT_LITE},${ACCENT},transparent)` }}/>
      <div style={{ position:"relative",zIndex:1,display:"flex",flexDirection:"column",minHeight:"100vh" }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@700&family=Orbitron:wght@700;900&family=DM+Sans:wght@400;500&display=swap');
        @keyframes ping      {0%{transform:scale(1);opacity:0.6}75%,100%{transform:scale(2.5);opacity:0}}
        @keyframes pulse     {0%,100%{opacity:1}50%{opacity:0.4}}
        @keyframes ticker    {0%{transform:translateX(0)}100%{transform:translateX(-50%)}}
        @keyframes neonCrit  {0%,100%{box-shadow:0 0 6px rgba(229,57,53,0.4),inset 0 0 6px rgba(229,57,53,0.05)}50%{box-shadow:0 0 18px rgba(229,57,53,0.7),inset 0 0 10px rgba(229,57,53,0.1)}}
        @keyframes neonHigh  {0%,100%{box-shadow:0 0 5px rgba(255,109,0,0.3)}50%{box-shadow:0 0 14px rgba(255,109,0,0.6)}}
        @keyframes glassIn   {from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:translateY(0)}}
        @keyframes rowFade   {from{opacity:0;transform:translateX(-8px)}to{opacity:1;transform:translateX(0)}}
        @keyframes scanH     {0%{transform:translateY(-100%)}100%{transform:translateY(100vh)}}
        @keyframes borderFlow{0%,100%{border-color:rgba(79,195,247,0.2)}50%{border-color:rgba(79,195,247,0.45)}}
        @keyframes topSlide  {from{transform:translateY(-6px);opacity:0}to{transform:translateY(0);opacity:1}}
        @keyframes counterUp {from{opacity:0;transform:scale(0.85)}to{opacity:1;transform:scale(1)}}
        * { box-sizing:border-box; margin:0; padding:0; }
        ::-webkit-scrollbar{width:3px;background:#050D15}
        ::-webkit-scrollbar-thumb{background:${ACCENT};border-radius:2px}
        input,button{font-family:'Share Tech Mono',monospace}
        .glass-panel{
          background:rgba(8,18,30,0.75)!important;
          backdrop-filter:blur(12px)!important;
          -webkit-backdrop-filter:blur(12px)!important;
        }
        .sev-CRITICAL{animation:neonCrit 2.5s ease-in-out infinite!important;}
        .sev-HIGH{animation:neonHigh 3s ease-in-out infinite!important;}
        .panel-in{animation:glassIn 0.45s ease-out forwards;}
        .row-in{animation:rowFade 0.3s ease-out both;}
        .metric-val{animation:counterUp 0.6s cubic-bezier(0.34,1.56,0.64,1) both;}
        .tab-content{animation:glassIn 0.35s ease-out forwards;}
        .dash-panel{
          border-radius:12px!important;
          border:1px solid rgba(79,195,247,0.1)!important;
          transition:border-color 0.3s!important;
        }
        .dash-panel:hover{border-color:rgba(79,195,247,0.22)!important;}
        .nav-btn{transition:all 0.18s!important;}
        .nav-btn:hover{background:rgba(79,195,247,0.08)!important;color:#90CAF9!important;}
      `}</style>

      {/* ── DUAL MODE SWITCHER BANNER ─────────────────────────────────── */}
      <div style={{
        height:40, background:"rgba(3,9,16,0.98)", borderBottom:"1px solid rgba(255,255,255,0.06)",
        display:"flex", alignItems:"center", justifyContent:"center", gap:4,
        position:"sticky", top:0, zIndex:101,
      }}>
        <div style={{ display:"flex", gap:2, background:"rgba(255,255,255,0.04)", borderRadius:8, padding:3 }}>
          {[["simulator","🔬","SIMULATED THREAT LAB","#1565C0","#4FC3F7"],
            ["dpi","📡","LIVE NETWORK SOC","#00897B","#4DB6AC"]].map(([mode, icon, label, accent, lite]) => {
            const isActive = activeMode === mode;
            return (
              <button key={mode} onClick={() => {
                setActiveMode(mode);
                setData({ dash: MOCK.dashboard, alerts: [], incidents: [] });
                setSelectedIncident(null);
                setIncidentDetail(null);
                setGeneratedRemediation(null);
                setBlockRecs([]);
                setFirewallRules([]);
                setCampaigns([]);
                fetchData(token, mode);
                fetchBlockRecs(mode);
                fetchFirewallRules();
                fetchCampaigns();
              }} style={{
                padding:"5px 22px", border:"none", borderRadius:6, cursor:"pointer",
                background: isActive ? `${accent}22` : "transparent",
                color: isActive ? lite : "#38516A",
                fontFamily:"'Share Tech Mono',monospace", fontSize:10, letterSpacing:1.5,
                borderBottom: isActive ? `2px solid ${accent}` : "2px solid transparent",
                transition:"all 0.18s", display:"flex", alignItems:"center", gap:7,
              }}>
                <span style={{ fontSize:13 }}>{icon}</span>
                <span>{label}</span>
                {isActive && <span style={{
                  fontSize:8, color:accent, background:`${accent}22`,
                  padding:"1px 7px", borderRadius:10, border:`1px solid ${accent}40`, letterSpacing:2,
                }}>ACTIVE</span>}
              </button>
            );
          })}
        </div>
        <div style={{ position:"absolute", right:20, fontFamily:"monospace", fontSize:9, color:"#38516A", letterSpacing:2 }}>
          {activeMode === "simulator"
            ? "Showing simulated attack traffic from Threat Simulator"
            : "Showing real network traffic captured by DPI Sensor"}
        </div>
      </div>

      {/* TOP BAR */}
      <div style={{
        height:52, background:"rgba(5,13,21,0.95)", borderBottom:`1px solid ${ACCENT}22`,
        display:"flex", alignItems:"center", justifyContent:"space-between", padding:"0 20px",
        position:"sticky", top:40, zIndex:100,
      }}>
        <div style={{ display:"flex", alignItems:"center", gap:16 }}>
          <span style={{ fontSize:18 }}>🛡️</span>
          <span style={{ fontFamily:"'Rajdhani',sans-serif", fontSize:17, fontWeight:700, letterSpacing:2, color:"#E2E8F0" }}>CYBERSENTINEL</span>
          <span style={{ fontFamily:"monospace", fontSize:9, color:ACCENT_LITE, background:`${ACCENT_LITE}18`, padding:"2px 8px", borderRadius:3, letterSpacing:2 }}>{MODE_ICON} {MODE_LABEL}</span>
          <div style={{ display:"flex", gap:1, marginLeft:8 }}>
            {[["overview","◉ OVERVIEW"],["alerts","⚡ ALERTS"],["incidents","🚨 INCIDENTS"],["campaigns","⚔ CAMPAIGNS"],["response","🛡️ RESPONSE"],["intel","🔍 THREAT INTEL"],["hosts","💻 HOSTS"],["threatfeed","📡 THREAT FEED"],["automation","⚙ AUTOMATION"]].map(([k,l]) => (
              <button key={k} onClick={()=>setTab(k)} style={{
                padding:"6px 14px", border:"none", background: tab===k?`${ACCENT}22`:"transparent",
                color: tab===k?ACCENT_LITE:"#546E7A", fontFamily:"'Share Tech Mono',monospace", fontSize:10,
                letterSpacing:1, cursor:"pointer", borderRadius:4,
                borderBottom: tab===k?`1px solid ${ACCENT_LITE}`:"1px solid transparent",
                transition:"all 0.15s", position:"relative",
              }}>
                {l}
                {k==="response" && blockRecs.length > 0 && (
                  <span style={{ marginLeft:6, background:"#E53935", color:"#fff", fontSize:9, fontWeight:700, padding:"1px 5px", borderRadius:8, verticalAlign:"middle" }}>{blockRecs.length}</span>
                )}
                {k==="threatfeed" && (data.alerts||[]).length > 0 && (
                  <span style={{ marginLeft:6, background:ACCENT, color:"#fff", fontSize:9, fontWeight:700, padding:"1px 5px", borderRadius:8, verticalAlign:"middle" }}>{(data.alerts||[]).length}</span>
                )}
                {k==="campaigns" && campaigns.filter(c=>c.max_severity==="CRITICAL").length > 0 && (
                  <span style={{ marginLeft:6, background:"#E53935", color:"#fff", fontSize:9, fontWeight:700, padding:"1px 5px", borderRadius:8, verticalAlign:"middle" }}>{campaigns.filter(c=>c.max_severity==="CRITICAL").length}</span>
                )}
                {k==="automation" && pendingReports.length > 0 && (
                  <span style={{ marginLeft:6, background:"#E53935", color:"#fff", fontSize:9, fontWeight:700, padding:"1px 5px", borderRadius:8, verticalAlign:"middle" }}>{pendingReports.length}</span>
                )}
              </button>
            ))}
          </div>
        </div>
        <div style={{ display:"flex", alignItems:"center", gap:20, fontFamily:"monospace", fontSize:11 }}>
          <div style={{ display:"flex", alignItems:"center", gap:6 }}>
            <ThreatDot color={apiLive?"#00E676":"#FF6D00"} size={5}/>
            <span style={{ color:apiLive?"#00E676":"#FF6D00" }}>{apiLive?"LIVE API":"CONNECTING..."}</span>
          </div>
          {/* ── AI INVESTIGATION CONTROLS — SIM / DPI ── */}
          {apiLive && (
            <div style={{ display:"flex", alignItems:"center", gap:5 }}>
              <span style={{ fontFamily:"monospace", fontSize:9, color:"#546E7A", letterSpacing:1 }}>AI INV:</span>
              {[["simulator","SIM"],["dpi","DPI"]].map(([src, label]) => {
                const paused = investigationsPaused[src] ?? false;
                return (
                  <button key={src} onClick={()=>toggleInvestigations(src)}
                    title={`${paused?"Resume":"Pause"} AI investigations for ${src}`}
                    style={{
                      padding:"3px 9px", borderRadius:4,
                      border:`1px solid ${paused?"#546E7A":"#4FC3F7"}`,
                      background:paused?"rgba(84,110,122,0.12)":"rgba(79,195,247,0.08)",
                      color:paused?"#546E7A":"#4FC3F7",
                      fontFamily:"'Share Tech Mono',monospace", fontSize:9, letterSpacing:1,
                      cursor:"pointer", transition:"all 0.2s",
                    }}>
                    {paused?"▶":"⏸"} {label}
                  </button>
                );
              })}
            </div>
          )}
          <span style={{ color:"#546E7A" }}>|</span>
          <span style={{ color:"#4FC3F7" }}>{dateStr}</span>
          <span style={{ color:"#E2E8F0", fontWeight:700 }}>{timeStr}</span>
          <span style={{ color:"#546E7A" }}>|</span>
          <div style={{ display:"flex", alignItems:"center", gap:6 }}>
            <span style={{ fontSize:9, color:"#546E7A", letterSpacing:1 }}>RISK</span>
            <span style={{ color:riskColor, fontWeight:700 }}>{riskPct}%</span>
          </div>
        </div>
      </div>

      {/* STATUS BANNERS */}
      {apiLive && (investigationsPaused.simulator || investigationsPaused.dpi) && (() => {
        const pausedSources = [investigationsPaused.simulator && "SIM", investigationsPaused.dpi && "DPI"].filter(Boolean).join(" + ");
        return (
          <div style={{
            background:"rgba(84,110,122,0.12)", borderBottom:"1px solid rgba(84,110,122,0.3)",
            padding:"6px 20px", display:"flex", alignItems:"center", gap:10,
            fontFamily:"'Share Tech Mono',monospace", fontSize:10, color:"#78909C", letterSpacing:1,
          }}>
            <span>⏸</span>
            <span>AI INVESTIGATIONS PAUSED [{pausedSources}] — Alerts are logged but no AI analysis. Use <strong style={{color:"#B0BEC5"}}>▶ SIM / ▶ DPI</strong> to resume.</span>
          </div>
        );
      })()}

      {/* CONTENT */}
      <div key={tab} className="tab-content" style={{ flex:1, padding:16, overflow:"auto" }}>

        {/* ── OVERVIEW TAB ── */}
        {tab==="overview" && (
          <div style={{ display:"flex", flexDirection:"column", gap:16 }}>
            {/* Metric cards */}
            <div style={{ display:"grid", gridTemplateColumns:"repeat(6,1fr)", gap:12 }}>
              <MetricCard label="Total Alerts 24h" value={data.dash.total_alerts_24h??0} color="#4FC3F7" live icon="⚡"/>
              <MetricCard label="Critical" value={data.dash.critical_alerts_24h??0} color="#E53935" live icon="🚨"/>
              <MetricCard label="High" value={data.dash.high_alerts_24h??0} color="#FF6D00" icon="⚠️"/>
              <MetricCard label="Active Incidents" value={data.dash.active_incidents??0} color="#FFD740" live icon="📋"/>
              <MetricCard label="Blocked IPs" value={data.dash.blocked_ips??0} color="#E53935" icon="🚫"/>
              <MetricCard label="Unique IPs Seen" value={data.dash.unique_ips_seen??0} color="#00E676" icon="🌐"/>
            </div>

            {/* Main row */}
            <div style={{ display:"grid", gridTemplateColumns:"2fr 1fr", gap:16 }}>
              {/* Alert timeline */}
              <Panel title="Alert Timeline — Last 24 Hours" badge={`${data.dash.total_alerts_24h??0} total`} style={{ height:280 }}>
                <div style={{ padding:"12px 0 0" }}>
                  <ResponsiveContainer width="100%" height={220}>
                    <AreaChart data={timeData} margin={{top:0,right:20,bottom:0,left:-10}}>
                      <defs>
                        <linearGradient id="crit" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#E53935" stopOpacity={0.3}/><stop offset="95%" stopColor="#E53935" stopOpacity={0}/></linearGradient>
                        <linearGradient id="high" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#FF6D00" stopOpacity={0.25}/><stop offset="95%" stopColor="#FF6D00" stopOpacity={0}/></linearGradient>
                      </defs>
                      <XAxis dataKey="h" tick={{fill:"#546E7A",fontSize:9,fontFamily:"monospace"}} tickLine={false} axisLine={false} interval={3}/>
                      <YAxis tick={{fill:"#546E7A",fontSize:9,fontFamily:"monospace"}} tickLine={false} axisLine={false}/>
                      <Tooltip content={<CustomTooltip/>}/>
                      <Area type="monotone" dataKey="medium" stroke="#FFD740" strokeWidth={1} fill="none" strokeDasharray="3 3"/>
                      <Area type="monotone" dataKey="high" stroke="#FF6D00" strokeWidth={1.5} fill="url(#high)"/>
                      <Area type="monotone" dataKey="critical" stroke="#E53935" strokeWidth={2} fill="url(#crit)"/>
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </Panel>

              {/* Platform health radar */}
              <Panel title="Platform Health" badge="6 services" style={{ height:280 }}>
                <ResponsiveContainer width="100%" height={230}>
                  <RadarChart data={radarData} margin={{top:10,right:20,bottom:10,left:20}}>
                    <PolarGrid stroke="rgba(79,195,247,0.1)"/>
                    <PolarAngleAxis dataKey="subject" tick={{fill:"#546E7A",fontSize:10,fontFamily:"monospace"}}/>
                    <Radar name="Health" dataKey="value" stroke="#4FC3F7" fill="#4FC3F7" fillOpacity={0.15} strokeWidth={1.5}/>
                  </RadarChart>
                </ResponsiveContainer>
              </Panel>
            </div>

            {/* Bottom row */}
            <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr 1fr", gap:16 }}>
              {/* Top threat types bar */}
              <Panel title="Top Threat Types" style={{ height:220 }}>
                <div style={{ padding:"8px 0" }}>
                  {(apiLive && (data.dash.top_threat_types||[]).length===0) ? (
                    <div style={{ textAlign:"center", padding:"50px 0", color:"#546E7A", fontFamily:"monospace", fontSize:11 }}>No threats detected yet</div>
                  ) : (
                    <ResponsiveContainer width="100%" height={180}>
                      <BarChart data={data.dash.top_threat_types||[]} layout="vertical" margin={{top:0,right:16,bottom:0,left:8}}>
                        <XAxis type="number" tick={{fill:"#546E7A",fontSize:9}} tickLine={false} axisLine={false}/>
                        <YAxis type="category" dataKey="type" width={160} tick={{fill:"#8899AA",fontSize:9,fontFamily:"monospace"}} tickLine={false} axisLine={false} tickFormatter={v=>v.replace("_DETECTED","").replace("_"," ")}/>
                        <Tooltip content={<CustomTooltip/>}/>
                        <Bar dataKey="count" fill="#1565C0" radius={[0,3,3,0]}>
                          {(data.dash.top_threat_types||[]).map((_,i)=>(<rect key={i} fill={["#E53935","#FF6D00","#FFD740","#4FC3F7","#00E676"][i]||"#1565C0"}/>))}
                        </Bar>
                      </BarChart>
                    </ResponsiveContainer>
                  )}
                </div>
              </Panel>

              {/* Recent alerts mini */}
              <Panel title="Latest Alerts" badge="LIVE" style={{ height:220 }}>
                <div style={{ overflow:"auto", maxHeight:175 }}>
                  {(data.alerts||[]).length===0 ? (
                    <div style={{ textAlign:"center", padding:"50px 0", color:"#546E7A", fontFamily:"monospace", fontSize:11 }}>Waiting for alerts...</div>
                  ) : (data.alerts||[]).slice(0,6).map(a => (
                    <div key={a.id} style={{ display:"flex", alignItems:"center", gap:10, padding:"8px 14px", borderBottom:"1px solid rgba(255,255,255,0.03)" }}>
                      <ThreatDot color={SEV_COLOR[a.severity]||"#fff"} size={5}/>
                      <div style={{ flex:1, minWidth:0 }}>
                        <div style={{ fontSize:11, color:"#CBD5E1", fontFamily:"monospace", whiteSpace:"nowrap", overflow:"hidden", textOverflow:"ellipsis" }}>{a.type?.replace("_DETECTED","")}</div>
                        <div style={{ fontSize:10, color:"#546E7A" }}>{a.src_ip} → {ago(a.timestamp)}</div>
                      </div>
                      <span style={{ fontFamily:"monospace", fontSize:9, color:"#4FC3F7", whiteSpace:"nowrap" }}>{a.mitre_technique}</span>
                    </div>
                  ))}
                </div>
              </Panel>

              {/* Risk gauge */}
              <Panel title="Risk Posture" style={{ height:220 }}>
                <div style={{ padding:16, display:"flex", flexDirection:"column", alignItems:"center", justifyContent:"center", height:175 }}>
                  <div style={{ position:"relative", width:120, height:120 }}>
                    <svg viewBox="0 0 120 120" style={{ transform:"rotate(-90deg)" }}>
                      <circle cx="60" cy="60" r="50" fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="12"/>
                      <circle cx="60" cy="60" r="50" fill="none" stroke={riskColor} strokeWidth="12"
                        strokeDasharray={`${riskPct*3.14} 314`} strokeLinecap="round" style={{ transition:"stroke-dasharray 1s ease" }}/>
                    </svg>
                    <div style={{ position:"absolute", inset:0, display:"flex", flexDirection:"column", alignItems:"center", justifyContent:"center" }}>
                      <div style={{ fontFamily:"'Share Tech Mono',monospace", fontSize:26, fontWeight:700, color:riskColor }}>{riskPct}%</div>
                      <div style={{ fontSize:9, color:"#546E7A", letterSpacing:1 }}>RISK</div>
                    </div>
                  </div>
                  <div style={{ fontFamily:"'Share Tech Mono',monospace", fontSize:11, color:riskColor, marginTop:8, letterSpacing:1 }}>
                    {riskPct>70?"CRITICAL RISK":riskPct>40?"ELEVATED RISK":"LOW RISK"}
                  </div>
                </div>
              </Panel>
            </div>
          </div>
        )}

        {/* ── ALERTS TAB ── */}
        {tab==="alerts" && (() => {
          const allAlerts = apiLive ? (data.alerts||[]) : MOCK.alerts;
          const SEV_ORDER = ["CRITICAL","HIGH","MEDIUM","LOW","INFO"];
          const grouped = SEV_ORDER.reduce((acc,s) => {
            const items = allAlerts.filter(a => (a.severity||"INFO") === s);
            if (items.length) acc[s] = items;
            return acc;
          }, {});
          const unknownMitre = allAlerts.filter(a => !a.mitre_technique || a.mitre_technique==="UNKNOWN");

          function AlertRow({ a, i }) {
            const mitre = a.mitre_technique || a.matched_mitre || "";
            const isUnknown = !mitre || mitre === "UNKNOWN";
            const isCrit = a.severity === "CRITICAL";
            const isHigh = a.severity === "HIGH";
            return (
              <tr key={a.id||i} className={`row-in${isCrit?" sev-CRITICAL":isHigh?" sev-HIGH":""}`}
                style={{
                  borderBottom:"1px solid rgba(255,255,255,0.03)",
                  transition:"background 0.15s",
                  animationDelay:`${Math.min(i * 0.03, 0.6)}s`,
                  borderLeft: isCrit ? "2px solid rgba(229,57,53,0.6)" : isHigh ? "2px solid rgba(255,109,0,0.5)" : "2px solid transparent",
                }}
                onMouseEnter={e=>e.currentTarget.style.background=isCrit?"rgba(229,57,53,0.06)":isHigh?"rgba(255,109,0,0.05)":"rgba(79,195,247,0.04)"}
                onMouseLeave={e=>e.currentTarget.style.background="transparent"}>
                <td style={{ padding:"9px 14px" }}><SevBadge s={a.severity}/></td>
                <td style={{ padding:"9px 14px", color:"#CBD5E1", fontSize:11, maxWidth:200 }}>
                  <div style={{ whiteSpace:"nowrap", overflow:"hidden", textOverflow:"ellipsis" }}>
                    {a.type?.replace("_DETECTED","").replace(/_/g," ")}
                  </div>
                  {isUnknown && (
                    <div style={{ fontSize:9, color:"#FF6D00", marginTop:2, letterSpacing:0.5 }}>UNKNOWN — AI CLASSIFYING</div>
                  )}
                </td>
                <td style={{ padding:"9px 14px", color:"#4FC3F7", fontFamily:"monospace", fontSize:11 }}>{a.src_ip}</td>
                <td style={{ padding:"9px 14px", color:"#8899AA", fontFamily:"monospace", fontSize:11 }}>{a.dst_ip||"—"}</td>
                <td style={{ padding:"9px 14px" }}>
                  {isUnknown
                    ? <span style={{ fontSize:9, color:"#FF6D00", background:"rgba(255,109,0,0.1)", padding:"2px 6px", borderRadius:3, border:"1px solid rgba(255,109,0,0.25)" }}>UNKNOWN</span>
                    : <span style={{ color:"#FFD740", fontSize:11, fontFamily:"monospace" }}>{mitre}</span>
                  }
                </td>
                <td style={{ padding:"9px 14px" }}>
                  <div style={{ display:"flex", alignItems:"center", gap:6, minWidth:80 }}>
                    <div style={{ flex:1, height:3, background:"rgba(255,255,255,0.08)", borderRadius:2 }}>
                      <div style={{ width:`${(a.anomaly_score||0)*100}%`, height:"100%", background:SEV_COLOR[a.severity]||"#4FC3F7", borderRadius:2 }}/>
                    </div>
                    <span style={{ color:"#8899AA", fontSize:10, whiteSpace:"nowrap" }}>{((a.anomaly_score||0)*100).toFixed(0)}%</span>
                  </div>
                </td>
                <td style={{ padding:"9px 14px", color:"#546E7A", fontSize:10, whiteSpace:"nowrap" }}>{ago(a.timestamp)}</td>
              </tr>
            );
          }

          function SevSection({ sev, alerts }) {
            const icon = { CRITICAL:"🚨", HIGH:"⚠️", MEDIUM:"🔔", LOW:"ℹ️", INFO:"💬" }[sev] || "●";
            const isCrit = sev === "CRITICAL", isHigh = sev === "HIGH";
            return (
              <div style={{ marginBottom:4 }}>
                <div className={isCrit?"sev-CRITICAL":isHigh?"sev-HIGH":""} style={{
                  display:"flex", alignItems:"center", gap:10,
                  padding:"8px 14px", background:`${SEV_BG[sev]||"rgba(255,255,255,0.03)"}`,
                  borderBottom:`1px solid ${SEV_COLOR[sev]||"#fff"}20`,
                  borderLeft:`3px solid ${SEV_COLOR[sev]||"#fff"}`,
                  position:"sticky", top:0, zIndex:1,
                  backdropFilter:"blur(8px)",
                }}>
                  <span style={{ fontSize:13 }}>{icon}</span>
                  <span style={{ fontFamily:"'Share Tech Mono',monospace", fontSize:10, color:SEV_COLOR[sev]||"#fff", letterSpacing:2 }}>{sev}</span>
                  <span style={{ fontFamily:"monospace", fontSize:10, color:`${SEV_COLOR[sev]}80`, background:`${SEV_COLOR[sev]}15`, padding:"1px 8px", borderRadius:10, border:`1px solid ${SEV_COLOR[sev]}30` }}>{alerts.length}</span>
                  <span style={{ fontSize:10, color:"#38516A", marginLeft:"auto" }}>
                    {sev==="CRITICAL"?"Immediate action required":sev==="HIGH"?"Investigate within 1h":sev==="MEDIUM"?"Review within 4h":"Monitor"}
                  </span>
                </div>
                <table style={{ width:"100%", borderCollapse:"collapse", fontFamily:"monospace", fontSize:12 }}>
                  <tbody>
                    {alerts.map((a,i) => <AlertRow key={a.id||i} a={a} i={i}/>)}
                  </tbody>
                </table>
              </div>
            );
          }

          return (
            <div style={{ display:"flex", flexDirection:"column", gap:12 }}>
              {/* Summary row */}
              <div style={{ display:"grid", gridTemplateColumns:"repeat(5,1fr)", gap:10 }}>
                {SEV_ORDER.map(s => (
                  <div key={s} style={{ background:`${SEV_BG[s]||"rgba(255,255,255,0.03)"}`, border:`1px solid ${SEV_COLOR[s]||"#fff"}25`, borderRadius:8, padding:"12px 16px" }}>
                    <div style={{ fontSize:9, color:"#546E7A", letterSpacing:2, marginBottom:6 }}>{s}</div>
                    <div style={{ fontFamily:"'Share Tech Mono',monospace", fontSize:24, color:SEV_COLOR[s]||"#fff", fontWeight:700 }}>
                      {allAlerts.filter(a=>(a.severity||"INFO")===s).length}
                    </div>
                  </div>
                ))}
              </div>

              {/* Unknown threats callout */}
              {unknownMitre.length > 0 && (
                <div style={{ background:"rgba(255,109,0,0.05)", border:"1px solid rgba(255,109,0,0.25)", borderRadius:8, padding:"10px 16px", display:"flex", alignItems:"center", gap:10 }}>
                  <ThreatDot color="#FF6D00" size={5}/>
                  <span style={{ fontFamily:"monospace", fontSize:11, color:"#FF6D00" }}>
                    {unknownMitre.length} alert{unknownMitre.length!==1?"s":""} with UNKNOWN threat type — AI classification pending. See 📡 THREAT FEED for details.
                  </span>
                </div>
              )}

              {/* Grouped table by severity */}
              <div className="dash-panel panel-in" style={{ background:"rgba(7,16,27,0.8)", backdropFilter:"blur(12px)", border:"1px solid rgba(79,195,247,0.1)", borderRadius:12, overflow:"hidden" }}>
                <div style={{ padding:"10px 14px", borderBottom:"1px solid rgba(79,195,247,0.08)", display:"flex", alignItems:"center", justifyContent:"space-between" }}>
                  <span style={{ fontFamily:"'Share Tech Mono',monospace", fontSize:10, color:"#4FC3F7", letterSpacing:2 }}>ALL ALERTS — GROUPED BY SEVERITY</span>
                  <span style={{ fontFamily:"monospace", fontSize:10, color:"#546E7A" }}>{allAlerts.length} total</span>
                </div>
                {/* Column headers */}
                <table style={{ width:"100%", borderCollapse:"collapse", fontFamily:"monospace", fontSize:12 }}>
                  <thead>
                    <tr style={{ borderBottom:"1px solid rgba(79,195,247,0.1)", background:"rgba(79,195,247,0.03)" }}>
                      {["Severity","Type","Source IP","Destination","MITRE","Score","Time"].map(h => (
                        <th key={h} style={{ padding:"8px 14px", textAlign:"left", fontFamily:"'Share Tech Mono',monospace", fontSize:9, color:"#546E7A", letterSpacing:2, fontWeight:400 }}>{h.toUpperCase()}</th>
                      ))}
                    </tr>
                  </thead>
                </table>
                <div style={{ maxHeight:"calc(100vh - 280px)", overflowY:"auto" }}>
                  {Object.keys(grouped).length === 0 ? (
                    <div style={{ textAlign:"center", padding:"50px 0", color:"#546E7A", fontFamily:"monospace", fontSize:12 }}>No alerts yet — waiting for threat traffic...</div>
                  ) : (
                    Object.entries(grouped).map(([sev, alerts]) => (
                      <SevSection key={sev} sev={sev} alerts={alerts}/>
                    ))
                  )}
                </div>
              </div>
            </div>
          );
        })()}

        {/* ── CAMPAIGNS TAB ── */}
        {tab==="campaigns" && (() => {
          const campData = apiLive ? campaigns : MOCK.campaigns;
          const TACTIC_MAP = {
            "T1190":    { tactic:"Initial Access",    phase:0, icon:"🚪" },
            "T1059.004":{ tactic:"Execution",         phase:1, icon:"⚡" },
            "T1027":    { tactic:"Defense Evasion",   phase:2, icon:"🕵️" },
            "T1110.001":{ tactic:"Credential Access", phase:3, icon:"🔑" },
            "T1110.003":{ tactic:"Credential Access", phase:3, icon:"🔑" },
            "T1078":    { tactic:"Credential Access", phase:3, icon:"🔑" },
            "T1046":    { tactic:"Discovery",         phase:4, icon:"🔍" },
            "T1595":    { tactic:"Discovery",         phase:4, icon:"🔍" },
            "T1021.001":{ tactic:"Lateral Movement",  phase:5, icon:"↔️" },
            "T1021.002":{ tactic:"Lateral Movement",  phase:5, icon:"↔️" },
            "T1071.001":{ tactic:"C2",                phase:6, icon:"📡" },
            "T1071.004":{ tactic:"C2",                phase:6, icon:"📡" },
            "T1572":    { tactic:"C2",                phase:6, icon:"📡" },
            "T1048":    { tactic:"Exfiltration",      phase:7, icon:"📤" },
            "T1041":    { tactic:"Exfiltration",      phase:7, icon:"📤" },
            "T1048.003":{ tactic:"Exfiltration",      phase:7, icon:"📤" },
            "T1568.002":{ tactic:"C2",                phase:6, icon:"📡" },
            "T1003":    { tactic:"Credential Access", phase:3, icon:"🔑" },
          };
          const CHAIN_LABELS = ["Initial Access","Execution","Defense Evasion","Credential Access","Discovery","Lateral Movement","C2","Exfiltration"];
          const critCount = campData.filter(c=>c.max_severity==="CRITICAL").length;
          const last24h = campData.filter(c=>(Date.now()-new Date(c.last_seen).getTime())<86400000).length;
          const SEV_COLOR = { CRITICAL:"#E53935", HIGH:"#FF6D00", MEDIUM:"#FFD740", LOW:"#66BB6A" };
          return (
            <div>
              {/* Stats row */}
              <div style={{ display:"grid", gridTemplateColumns:"repeat(3,1fr)", gap:12, marginBottom:16 }}>
                <MetricCard label="Total Campaigns" value={campData.length} color={ACCENT} icon="⚔"/>
                <MetricCard label="Critical Campaigns" value={critCount} color="#E53935" live={critCount>0} icon="🔴"/>
                <MetricCard label="Active (Last 24h)" value={last24h} color="#FF6D00" icon="🕐"/>
              </div>
              {campData.length === 0 ? (
                <div style={{ textAlign:"center", padding:60, color:"#546E7A", fontFamily:"monospace", fontSize:12 }}>
                  No active attack campaigns detected
                </div>
              ) : (
                <div style={{ display:"flex", flexDirection:"column", gap:12 }}>
                  {campData.map(c => {
                    const activePhases = new Set((c.mitre_stages||[]).map(t => (TACTIC_MAP[t]||{}).phase).filter(p=>p!=null));
                    return (
                      <Panel key={c.campaign_id}>
                        <div style={{ padding:"14px 18px" }}>
                          {/* Header row */}
                          <div style={{ display:"flex", alignItems:"center", gap:12, marginBottom:10 }}>
                            <span style={{ fontFamily:"'Share Tech Mono',monospace", fontSize:11, color:ACCENT_LITE, fontWeight:700 }}>{c.campaign_id}</span>
                            <span style={{ background:`${SEV_COLOR[c.max_severity]||"#546E7A"}22`, color:SEV_COLOR[c.max_severity]||"#546E7A", border:`1px solid ${SEV_COLOR[c.max_severity]||"#546E7A"}55`, padding:"1px 8px", borderRadius:4, fontSize:10, fontFamily:"'Share Tech Mono',monospace", fontWeight:700 }}>{c.max_severity}</span>
                            <span style={{ fontFamily:"monospace", fontSize:11, color:"#E2E8F0" }}>SRC: <span style={{ color:ACCENT_LITE }}>{c.src_ip}</span></span>
                            <span style={{ marginLeft:"auto", fontFamily:"monospace", fontSize:10, color:"#546E7A" }}>{c.incident_count} incident{c.incident_count!==1?"s":""}</span>
                          </div>
                          {/* Kill chain strip */}
                          <div style={{ display:"flex", gap:3, marginBottom:10 }}>
                            {CHAIN_LABELS.map((label,phase) => {
                              const hit = activePhases.has(phase);
                              return (
                                <div key={phase} title={label} style={{ flex:1, textAlign:"center", padding:"3px 2px", borderRadius:4, fontSize:9, fontFamily:"'Share Tech Mono',monospace", letterSpacing:0,
                                  background: hit ? (phase<=2?"rgba(229,57,53,0.25)":phase<=5?"rgba(255,109,0,0.25)":"rgba(0,176,255,0.25)") : "rgba(255,255,255,0.04)",
                                  color: hit ? (phase<=2?"#EF9A9A":phase<=5?"#FFCC80":"#81D4FA") : "#37474F",
                                  border: hit ? `1px solid ${phase<=2?"rgba(229,57,53,0.5)":phase<=5?"rgba(255,109,0,0.5)":"rgba(0,176,255,0.5)"}` : "1px solid rgba(255,255,255,0.04)",
                                  fontWeight: hit ? 700 : 400,
                                }}>
                                  {CHAIN_LABELS[phase].split(" ").map(w=>w[0]).join("")}
                                </div>
                              );
                            })}
                          </div>
                          {/* MITRE tags */}
                          <div style={{ display:"flex", gap:6, flexWrap:"wrap", marginBottom:8 }}>
                            {(c.mitre_stages||[]).map(t => (
                              <span key={t} style={{ background:"rgba(0,176,255,0.1)", color:"#4FC3F7", border:"1px solid rgba(0,176,255,0.25)", padding:"1px 7px", borderRadius:3, fontSize:9, fontFamily:"monospace" }}>{t}</span>
                            ))}
                          </div>
                          {/* Summary */}
                          {c.campaign_summary && (
                            <div style={{ fontFamily:"'Rajdhani',sans-serif", fontSize:12, color:"#90A4AE", lineHeight:1.5, marginBottom:8 }}>{c.campaign_summary}</div>
                          )}
                          {/* Timestamps */}
                          <div style={{ display:"flex", gap:24, fontFamily:"monospace", fontSize:10, color:"#546E7A" }}>
                            <span>FIRST: {new Date(c.first_seen).toLocaleString()}</span>
                            <span>LAST: {new Date(c.last_seen).toLocaleString()}</span>
                          </div>
                        </div>
                      </Panel>
                    );
                  })}
                </div>
              )}
            </div>
          );
        })()}

        {/* ── RESPONSE TAB ── */}
        {tab==="response" && (
          <div style={{ display:"flex", flexDirection:"column", gap:16 }}>
            <div style={{ display:"grid", gridTemplateColumns:"repeat(3,1fr)", gap:12 }}>
              <MetricCard label="Pending Block Actions" value={blockRecs.length} color="#E53935" live={blockRecs.length>0} icon="🚫"/>
              <MetricCard label="Blocked IPs (24h)" value={data.dash.blocked_ips??0} color="#FF6D00" icon="🔒"/>
              <MetricCard label="Active Incidents" value={(data.incidents||[]).filter(i=>i.status==='OPEN').length} color="#FFD740" icon="📋"/>
            </div>

            {/* ── ACTIVE INCIDENTS PANEL ── */}
            {(() => {
              const allOpen  = (data.incidents||[]).filter(i => i.status === 'OPEN');
              const openInc  = allOpen.filter(i => i.investigation_summary && !i.investigation_summary?.startsWith('⏸'));
              const pendingCount = allOpen.length - openInc.length;
              return (
                <div className="dash-panel panel-in" style={{ background:"rgba(7,16,27,0.8)", backdropFilter:"blur(12px)", border:"1px solid rgba(255,215,64,0.15)", borderRadius:12, overflow:"hidden" }}>
                  <div style={{ padding:"12px 18px", borderBottom:"1px solid rgba(255,215,64,0.1)", background:"rgba(255,215,64,0.03)", display:"flex", alignItems:"center", justifyContent:"space-between" }}>
                    <div style={{ display:"flex", alignItems:"center", gap:10, flexWrap:"wrap" }}>
                      {openInc.length > 0 && <ThreatDot color="#FFD740" size={5}/>}
                      <span style={{ fontFamily:"'Share Tech Mono',monospace", fontSize:10, color:"#FFD740", letterSpacing:2 }}>ACTIVE INCIDENTS — AI INVESTIGATED</span>
                      <span style={{ fontFamily:"monospace", fontSize:10, color:"#FFD740", background:"rgba(255,215,64,0.1)", padding:"2px 10px", borderRadius:10, border:"1px solid rgba(255,215,64,0.25)" }}>{openInc.length} OPEN</span>
                      {pendingCount > 0 && (
                        <span style={{ fontFamily:"monospace", fontSize:9, color:"#546E7A", background:"rgba(255,215,64,0.05)", padding:"2px 8px", borderRadius:10, border:"1px solid rgba(255,215,64,0.12)" }}>+{pendingCount} pending AI → see Incidents tab</span>
                      )}
                    </div>
                    <button onClick={()=>setTab("incidents")} style={{ fontFamily:"'Share Tech Mono',monospace", fontSize:9, color:"#4FC3F7", background:"rgba(79,195,247,0.06)", border:"1px solid rgba(79,195,247,0.2)", borderRadius:4, padding:"3px 10px", cursor:"pointer", letterSpacing:1 }}>
                      VIEW ALL →
                    </button>
                  </div>
                  <div style={{ padding:16, display:"flex", flexDirection:"column", gap:8, maxHeight:320, overflowY:"auto" }}>
                    {openInc.length === 0 ? (
                      <div style={{ textAlign:"center", color:"#546E7A", fontFamily:"monospace", fontSize:11, padding:"24px 0" }}>
                        ✅ No open incidents
                      </div>
                    ) : openInc.slice(0,10).map(inc => {
                      const sev = inc.severity || 'MEDIUM';
                      const sevColor = sev==='CRITICAL'?'#FF5252':sev==='HIGH'?'#FF6D00':sev==='MEDIUM'?'#FFD740':'#78909C';
                      const isPending = !inc.investigation_summary || inc.investigation_summary?.startsWith('⏸');
                      return (
                        <div key={inc.incident_id}
                          onClick={()=>{ setSelectedIncident(inc); setTab("incidents"); }}
                          style={{ background:`${sevColor}08`, border:`1px solid ${sevColor}25`,
                            borderLeft:`3px solid ${sevColor}`, borderRadius:8,
                            padding:"12px 16px", cursor:"pointer", transition:"all 0.15s" }}
                          onMouseEnter={e=>{ e.currentTarget.style.background=`${sevColor}14`; e.currentTarget.style.borderColor=`${sevColor}50`; }}
                          onMouseLeave={e=>{ e.currentTarget.style.background=`${sevColor}08`; e.currentTarget.style.borderColor=`${sevColor}25`; }}>
                          <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:6, flexWrap:"wrap" }}>
                            <SevBadge s={sev}/>
                            <span style={{ fontFamily:"monospace", fontSize:9, color:"#546E7A" }}>{inc.incident_id}</span>
                            {isPending && (
                              <span style={{ fontFamily:"monospace", fontSize:9, color:"#FFD740", background:"rgba(255,215,64,0.1)", border:"1px solid rgba(255,215,64,0.25)", padding:"1px 7px", borderRadius:3 }}>⏸ PENDING AI</span>
                            )}
                            {inc.block_recommended && (
                              <span style={{ fontFamily:"monospace", fontSize:9, color:"#E53935", background:"rgba(229,57,53,0.1)", border:"1px solid rgba(229,57,53,0.3)", padding:"1px 7px", borderRadius:3 }}>🚫 BLOCK REC</span>
                            )}
                            <span style={{ marginLeft:"auto", fontFamily:"monospace", fontSize:9, color:"#3D5465" }}>{ago(inc.created_at)}</span>
                          </div>
                          <div style={{ fontSize:12, color:"#CBD5E1", marginBottom:4, fontWeight:500 }}>{inc.title}</div>
                          <div style={{ fontSize:10, color:"#546E7A", fontFamily:"monospace" }}>
                            {(inc.affected_ips||[]).join(", ")||"—"}
                            {(inc.mitre_techniques||[]).length > 0 && ` · ${inc.mitre_techniques[0]}`}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              );
            })()}
            <div className="dash-panel panel-in" style={{ background:"rgba(7,16,27,0.8)", backdropFilter:"blur(12px)", border:`1px solid ${blockRecs.length > 0 ? "rgba(229,57,53,0.35)" : "rgba(79,195,247,0.1)"}`, borderRadius:12, overflow:"hidden" }}>
              <div style={{ padding:"12px 18px", borderBottom:`1px solid ${blockRecs.length > 0 ? "rgba(229,57,53,0.2)" : "rgba(79,195,247,0.08)"}`, background: blockRecs.length > 0 ? "rgba(229,57,53,0.05)" : "rgba(79,195,247,0.03)", display:"flex", alignItems:"center", justifyContent:"space-between" }}>
                <div style={{ display:"flex", alignItems:"center", gap:10 }}>
                  {blockRecs.length > 0 && <ThreatDot color="#E53935" size={5}/>}
                  <span style={{ fontFamily:"'Share Tech Mono',monospace", fontSize:10, color: blockRecs.length > 0 ? "#E53935" : "#4FC3F7", letterSpacing:2, textTransform:"uppercase" }}>Block Recommendations — Pending Analyst Decision</span>
                </div>
                <span style={{ fontFamily:"monospace", fontSize:10, color: blockRecs.length > 0 ? "#E53935" : "#546E7A", background: blockRecs.length > 0 ? "rgba(229,57,53,0.15)" : "transparent", padding:"2px 10px", borderRadius:10, border: blockRecs.length > 0 ? "1px solid rgba(229,57,53,0.3)" : "none" }}>
                  {blockRecs.length > 0 ? `${blockRecs.length} awaiting action` : "all clear"}
                </span>
              </div>
              <div style={{ padding:16, display:"flex", flexDirection:"column", gap:10 }}>
                {blockRecs.length === 0 ? (
                  <div style={{ textAlign:"center", color:"#546E7A", fontFamily:"monospace", fontSize:11, padding:"30px 0" }}>
                    ✅ No pending block recommendations — AI will surface flagged IPs here after each investigation
                  </div>
                ) : blockRecs.map(rec => (
                  <div key={rec.incident_id} style={{
                    background:"rgba(229,57,53,0.05)", border:"1px solid rgba(229,57,53,0.2)",
                    borderLeft:"3px solid #E53935", borderRadius:8, padding:"16px 20px",
                    display:"flex", justifyContent:"space-between", alignItems:"center", gap:16,
                  }}>
                    <div style={{ flex:1, minWidth:0 }}>
                      <div style={{ display:"flex", gap:10, alignItems:"center", marginBottom:8, flexWrap:"wrap" }}>
                        <span style={{ fontFamily:"monospace", fontSize:10, color:"#546E7A" }}>{rec.incident_id}</span>
                        <SevBadge s={rec.severity}/>
                        <span style={{ fontFamily:"monospace", fontSize:12, color:"#E53935", background:"rgba(229,57,53,0.12)", padding:"3px 10px", borderRadius:3, border:"1px solid rgba(229,57,53,0.3)", fontWeight:700 }}>🚫 {rec.block_target_ip}</span>
                      </div>
                      <div style={{ fontSize:13, color:"#E2E8F0", marginBottom:6, fontWeight:500 }}>{rec.title}</div>
                      <div style={{ fontSize:10, color:"#546E7A", fontFamily:"monospace", marginBottom: rec.investigation_summary ? 8 : 0 }}>
                        MITRE: {(rec.mitre_techniques||[]).join(", ")||"—"} · {ago(rec.created_at)}
                      </div>
                      {rec.investigation_summary && (
                        <div style={{ fontSize:10, color:"#8899AA", fontFamily:"monospace", background:"rgba(5,13,21,0.5)", border:"1px solid rgba(79,195,247,0.08)", borderRadius:4, padding:"8px 10px", maxHeight:60, overflow:"hidden", lineHeight:1.6 }}>
                          {rec.investigation_summary.substring(0,180)}{rec.investigation_summary.length>180?"…":""}
                        </div>
                      )}
                    </div>
                    <div style={{ display:"flex", flexDirection:"column", gap:8, flexShrink:0, minWidth:140 }}>
                      <button onClick={()=>handleBlockIP(rec.incident_id)} disabled={!!blockAction[rec.incident_id]}
                        style={{ padding:"10px 16px", background:"rgba(229,57,53,0.15)", border:"1px solid rgba(229,57,53,0.5)", borderRadius:4, color:"#E53935", cursor:blockAction[rec.incident_id]?"wait":"pointer", fontSize:11, fontFamily:"'Share Tech Mono',monospace", letterSpacing:0.5, transition:"background 0.15s", width:"100%" }}
                        onMouseEnter={e=>{ if (!blockAction[rec.incident_id]) e.target.style.background="rgba(229,57,53,0.3)"; }}
                        onMouseLeave={e=>e.target.style.background="rgba(229,57,53,0.15)"}>
                        {blockAction[rec.incident_id]==='blocking' ? '⏳ BLOCKING...' : '🚫 BLOCK IP'}
                      </button>
                      <button onClick={()=>handleDismissRec(rec.incident_id)} disabled={!!blockAction[rec.incident_id]}
                        style={{ padding:"10px 16px", background:"rgba(84,110,122,0.1)", border:"1px solid rgba(84,110,122,0.3)", borderRadius:4, color:"#546E7A", cursor:blockAction[rec.incident_id]?"wait":"pointer", fontSize:11, fontFamily:"'Share Tech Mono',monospace", letterSpacing:0.5, width:"100%" }}>
                        {blockAction[rec.incident_id]==='dismissing' ? '⏳ DISMISSING...' : 'DISMISS'}
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* ── FIREWALL RULES PANEL ── */}
            {(() => {
              const filtered = firewallRules.filter(r =>
                firewallFilter === "all" ? true :
                firewallFilter === "active" ? r.is_active :
                !r.is_active
              );
              const activeCount  = firewallRules.filter(r => r.is_active).length;
              const expiredCount = firewallRules.filter(r => !r.is_active).length;
              return (
                <div className="dash-panel panel-in" style={{ background:"rgba(7,16,27,0.8)", backdropFilter:"blur(12px)", border:"1px solid rgba(79,195,247,0.1)", borderRadius:12, overflow:"hidden" }}>
                  {/* Header */}
                  <div style={{ padding:"12px 18px", borderBottom:"1px solid rgba(79,195,247,0.07)", background:"rgba(79,195,247,0.025)", display:"flex", alignItems:"center", justifyContent:"space-between", flexWrap:"wrap", gap:8 }}>
                    <div style={{ display:"flex", alignItems:"center", gap:10 }}>
                      {activeCount > 0 && <ThreatDot color="#FF6D00" size={5}/>}
                      <span style={{ fontFamily:"'Share Tech Mono',monospace", fontSize:10, color:"#4FC3F7", letterSpacing:2 }}>FIREWALL RULES — BLOCK LOG</span>
                      <span style={{ fontFamily:"monospace", fontSize:10, color:"#FF6D00", background:"rgba(255,109,0,0.12)", padding:"2px 10px", borderRadius:10, border:"1px solid rgba(255,109,0,0.25)" }}>{activeCount} ACTIVE</span>
                      <span style={{ fontFamily:"monospace", fontSize:10, color:"#546E7A", background:"rgba(84,110,122,0.08)", padding:"2px 10px", borderRadius:10 }}>{expiredCount} EXPIRED</span>
                    </div>
                    <div style={{ display:"flex", gap:4 }}>
                      {["all","active","expired"].map(f => (
                        <button key={f} onClick={()=>setFirewallFilter(f)} style={{
                          padding:"3px 12px", border:`1px solid ${firewallFilter===f?"#4FC3F7":"rgba(79,195,247,0.15)"}`,
                          borderRadius:4, background: firewallFilter===f?"rgba(79,195,247,0.1)":"transparent",
                          color: firewallFilter===f?"#4FC3F7":"#546E7A",
                          fontFamily:"'Share Tech Mono',monospace", fontSize:9, letterSpacing:1, cursor:"pointer",
                        }}>{f.toUpperCase()}</button>
                      ))}
                    </div>
                  </div>

                  {/* Table */}
                  <div style={{ padding:16 }}>
                    {filtered.length === 0 ? (
                      <div style={{ textAlign:"center", color:"#546E7A", fontFamily:"monospace", fontSize:11, padding:"30px 0" }}>
                        {firewallRules.length === 0 ? "No firewall rules yet — blocked IPs will appear here after analyst approval" : `No ${firewallFilter} rules`}
                      </div>
                    ) : (
                      <div style={{ display:"flex", flexDirection:"column", gap:8 }}>
                        {/* Column headers */}
                        <div style={{ display:"grid", gridTemplateColumns:"140px 1fr 90px 130px 130px 110px", gap:8, padding:"4px 10px", borderBottom:"1px solid rgba(79,195,247,0.08)" }}>
                          {["IP ADDRESS","JUSTIFICATION","DURATION","BLOCKED AT","EXPIRES AT","STATUS"].map(h => (
                            <span key={h} style={{ fontFamily:"'Share Tech Mono',monospace", fontSize:9, color:"#546E7A", letterSpacing:1 }}>{h}</span>
                          ))}
                        </div>
                        {filtered.map(rule => (
                          <div key={rule.id} style={{
                            display:"grid", gridTemplateColumns:"140px 1fr 90px 130px 130px 110px",
                            gap:8, padding:"10px 10px", borderRadius:6, alignItems:"center",
                            background: rule.is_active ? "rgba(255,109,0,0.04)" : "rgba(84,110,122,0.04)",
                            border: `1px solid ${rule.is_active ? "rgba(255,109,0,0.2)" : "rgba(84,110,122,0.15)"}`,
                            borderLeft: `3px solid ${rule.is_active ? "#FF6D00" : "#546E7A"}`,
                          }}>
                            <span style={{ fontFamily:"monospace", fontSize:12, color: rule.is_active ? "#FF6D00" : "#78909C", fontWeight:700 }}>
                              {rule.ip_address}
                            </span>
                            <span style={{ fontFamily:"monospace", fontSize:10, color:"#8899AA", overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }} title={rule.justification}>
                              {rule.justification || "—"}
                            </span>
                            <span style={{ fontFamily:"monospace", fontSize:10, color:"#546E7A" }}>
                              {rule.duration_hours > 0 ? `${rule.duration_hours}h` : "Expired"}
                            </span>
                            <span style={{ fontFamily:"monospace", fontSize:10, color:"#546E7A" }}>
                              {new Date(rule.created_at).toLocaleString()}
                            </span>
                            <span style={{ fontFamily:"monospace", fontSize:10, color: rule.is_active ? "#FFD740" : "#546E7A" }}>
                              {rule.expires_at ? new Date(rule.expires_at).toLocaleString() : "Never"}
                            </span>
                            <div style={{ display:"flex", alignItems:"center", gap:6 }}>
                              <span style={{
                                fontFamily:"'Share Tech Mono',monospace", fontSize:9, letterSpacing:1,
                                color: rule.is_active ? "#FF6D00" : "#546E7A",
                                background: rule.is_active ? "rgba(255,109,0,0.12)" : "rgba(84,110,122,0.12)",
                                padding:"2px 8px", borderRadius:3,
                                border: `1px solid ${rule.is_active ? "rgba(255,109,0,0.3)" : "rgba(84,110,122,0.2)"}`,
                              }}>
                                {rule.is_active ? "ACTIVE" : "EXPIRED"}
                              </span>
                              {rule.is_active && (
                                <button onClick={()=>handleUnblockIP(rule.ip_address)} disabled={!!unblockAction[rule.ip_address]}
                                  style={{ padding:"2px 8px", background:"rgba(102,187,106,0.1)", border:"1px solid rgba(102,187,106,0.3)", borderRadius:3, color:"#66BB6A", cursor: unblockAction[rule.ip_address]?"wait":"pointer", fontSize:9, fontFamily:"'Share Tech Mono',monospace", letterSpacing:0.5 }}>
                                  {unblockAction[rule.ip_address] ? "..." : "UNBLOCK"}
                                </button>
                              )}
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                  <div style={{ padding:"8px 18px", borderTop:"1px solid rgba(79,195,247,0.06)", display:"flex", alignItems:"center", gap:8 }}>
                    <span style={{ fontFamily:"monospace", fontSize:9, color:"#37474F" }}>
                      ⚠ Block rules are logged in the database only — no live firewall enforcement is active.
                      See <span style={{ color:"#4FC3F7" }}>docs/REAL_IP_BLOCKING.md</span> for production enforcement options.
                    </span>
                  </div>
                </div>
              );
            })()}
          </div>
        )}

        {/* ── INCIDENTS TAB ── */}
        {tab==="incidents" && (() => {
          const allInc        = apiLive ? (data.incidents||[]) : MOCK.incidents;
          const pendingInc    = allInc.filter(i => !i.investigation_summary || i.investigation_summary?.startsWith('⏸'));
          const investigatedInc = allInc.filter(i => i.investigation_summary && !i.investigation_summary?.startsWith('⏸'));

          function IncCard({ inc, pending=false }) {
            const isUnknown = !inc.mitre_techniques?.length || inc.mitre_techniques.includes("UNKNOWN");
            const border = pending ? "rgba(255,215,64,0.35)" : isUnknown ? "rgba(255,109,0,0.4)" : `${STATUS_COLOR[inc.status]||"#546E7A"}30`;
            const accent = pending ? "#FFD740" : isUnknown ? "#FF6D00" : (STATUS_COLOR[inc.status]||"#546E7A");
            const bgDefault = pending ? "rgba(255,215,64,0.03)" : isUnknown ? "rgba(255,109,0,0.04)" : "rgba(5,13,21,0.6)";
            const bgHover   = pending ? "rgba(255,215,64,0.07)" : isUnknown ? "rgba(255,109,0,0.08)" : "rgba(79,195,247,0.08)";
            return (
              <div
                onClick={() => openIncidentDrawer(inc)}
                style={{
                  background: bgDefault,
                  border:`1px solid ${border}`,
                  borderLeft:`3px solid ${accent}`,
                  borderRadius:8, padding:"16px 20px",
                  transition:"all 0.2s", cursor:"pointer",
                }}
                onMouseEnter={e=>e.currentTarget.style.background=bgHover}
                onMouseLeave={e=>e.currentTarget.style.background=bgDefault}>
                <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start", marginBottom:10 }}>
                  <div>
                    <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:6, flexWrap:"wrap" }}>
                      <span style={{ fontFamily:"monospace", fontSize:10, color:"#546E7A" }}>{inc.incident_id}</span>
                      <SevBadge s={inc.severity}/>
                      <span style={{ fontFamily:"monospace", fontSize:10, color:STATUS_COLOR[inc.status], background:`${STATUS_COLOR[inc.status]}18`, padding:"2px 8px", borderRadius:3, border:`1px solid ${STATUS_COLOR[inc.status]}40`, letterSpacing:1 }}>{inc.status}</span>
                      {pending && (
                        <span style={{ fontFamily:"monospace", fontSize:9, color:"#FFD740", background:"rgba(255,215,64,0.12)", padding:"2px 8px", borderRadius:3, border:"1px solid rgba(255,215,64,0.35)", letterSpacing:1, animation:"pulse 2s infinite" }}>⏸ AWAITING AI</span>
                      )}
                      {!pending && isUnknown && (
                        <span style={{ fontFamily:"monospace", fontSize:9, color:"#FF6D00", background:"rgba(255,109,0,0.12)", padding:"2px 8px", borderRadius:3, border:"1px solid rgba(255,109,0,0.3)", letterSpacing:1 }}>UNKNOWN THREAT</span>
                      )}
                    </div>
                    <div style={{ fontSize:13, color:"#E2E8F0", fontWeight:500 }}>{inc.title}</div>
                  </div>
                  <div style={{ textAlign:"right", fontFamily:"monospace", fontSize:10, color:"#546E7A", whiteSpace:"nowrap", marginLeft:12 }}>{ago(inc.created_at)}</div>
                </div>
                <div style={{ display:"flex", gap:16, flexWrap:"wrap", marginBottom:6 }}>
                  <div style={{ fontSize:11, color:"#8899AA" }}>
                    <span style={{ color:"#546E7A" }}>IPs: </span>
                    {(inc.affected_ips||[]).map(ip => <span key={ip} style={{ color:"#4FC3F7", marginRight:8, fontFamily:"monospace" }}>{ip}</span>)}
                  </div>
                  <div style={{ fontSize:11, color:"#8899AA" }}>
                    <span style={{ color:"#546E7A" }}>MITRE: </span>
                    {isUnknown && !inc.investigation_summary
                      ? <span style={{ color:"#FF6D00" }}>AI CLASSIFYING — no technique mapped</span>
                      : (inc.mitre_techniques||[]).map(m => <span key={m} style={{ color:"#FFD740", marginRight:8, fontFamily:"monospace" }}>{m}</span>)
                    }
                  </div>
                </div>
                {!pending && inc.investigation_summary && (
                  <div style={{ fontSize:10, color:"#8899AA", fontFamily:"monospace", background:"rgba(5,13,21,0.5)", border:"1px solid rgba(79,195,247,0.08)", borderRadius:4, padding:"6px 10px", maxHeight:44, overflow:"hidden", lineHeight:1.6, marginBottom:6 }}>
                    {inc.investigation_summary.substring(0,160)}{inc.investigation_summary.length>160?"…":""}
                  </div>
                )}
                {pending && (
                  <div style={{ fontSize:10, color:"#6B7280", fontFamily:"monospace", fontStyle:"italic" }}>AI investigation queued — will appear in Response panel once complete</div>
                )}
                {!pending && <div style={{ fontSize:10, color:"#38516A", fontFamily:"monospace" }}>click to investigate →</div>}
              </div>
            );
          }

          return (
            <div style={{ display:"flex", flexDirection:"column", gap:16 }}>
              {/* Status metric row */}
              <div style={{ display:"grid", gridTemplateColumns:"repeat(6,1fr)", gap:12 }}>
                {Object.entries(STATUS_COLOR).map(([s,c]) => (
                  <MetricCard key={s} label={s} icon="" color={c}
                    value={allInc.filter(i=>i.status===s).length}
                    sub={`${s.toLowerCase()}`}/>
                ))}
                <MetricCard label="AI Investigated" color="#4FC3F7" value={investigatedInc.length} icon="✓"/>
                <MetricCard label="Pending AI" color="#FFD740" value={pendingInc.length} live={pendingInc.length>0} icon="⏸"/>
              </div>

              {/* ── PENDING AI INVESTIGATION ── */}
              <div className="dash-panel" style={{ background:"rgba(7,16,27,0.8)", backdropFilter:"blur(12px)", border:`1px solid ${pendingInc.length>0?"rgba(255,215,64,0.2)":"rgba(79,195,247,0.08)"}`, borderRadius:12, overflow:"hidden" }}>
                <div style={{ padding:"12px 18px", borderBottom:`1px solid ${pendingInc.length>0?"rgba(255,215,64,0.12)":"rgba(79,195,247,0.06)"}`, background: pendingInc.length>0?"rgba(255,215,64,0.03)":"transparent", display:"flex", alignItems:"center", gap:10 }}>
                  {pendingInc.length > 0 && <ThreatDot color="#FFD740" size={5}/>}
                  <span style={{ fontFamily:"'Share Tech Mono',monospace", fontSize:10, color:"#FFD740", letterSpacing:2 }}>PENDING AI INVESTIGATION</span>
                  <span style={{ fontFamily:"monospace", fontSize:10, color:"#FFD740", background:"rgba(255,215,64,0.1)", padding:"2px 10px", borderRadius:10, border:"1px solid rgba(255,215,64,0.25)" }}>{pendingInc.length} queued</span>
                  <span style={{ marginLeft:"auto", fontFamily:"monospace", fontSize:9, color:"#546E7A" }}>not visible in Response panel until AI investigated</span>
                </div>
                <div style={{ padding:16, display:"flex", flexDirection:"column", gap:10 }}>
                  {pendingInc.length === 0 ? (
                    <div style={{ textAlign:"center", color:"#546E7A", fontFamily:"monospace", fontSize:11, padding:"20px 0" }}>
                      ✅ No pending incidents — all incidents have been AI investigated
                    </div>
                  ) : pendingInc.map(inc => <IncCard key={inc.incident_id} inc={inc} pending={true}/>)}
                </div>
              </div>

              {/* ── AI INVESTIGATED ── */}
              <div className="dash-panel" style={{ background:"rgba(7,16,27,0.8)", backdropFilter:"blur(12px)", border:"1px solid rgba(79,195,247,0.12)", borderRadius:12, overflow:"hidden" }}>
                <div style={{ padding:"12px 18px", borderBottom:"1px solid rgba(79,195,247,0.08)", background:"rgba(79,195,247,0.02)", display:"flex", alignItems:"center", gap:10 }}>
                  <span style={{ fontFamily:"'Share Tech Mono',monospace", fontSize:10, color:"#4FC3F7", letterSpacing:2 }}>AI INVESTIGATED</span>
                  <span style={{ fontFamily:"monospace", fontSize:10, color:"#4FC3F7", background:"rgba(79,195,247,0.1)", padding:"2px 10px", borderRadius:10, border:"1px solid rgba(79,195,247,0.25)" }}>{investigatedInc.length} incidents</span>
                  <span style={{ marginLeft:"auto", fontFamily:"monospace", fontSize:9, color:"#546E7A" }}>these appear in Response panel</span>
                </div>
                <div style={{ padding:16, display:"flex", flexDirection:"column", gap:10 }}>
                  {allInc.length === 0 ? (
                    <div style={{ textAlign:"center", color:"#546E7A", fontFamily:"monospace", fontSize:11, padding:"20px 0" }}>
                      {invPaused
                        ? "AI investigations paused — enable via top bar toggle"
                        : "No incidents yet — AI investigation creates incidents after each alert"}
                    </div>
                  ) : investigatedInc.length === 0 ? (
                    <div style={{ textAlign:"center", color:"#546E7A", fontFamily:"monospace", fontSize:11, padding:"20px 0" }}>
                      AI is processing — investigated incidents will appear here
                    </div>
                  ) : (
                    investigatedInc.map(inc => <IncCard key={inc.incident_id} inc={inc} pending={false}/>)
                  )}
                </div>
              </div>
            </div>
          );
        })()}

        {/* ── THREAT INTEL TAB ── */}
        {tab==="intel" && (
          <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:16 }}>
            <Panel title="Semantic Threat Search — ChromaDB" badge="NLP powered">
              <div style={{ padding:16 }}>
                <div style={{ display:"flex", gap:8, marginBottom:16 }}>
                  <input value={searchQuery} onChange={e=>setSearchQuery(e.target.value)}
                    onKeyDown={e=>e.key==="Enter"&&runThreatSearch()}
                    placeholder="e.g. C2 beacon with regular timing on port 80..."
                    style={{ flex:1, background:"rgba(5,13,21,0.8)", border:"1px solid rgba(79,195,247,0.2)", borderRadius:6, padding:"10px 14px", color:"#E2E8F0", fontSize:12, outline:"none" }}
                  />
                  <button onClick={runThreatSearch} style={{ padding:"10px 18px", background:"#1565C0", border:"none", borderRadius:6, color:"#fff", cursor:"pointer", fontSize:12 }}>
                    {loading?"...":"SEARCH"}
                  </button>
                </div>
                {threatResults.length>0 && (
                  <div style={{ display:"flex", flexDirection:"column", gap:8 }}>
                    {threatResults.map((r,i) => {
                      const doc  = r?.document  ?? (typeof r==="string" ? r : JSON.stringify(r));
                      const sim  = r?.similarity != null ? `${(r.similarity*100).toFixed(1)}%` : null;
                      const mitre = r?.metadata?.mitre ?? r?.metadata?.technique ?? null;
                      const sev   = r?.metadata?.severity ?? null;
                      return (
                        <div key={i} style={{ background:"rgba(79,195,247,0.05)", border:"1px solid rgba(79,195,247,0.15)", borderRadius:6, padding:"12px 14px" }}>
                          <div style={{ display:"flex", gap:10, alignItems:"flex-start" }}>
                            <span style={{ fontFamily:"monospace", fontSize:10, color:"#4FC3F7", background:"rgba(79,195,247,0.1)", padding:"2px 8px", borderRadius:3, marginTop:2, flexShrink:0 }}>{i+1}</span>
                            <div style={{ flex:1, minWidth:0 }}>
                              <div style={{ display:"flex", gap:8, marginBottom:5, flexWrap:"wrap" }}>
                                {sim   && <span style={{ fontFamily:"monospace", fontSize:9, color:"#00E676", background:"rgba(0,230,118,0.1)", padding:"1px 6px", borderRadius:3 }}>match {sim}</span>}
                                {mitre && <span style={{ fontFamily:"monospace", fontSize:9, color:"#FFD740", background:"rgba(255,215,64,0.1)", padding:"1px 6px", borderRadius:3 }}>{mitre}</span>}
                                {sev   && <span style={{ fontFamily:"monospace", fontSize:9, color:SEV_COLOR[sev]||"#fff", background:`${SEV_BG[sev]||"transparent"}`, padding:"1px 6px", borderRadius:3 }}>{sev}</span>}
                              </div>
                              <span style={{ fontSize:11, color:"#CBD5E1", lineHeight:1.7, fontFamily:"monospace", whiteSpace:"pre-wrap", wordBreak:"break-word" }}>{doc}</span>
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
                {searchQuery && threatResults.length===0 && !loading && (
                  <div style={{ textAlign:"center", padding:"20px 0", color:"#546E7A", fontFamily:"monospace", fontSize:11 }}>No matching signatures found for "{searchQuery}"</div>
                )}
                <div style={{ marginTop:16 }}>
                  <div style={{ fontSize:10, color:"#546E7A", letterSpacing:1, marginBottom:10 }}>CTI SOURCES — LIVE STATUS</div>
                  {[["NVD (NIST)","Every 4h","CVEs CVSS ≥ 9.0","#4FC3F7"],["CISA KEV","Every 6h","Active exploits","#E53935"],["Abuse.ch Feodo","Every 1h","C2 botnet IPs","#FF6D00"],["MITRE ATT&CK","Every 24h","500+ techniques","#FFD740"],["AlienVault OTX","Every 2h","Community threat intel","#00E676"]].map(([name,interval,desc,color]) => (
                    <div key={name} style={{ display:"flex", alignItems:"center", gap:12, padding:"8px 0", borderBottom:"1px solid rgba(255,255,255,0.03)" }}>
                      <ThreatDot color={color} size={5}/>
                      <div style={{ flex:1 }}>
                        <span style={{ fontFamily:"monospace", fontSize:11, color:"#CBD5E1" }}>{name}</span>
                        <span style={{ fontSize:10, color:"#546E7A", marginLeft:12 }}>{desc}</span>
                      </div>
                      <span style={{ fontFamily:"monospace", fontSize:10, color:color }}>{interval}</span>
                    </div>
                  ))}
                </div>
              </div>
            </Panel>

            <Panel title="MITRE ATT&CK Coverage">
              <div style={{ padding:16 }}>
                <div style={{ fontSize:10, color:"#546E7A", letterSpacing:1, marginBottom:12 }}>9 TECHNIQUES COVERED</div>
                {[
                  {id:"T1071.001",name:"C2 via HTTP/S",layer:"DPI + RLM",color:"#E53935"},
                  {id:"T1046",name:"Network Scanning",layer:"DPI",color:"#FF6D00"},
                  {id:"T1048",name:"Data Exfiltration",layer:"RLM",color:"#E53935"},
                  {id:"T1568.002",name:"DGA Malware",layer:"DPI",color:"#FF6D00"},
                  {id:"T1021.002",name:"Lateral Movement",layer:"RLM",color:"#FF6D00"},
                  {id:"T1486",name:"Ransomware Staging",layer:"RLM + DPI",color:"#E53935"},
                  {id:"T1003",name:"Credential Dumping",layer:"RLM",color:"#FF6D00"},
                  {id:"T1090.003",name:"Tor / Proxy Use",layer:"DPI + CTI",color:"#FFD740"},
                  {id:"T1595",name:"Active Scanning",layer:"DPI",color:"#4FC3F7"},
                ].map(t => (
                  <div key={t.id} style={{ display:"flex", alignItems:"center", gap:12, padding:"8px 0", borderBottom:"1px solid rgba(255,255,255,0.03)" }}>
                    <span style={{ fontFamily:"monospace", fontSize:10, color:t.color, background:`${t.color}15`, padding:"2px 8px", borderRadius:3, border:`1px solid ${t.color}30`, minWidth:80 }}>{t.id}</span>
                    <div style={{ flex:1 }}>
                      <span style={{ fontSize:12, color:"#CBD5E1" }}>{t.name}</span>
                    </div>
                    <span style={{ fontFamily:"monospace", fontSize:10, color:"#546E7A" }}>{t.layer}</span>
                  </div>
                ))}
              </div>
            </Panel>
          </div>
        )}

        {/* ── HOST INTEL TAB ── */}
        {tab==="hosts" && (
          <div style={{ display:"flex", flexDirection:"column", gap:16 }}>
            <Panel title="Host Intelligence — RLM Behavioral Profile">
              <div style={{ padding:16 }}>
                <div style={{ display:"flex", gap:8, marginBottom:20 }}>
                  <input value={searchIp} onChange={e=>setSearchIp(e.target.value)}
                    onKeyDown={e=>e.key==="Enter"&&searchHost()}
                    placeholder="Enter IP address e.g. 10.0.0.55"
                    style={{ flex:1, background:"rgba(5,13,21,0.8)", border:"1px solid rgba(79,195,247,0.2)", borderRadius:6, padding:"10px 14px", color:"#E2E8F0", fontSize:13, outline:"none" }}
                  />
                  <button onClick={searchHost} style={{ padding:"10px 20px", background:"#1565C0", border:"none", borderRadius:6, color:"#fff", cursor:"pointer" }}>
                    {loading?"LOADING...":"LOOKUP"}
                  </button>
                </div>
                {hostProfile && (() => {
                  const p = hostProfile.profile || {};
                  const anomalyScore = p.anomaly_score || 0;
                  const avgBytes    = p.avg_bytes_per_min || 0;
                  const avgEntropy  = p.avg_entropy || 0;
                  const obsCount    = p.observation_count || 0;
                  const profileText = p.profile_text || "PROFILED";
                  return (
                    <div style={{ display:"flex", flexDirection:"column", gap:16 }}>
                      {/* Metric Cards */}
                      <div style={{ display:"grid", gridTemplateColumns:"repeat(3,1fr)", gap:12 }}>
                        {[
                          {label:"IP Address",    value:hostProfile.ip_address||searchIp,                      color:"#4FC3F7"},
                          {label:"Anomaly Score", value:`${(anomalyScore*100).toFixed(0)}%`,                   color:anomalyScore>0.65?"#E53935":"#00E676"},
                          {label:"Avg Bytes/Min", value:avgBytes.toLocaleString(),                             color:"#FFD740"},
                          {label:"Avg Entropy",   value:avgEntropy.toFixed(2),                                 color:avgEntropy>7?"#E53935":"#00E676"},
                          {label:"Observations",  value:obsCount.toLocaleString(),                             color:"#4FC3F7"},
                          {label:"Blocked",       value:hostProfile.is_blocked?"YES":"NO",                     color:hostProfile.is_blocked?"#E53935":"#00E676"},
                        ].map(item => (
                          <div key={item.label} style={{ background:"rgba(5,13,21,0.7)", border:`1px solid ${item.color}25`, borderRadius:8, padding:"16px 18px" }}>
                            <div style={{ fontSize:9, color:"#546E7A", letterSpacing:2, marginBottom:8 }}>{item.label.toUpperCase()}</div>
                            <div style={{ fontFamily:"'Share Tech Mono',monospace", fontSize:22, color:item.color, fontWeight:700 }}>{item.value}</div>
                          </div>
                        ))}
                      </div>

                      {/* Risk Summary Row */}
                      <div style={{ display:"grid", gridTemplateColumns:"repeat(3,1fr)", gap:12 }}>
                        {[
                          {label:"Block Events",    value:(hostProfile.block_count||0).toString(),    color:"#FF7043"},
                          {label:"Linked Incidents",value:(hostProfile.incident_count||0).toString(), color:"#FFD740"},
                          {label:"Profile Note",    value:profileText,                                color:"#78909C"},
                        ].map(item => (
                          <div key={item.label} style={{ background:"rgba(5,13,21,0.7)", border:`1px solid ${item.color}25`, borderRadius:8, padding:"16px 18px" }}>
                            <div style={{ fontSize:9, color:"#546E7A", letterSpacing:2, marginBottom:8 }}>{item.label.toUpperCase()}</div>
                            <div style={{ fontFamily:"'Share Tech Mono',monospace", fontSize:item.label==="Profile Note"?11:22, color:item.color, fontWeight:700, wordBreak:"break-word", lineHeight:1.4 }}>{item.value}</div>
                          </div>
                        ))}
                      </div>

                      {/* Recent Alerts */}
                      {hostProfile.recent_alerts && hostProfile.recent_alerts.length > 0 && (
                        <div style={{ background:"rgba(5,13,21,0.7)", border:"1px solid rgba(79,195,247,0.1)", borderRadius:8, padding:16 }}>
                          <div style={{ fontSize:10, color:"#546E7A", letterSpacing:2, marginBottom:12 }}>RECENT ALERTS</div>
                          {hostProfile.recent_alerts.map((al, i) => (
                            <div key={i} style={{ display:"flex", alignItems:"center", gap:10, padding:"6px 0", borderBottom:"1px solid rgba(255,255,255,0.03)" }}>
                              <SevBadge s={al.severity}/>
                              <span style={{ fontFamily:"monospace", fontSize:11, color:"#CBD5E1", flex:1 }}>{al.type}</span>
                              {al.mitre_technique && (
                                <span style={{ fontFamily:"monospace", fontSize:9, color:"#FFD740", background:"rgba(255,215,64,0.08)", padding:"2px 6px", borderRadius:3, border:"1px solid rgba(255,215,64,0.2)" }}>{al.mitre_technique}</span>
                              )}
                              <span style={{ fontFamily:"monospace", fontSize:9, color:"#546E7A" }}>{al.timestamp ? new Date(al.timestamp).toLocaleTimeString() : ""}</span>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  );
                })()}
                {!hostProfile && (
                  <div style={{ textAlign:"center", padding:40, color:"#546E7A", fontFamily:"monospace", fontSize:12 }}>
                    Enter an IP address to retrieve its RLM behavioral profile from ChromaDB
                  </div>
                )}
              </div>
            </Panel>
          </div>
        )}

        {/* ── THREAT FEED TAB ── */}
        {tab==="threatfeed" && (() => {
          const feedAlerts = apiLive ? (data.alerts||[]) : MOCK.alerts;

          // ── MITRE technique → tactic + kill chain phase ─────────────────────
          const TACTIC_MAP = {
            "T1190":   { tactic:"Initial Access",    phase:0, icon:"🚪" },
            "T1059.004":{ tactic:"Execution",        phase:1, icon:"⚡" },
            "T1027":   { tactic:"Defense Evasion",   phase:2, icon:"🕵️" },
            "T1205":   { tactic:"Defense Evasion",   phase:2, icon:"🕵️" },
            "T1564.004":{ tactic:"Defense Evasion",  phase:2, icon:"🕵️" },
            "T1110.001":{ tactic:"Credential Access",phase:3, icon:"🔑" },
            "T1110.003":{ tactic:"Credential Access",phase:3, icon:"🔑" },
            "T1046":   { tactic:"Discovery",         phase:4, icon:"🔍" },
            "T1021.001":{ tactic:"Lateral Movement", phase:5, icon:"↔️" },
            "T1021.002":{ tactic:"Lateral Movement", phase:5, icon:"↔️" },
            "T1071.001":{ tactic:"Command & Control",phase:6, icon:"📡" },
            "T1071.004":{ tactic:"Command & Control",phase:6, icon:"📡" },
            "T1572":   { tactic:"Command & Control", phase:6, icon:"📡" },
            "T1090.003":{ tactic:"Command & Control",phase:6, icon:"📡" },
            "T1048.003":{ tactic:"Exfiltration",     phase:7, icon:"📤" },
          };
          const KILL_CHAIN = [
            { label:"Initial Access",    phase:0, icon:"🚪" },
            { label:"Execution",         phase:1, icon:"⚡" },
            { label:"Defense Evasion",   phase:2, icon:"🕵️" },
            { label:"Credential Access", phase:3, icon:"🔑" },
            { label:"Discovery",         phase:4, icon:"🔍" },
            { label:"Lateral Movement",  phase:5, icon:"↔️" },
            { label:"C2",                phase:6, icon:"📡" },
            { label:"Exfiltration",      phase:7, icon:"📤" },
          ];

          // Active phases from current alerts
          const activePhases = new Set(
            feedAlerts
              .map(a => TACTIC_MAP[a.mitre_technique]?.phase)
              .filter(p => p != null)
          );

          // ── Alert velocity: 5-min buckets for last hour ─────────────────────
          const now = Date.now();
          const BUCKETS = 12;
          const velocityBuckets = Array.from({length:BUCKETS}, (_,i) => ({
            label: `${(BUCKETS-1-i)*5}m`,
            count: 0,
          }));
          feedAlerts.forEach(a => {
            const age = (now - new Date(a.timestamp).getTime()) / 60000; // minutes
            const idx = Math.floor(age / 5);
            if (idx >= 0 && idx < BUCKETS) velocityBuckets[BUCKETS-1-idx].count++;
          });
          const maxVelocity = Math.max(...velocityBuckets.map(b => b.count), 1);

          // ── IP campaign detection: ≥2 alerts from same src_ip ──────────────
          const ipCount = {};
          feedAlerts.forEach(a => { if (a.src_ip) ipCount[a.src_ip] = (ipCount[a.src_ip]||0)+1; });
          const campaignIPs = new Set(Object.keys(ipCount).filter(ip => ipCount[ip] >= 2));

          // ── Filtering ───────────────────────────────────────────────────────
          const searchLower = feedSearch.toLowerCase();
          const filtered = feedAlerts.filter(a => {
            if (feedFilter !== "ALL" && a.severity !== feedFilter) return false;
            if (searchLower) {
              const haystack = [a.type, a.src_ip, a.dst_ip, a.mitre_technique, ...(a.suspicion_reasons||[])].join(" ").toLowerCase();
              if (!haystack.includes(searchLower)) return false;
            }
            return true;
          });
          const unknownFiltered = filtered.filter(a => !a.mitre_technique || a.mitre_technique === "UNKNOWN" || a.mitre_technique === "");
          const knownFiltered   = filtered.filter(a =>  a.mitre_technique && a.mitre_technique !== "UNKNOWN" && a.mitre_technique !== "");

          // ── Ticker items: newest 8 alerts ───────────────────────────────────
          const tickerItems = [...feedAlerts].sort((a,b) => new Date(b.timestamp)-new Date(a.timestamp)).slice(0,8);

          // ── ThreatCard component ─────────────────────────────────────────────
          function ThreatCard({ a, idx }) {
            const isUnknown  = !a.mitre_technique || a.mitre_technique === "UNKNOWN" || a.mitre_technique === "";
            const accentLeft = isUnknown ? "#FF6D00" : (SEV_COLOR[a.severity]||"#4FC3F7");
            const cardBg     = isUnknown ? "rgba(255,109,0,0.04)" : (SEV_BG[a.severity]||"rgba(79,195,247,0.04)");
            const cardBorder = isUnknown ? "rgba(255,109,0,0.35)" : `${SEV_COLOR[a.severity]||"#4FC3F7"}35`;
            const cardId     = a.id || `${a.src_ip}-${a.type}-${idx}`;
            const isExpanded = expandedCard === cardId;
            const isCampaign = campaignIPs.has(a.src_ip);
            const tactic     = TACTIC_MAP[a.mitre_technique];
            const playbook   = MITRE_PLAYBOOK[a.mitre_technique];
            const reasons    = Array.isArray(a.suspicion_reasons) ? a.suspicion_reasons
              : (a.reasons ? (Array.isArray(a.reasons) ? a.reasons : [a.reasons]) : []);
            const hasProfile = (a.anomaly_score != null && a.anomaly_score > 0) || a.avg_bytes_per_min != null || a.avg_entropy != null;
            const tsAge      = now - new Date(a.timestamp).getTime();
            const ageColor   = tsAge < 5*60000 ? "#E53935" : tsAge < 30*60000 ? "#FF6D00" : "#546E7A";

            return (
              <div
                onClick={() => setExpandedCard(isExpanded ? null : cardId)}
                style={{
                  background: cardBg,
                  border: `1px solid ${isExpanded ? accentLeft+"88" : cardBorder}`,
                  borderLeft: `4px solid ${accentLeft}`,
                  borderRadius: 10,
                  padding: "16px 20px",
                  display: "flex", flexDirection: "column", gap: 10,
                  cursor: "pointer",
                  transition: "border-color 0.2s",
                  position: "relative",
                }}>

                {/* Campaign badge */}
                {isCampaign && (
                  <div style={{
                    position:"absolute", top:10, right:12,
                    fontFamily:"monospace", fontSize:8, letterSpacing:1,
                    color:"#FFD740", background:"rgba(255,215,64,0.1)",
                    padding:"2px 7px", borderRadius:3, border:"1px solid rgba(255,215,64,0.25)",
                  }}>
                    CAMPAIGN · {ipCount[a.src_ip]} alerts
                  </div>
                )}

                {/* Row 1 — header */}
                <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", flexWrap:"wrap", gap:8 }}>
                  <div style={{ display:"flex", alignItems:"center", gap:8, flexWrap:"wrap" }}>
                    <ThreatDot color={accentLeft} size={6}/>
                    <span style={{ fontFamily:"'Share Tech Mono',monospace", fontSize:13, fontWeight:700, color:accentLeft, letterSpacing:0.5 }}>
                      {a.type?.replace(/_DETECTED$/,"").replace(/_/g," ") || "UNKNOWN THREAT"}
                    </span>
                    <SevBadge s={a.severity||"MEDIUM"}/>
                    {isUnknown ? (
                      <span style={{ fontFamily:"monospace", fontSize:9, color:"#FF6D00", background:"rgba(255,109,0,0.12)", padding:"2px 8px", borderRadius:3, border:"1px solid rgba(255,109,0,0.3)", letterSpacing:1, fontWeight:700, animation:"pulse 2s infinite" }}>
                        UNKNOWN — AI CLASSIFYING
                      </span>
                    ) : (
                      <span style={{ fontFamily:"monospace", fontSize:9, color:"#FFD740", background:"rgba(255,215,64,0.08)", padding:"2px 8px", borderRadius:3, border:"1px solid rgba(255,215,64,0.2)" }}>
                        {a.mitre_technique}
                      </span>
                    )}
                    {tactic && (
                      <span style={{ fontFamily:"monospace", fontSize:9, color:"#78909C", background:"rgba(255,255,255,0.04)", padding:"2px 8px", borderRadius:3, border:"1px solid rgba(255,255,255,0.06)" }}>
                        {tactic.icon} {tactic.tactic}
                      </span>
                    )}
                  </div>
                  <div style={{ display:"flex", alignItems:"center", gap:10 }}>
                    <span style={{ fontFamily:"monospace", fontSize:10, color:ageColor }}>{ago(a.timestamp)}</span>
                    <span style={{ fontFamily:"monospace", fontSize:10, color:"#546E7A" }}>{isExpanded ? "▲" : "▼"}</span>
                  </div>
                </div>

                {/* Row 2 — network flow */}
                <div style={{ display:"flex", alignItems:"center", gap:8, fontFamily:"'Share Tech Mono',monospace", fontSize:12 }}>
                  <span style={{ color:"#4FC3F7", background:"rgba(79,195,247,0.1)", padding:"3px 10px", borderRadius:4 }}>
                    {a.src_ip||"?"}:{a.src_port||"?"}
                  </span>
                  <span style={{ color:"#546E7A", fontSize:16 }}>→</span>
                  <span style={{ color:"#CBD5E1", background:"rgba(255,255,255,0.04)", padding:"3px 10px", borderRadius:4 }}>
                    {a.dst_ip||"?"}:{a.dst_port||"?"}
                  </span>
                  <span style={{ fontFamily:"monospace", fontSize:10, color:"#546E7A", marginLeft:4 }}>{a.protocol||"TCP"}</span>
                  {a.has_tls && <span style={{ fontSize:9, color:"#00E676", background:"rgba(0,230,118,0.1)", padding:"2px 6px", borderRadius:3, border:"1px solid rgba(0,230,118,0.2)" }}>TLS</span>}
                  {/* Anomaly score bar */}
                  {a.anomaly_score > 0 && (
                    <div style={{ marginLeft:"auto", display:"flex", alignItems:"center", gap:6 }}>
                      <span style={{ fontFamily:"monospace", fontSize:9, color:"#546E7A" }}>RISK</span>
                      <div style={{ width:60, height:5, background:"rgba(255,255,255,0.08)", borderRadius:3, overflow:"hidden" }}>
                        <div style={{ height:"100%", borderRadius:3, width:`${(a.anomaly_score||0)*100}%`, background: a.anomaly_score>0.85?"#E53935":a.anomaly_score>0.65?"#FF6D00":"#FFD740", transition:"width 0.5s" }}/>
                      </div>
                      <span style={{ fontFamily:"monospace", fontSize:9, color: a.anomaly_score>0.85?"#E53935":a.anomaly_score>0.65?"#FF6D00":"#FFD740" }}>
                        {((a.anomaly_score||0)*100).toFixed(0)}%
                      </span>
                    </div>
                  )}
                </div>

                {/* Evidence pills — always visible */}
                {reasons.length > 0 && (
                  <div style={{ display:"flex", gap:5, flexWrap:"wrap" }}>
                    <span style={{ fontSize:9, color:"#546E7A", fontFamily:"monospace", alignSelf:"center", letterSpacing:1 }}>EVIDENCE:</span>
                    {reasons.slice(0, isExpanded ? reasons.length : 4).map((r,i) => (
                      <span key={i} style={{
                        fontFamily:"monospace", fontSize:9,
                        color: isUnknown ? "#FF9800" : "#8899AA",
                        background: isUnknown ? "rgba(255,152,0,0.08)" : "rgba(255,255,255,0.04)",
                        padding:"2px 7px", borderRadius:3,
                        border: isUnknown ? "1px solid rgba(255,152,0,0.2)" : "1px solid rgba(255,255,255,0.06)",
                      }}>{r}</span>
                    ))}
                    {!isExpanded && reasons.length > 4 && <span style={{ fontSize:9, color:"#546E7A", fontFamily:"monospace" }}>+{reasons.length-4} more</span>}
                  </div>
                )}

                {/* ── EXPANDED DETAIL ────────────────────────────────────────── */}
                {isExpanded && (
                  <div style={{ display:"flex", flexDirection:"column", gap:10, borderTop:`1px solid ${accentLeft}22`, paddingTop:10, marginTop:2 }}>

                    {/* AI investigation summary */}
                    {(a.description || a.investigation_summary) && (
                      <div style={{ background:"rgba(5,13,21,0.6)", border:"1px solid rgba(79,195,247,0.12)", borderRadius:6, padding:"10px 14px" }}>
                        <span style={{ fontFamily:"monospace", fontSize:9, color:"#4FC3F7", letterSpacing:1, display:"block", marginBottom:6 }}>
                          {isUnknown ? "AI CLASSIFICATION PENDING" : "AI INVESTIGATION SUMMARY"}
                        </span>
                        <div style={{ fontSize:11, color:"#CBD5E1", lineHeight:1.8, fontFamily:"monospace", whiteSpace:"pre-wrap" }}>
                          {(a.investigation_summary || a.description || "")}
                        </div>
                      </div>
                    )}

                    {/* Behavioral profile row */}
                    {hasProfile && (
                      <div style={{ display:"flex", gap:8, flexWrap:"wrap" }}>
                        <span style={{ fontSize:9, color:"#546E7A", fontFamily:"monospace", alignSelf:"center", letterSpacing:1 }}>BEHAVIOR:</span>
                        {a.avg_bytes_per_min > 0 && (
                          <span style={{ fontFamily:"monospace", fontSize:10, color:"#8899AA", background:"rgba(5,13,21,0.6)", padding:"3px 8px", borderRadius:3, border:"1px solid rgba(255,255,255,0.06)" }}>
                            ↑ {(a.avg_bytes_per_min/1000).toFixed(1)} KB/min
                          </span>
                        )}
                        {a.avg_entropy > 0 && (
                          <span style={{ fontFamily:"monospace", fontSize:10, color: a.avg_entropy>7.5?"#E53935":a.avg_entropy>6.5?"#FF6D00":"#8899AA", background:"rgba(5,13,21,0.6)", padding:"3px 8px", borderRadius:3, border:"1px solid rgba(255,255,255,0.06)" }}>
                            entropy {(a.avg_entropy||0).toFixed(2)}
                          </span>
                        )}
                        {a.observation_count > 0 && (
                          <span style={{ fontFamily:"monospace", fontSize:10, color:"#8899AA", background:"rgba(5,13,21,0.6)", padding:"3px 8px", borderRadius:3, border:"1px solid rgba(255,255,255,0.06)" }}>
                            {a.observation_count} packets observed
                          </span>
                        )}
                        {a.payload_size > 0 && (
                          <span style={{ fontFamily:"monospace", fontSize:10, color:"#8899AA", background:"rgba(5,13,21,0.6)", padding:"3px 8px", borderRadius:3, border:"1px solid rgba(255,255,255,0.06)" }}>
                            payload {a.payload_size>1000000?`${(a.payload_size/1000000).toFixed(1)}MB`:a.payload_size>1000?`${(a.payload_size/1000).toFixed(0)}KB`:`${a.payload_size}B`}
                          </span>
                        )}
                      </div>
                    )}

                    {/* MITRE playbook */}
                    {playbook && (
                      <div style={{ background:"rgba(255,215,64,0.03)", border:"1px solid rgba(255,215,64,0.15)", borderRadius:6, padding:"12px 14px" }}>
                        <div style={{ fontFamily:"monospace", fontSize:9, color:"#FFD740", letterSpacing:1, marginBottom:8 }}>
                          MITRE {a.mitre_technique} — {playbook.name} — RESPONSE PLAYBOOK
                        </div>
                        {playbook.steps.map((step, i) => (
                          <div key={i} style={{ display:"flex", gap:10, marginBottom:6 }}>
                            <span style={{
                              fontFamily:"monospace", fontSize:9, fontWeight:700, minWidth:14,
                              color: i===0?"#E53935":i===1?"#FF6D00":"#546E7A",
                            }}>{i+1}.</span>
                            <span style={{ fontFamily:"monospace", fontSize:10, color:"#8899AA", lineHeight:1.6 }}>{step}</span>
                          </div>
                        ))}
                      </div>
                    )}

                    {/* Block recommendation */}
                    {(a.block_recommended || isUnknown) && (
                      <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", background:"rgba(229,57,53,0.05)", border:"1px solid rgba(229,57,53,0.2)", borderRadius:6, padding:"8px 14px" }}>
                        <div style={{ display:"flex", alignItems:"center", gap:8 }}>
                          <ThreatDot color="#E53935" size={5}/>
                          <span style={{ fontFamily:"monospace", fontSize:10, color:"#E53935" }}>
                            {isUnknown ? "UNKNOWN THREAT — Human review required before any action" : "Block recommended — pending analyst decision"}
                          </span>
                        </div>
                        <span style={{ fontFamily:"monospace", fontSize:9, color:"#546E7A" }}>→ RESPONSE tab</span>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          }

          return (
            <div style={{ display:"flex", flexDirection:"column", gap:14 }}>

              {/* ── LIVE THREAT TICKER ──────────────────────────────────────── */}
              {tickerItems.length > 0 && (
                <div style={{
                  background:"rgba(5,13,21,0.8)", border:`1px solid ${ACCENT}33`,
                  borderRadius:6, padding:"6px 12px", overflow:"hidden", position:"relative",
                }}>
                  <div style={{ display:"flex", alignItems:"center", gap:10 }}>
                    <span style={{ fontFamily:"monospace", fontSize:9, color:ACCENT, letterSpacing:2, whiteSpace:"nowrap", borderRight:`1px solid ${ACCENT}44`, paddingRight:10, marginRight:2 }}>
                      LIVE FEED
                    </span>
                    <div style={{ overflow:"hidden", flex:1 }}>
                      <div style={{ display:"flex", gap:24, animation:"ticker 30s linear infinite", whiteSpace:"nowrap" }}>
                        {[...tickerItems, ...tickerItems].map((a,i) => (
                          <span key={i} style={{ fontFamily:"'Share Tech Mono',monospace", fontSize:10, display:"inline-flex", alignItems:"center", gap:8 }}>
                            <span style={{ color:SEV_COLOR[a.severity]||"#4FC3F7", fontWeight:700 }}>◉</span>
                            <span style={{ color:"#CBD5E1" }}>{a.type?.replace(/_DETECTED$/,"").replace(/_/g," ")}</span>
                            <span style={{ color:"#546E7A" }}>{a.src_ip}</span>
                            <span style={{ color:"#38516A" }}>·</span>
                            <span style={{ color:"#546E7A", fontSize:9 }}>{ago(a.timestamp)}</span>
                            <span style={{ color:"#38516A", marginLeft:8 }}>│</span>
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* ── METRICS ROW ─────────────────────────────────────────────── */}
              <div style={{ display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:12 }}>
                <MetricCard label="Total Alerts" value={feedAlerts.length} color="#4FC3F7" live icon="📡"/>
                <MetricCard label="Novel Threats" value={feedAlerts.filter(a=>!a.mitre_technique||a.mitre_technique===""||a.mitre_technique==="UNKNOWN").length} color="#FF6D00" live={feedAlerts.some(a=>!a.mitre_technique)} icon="❓"/>
                <MetricCard label="MITRE-Mapped" value={feedAlerts.filter(a=>a.mitre_technique&&a.mitre_technique!=="UNKNOWN"&&a.mitre_technique!=="").length} color="#00E676" icon="🗺️"/>
                <MetricCard label="Critical / High" value={feedAlerts.filter(a=>a.severity==="CRITICAL"||a.severity==="HIGH").length} color="#E53935" live icon="🚨"/>
              </div>

              {/* ── KILL CHAIN + VELOCITY ROW ───────────────────────────────── */}
              <div style={{ display:"grid", gridTemplateColumns:"1fr 260px", gap:12 }}>

                {/* Kill Chain */}
                <div style={{ background:"rgba(5,13,21,0.6)", border:"1px solid rgba(79,195,247,0.1)", borderRadius:8, padding:"14px 18px" }}>
                  <div style={{ fontFamily:"monospace", fontSize:9, color:"#546E7A", letterSpacing:2, marginBottom:12 }}>MITRE ATT&CK KILL CHAIN — ACTIVE PHASES</div>
                  <div style={{ display:"flex", alignItems:"stretch", gap:0 }}>
                    {KILL_CHAIN.map((phase, i) => {
                      const active = activePhases.has(phase.phase);
                      return (
                        <div key={i} style={{ flex:1, display:"flex", flexDirection:"column", alignItems:"center", gap:6, position:"relative" }}>
                          {/* Connector line */}
                          {i < KILL_CHAIN.length-1 && (
                            <div style={{
                              position:"absolute", top:16, left:"50%", right:"-50%",
                              height:2, background: active?"rgba(229,57,53,0.4)":"rgba(255,255,255,0.06)", zIndex:0,
                            }}/>
                          )}
                          {/* Phase node */}
                          <div style={{
                            width:32, height:32, borderRadius:"50%", zIndex:1,
                            display:"flex", alignItems:"center", justifyContent:"center",
                            fontSize:14,
                            background: active ? "rgba(229,57,53,0.15)" : "rgba(255,255,255,0.04)",
                            border: active ? "2px solid #E53935" : "2px solid rgba(255,255,255,0.08)",
                            boxShadow: active ? "0 0 12px rgba(229,57,53,0.4)" : "none",
                            animation: active ? "pulse 2s infinite" : "none",
                          }}>{phase.icon}</div>
                          <div style={{
                            fontFamily:"monospace", fontSize:8, textAlign:"center", letterSpacing:0.3,
                            color: active ? "#E53935" : "#38516A",
                            fontWeight: active ? 700 : 400,
                            lineHeight:1.3,
                          }}>
                            {phase.label.split(" ").join("\n")}
                          </div>
                          {active && (
                            <div style={{ width:6, height:6, borderRadius:"50%", background:"#E53935", animation:"pulse 1s infinite" }}/>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* Alert Velocity chart */}
                <div style={{ background:"rgba(5,13,21,0.6)", border:"1px solid rgba(79,195,247,0.1)", borderRadius:8, padding:"14px 18px" }}>
                  <div style={{ fontFamily:"monospace", fontSize:9, color:"#546E7A", letterSpacing:2, marginBottom:12 }}>ALERT VELOCITY — LAST HOUR</div>
                  <div style={{ display:"flex", alignItems:"flex-end", gap:3, height:60 }}>
                    {velocityBuckets.map((b,i) => {
                      const h = Math.max(3, (b.count / maxVelocity) * 54);
                      const isRecent = i >= BUCKETS-3;
                      return (
                        <div key={i} style={{ flex:1, display:"flex", flexDirection:"column", alignItems:"center", gap:2 }}>
                          <div style={{
                            width:"100%", height:h, borderRadius:"2px 2px 0 0",
                            background: isRecent
                              ? (b.count>0 ? "#E53935" : "rgba(229,57,53,0.2)")
                              : (b.count>0 ? ACCENT : `${ACCENT}22`),
                            transition:"height 0.4s",
                          }}/>
                        </div>
                      );
                    })}
                  </div>
                  <div style={{ display:"flex", justifyContent:"space-between", marginTop:6 }}>
                    <span style={{ fontFamily:"monospace", fontSize:8, color:"#38516A" }}>60m ago</span>
                    <span style={{ fontFamily:"monospace", fontSize:8, color:"#38516A" }}>now</span>
                  </div>
                  <div style={{ marginTop:6, fontFamily:"monospace", fontSize:9, color:ACCENT, textAlign:"center" }}>
                    {velocityBuckets.slice(-3).reduce((s,b)=>s+b.count,0)} alerts in last 15 min
                  </div>
                </div>
              </div>

              {/* ── FILTER BAR ──────────────────────────────────────────────── */}
              <div style={{ display:"flex", gap:8, alignItems:"center", flexWrap:"wrap" }}>
                <span style={{ fontFamily:"monospace", fontSize:9, color:"#546E7A", letterSpacing:1 }}>FILTER:</span>
                {["ALL","CRITICAL","HIGH","MEDIUM","LOW"].map(f => (
                  <button key={f} onClick={e=>{e.stopPropagation();setFeedFilter(f);}} style={{
                    fontFamily:"monospace", fontSize:9, padding:"3px 10px", borderRadius:3, cursor:"pointer",
                    background: feedFilter===f ? (f==="ALL"?ACCENT:SEV_COLOR[f]||ACCENT)+"22" : "rgba(255,255,255,0.04)",
                    border: feedFilter===f ? `1px solid ${f==="ALL"?ACCENT:SEV_COLOR[f]||ACCENT}` : "1px solid rgba(255,255,255,0.08)",
                    color: feedFilter===f ? (f==="ALL"?ACCENT:SEV_COLOR[f]||ACCENT) : "#546E7A",
                    letterSpacing:1, fontWeight: feedFilter===f?700:400,
                  }}>{f}</button>
                ))}
                <div style={{ flex:1, minWidth:160, display:"flex", alignItems:"center", gap:6,
                  background:"rgba(255,255,255,0.04)", border:"1px solid rgba(255,255,255,0.08)",
                  borderRadius:4, padding:"4px 10px" }}>
                  <span style={{ color:"#546E7A", fontSize:11 }}>⌕</span>
                  <input
                    value={feedSearch}
                    onChange={e=>setFeedSearch(e.target.value)}
                    placeholder="Search IP, type, MITRE..."
                    onClick={e=>e.stopPropagation()}
                    style={{ background:"transparent", border:"none", outline:"none", flex:1,
                      fontFamily:"monospace", fontSize:10, color:"#CBD5E1" }}
                  />
                  {feedSearch && <button onClick={e=>{e.stopPropagation();setFeedSearch("");}} style={{ background:"none",border:"none",cursor:"pointer",color:"#546E7A",fontSize:11 }}>✕</button>}
                </div>
                <span style={{ fontFamily:"monospace", fontSize:9, color:"#546E7A", marginLeft:"auto" }}>
                  {filtered.length} / {feedAlerts.length} shown
                </span>
              </div>

              {/* ── UNKNOWN / NOVEL THREATS ─────────────────────────────────── */}
              {unknownFiltered.length > 0 && (
                <div>
                  <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:10 }}>
                    <ThreatDot color="#FF6D00" size={6}/>
                    <span style={{ fontFamily:"'Share Tech Mono',monospace", fontSize:11, color:"#FF6D00", letterSpacing:2 }}>
                      NOVEL / UNCLASSIFIED THREATS — AI REVIEW REQUIRED
                    </span>
                    <span style={{ fontFamily:"monospace", fontSize:9, color:"#546E7A", marginLeft:"auto" }}>{unknownFiltered.length} unclassified</span>
                  </div>
                  <div style={{ display:"flex", flexDirection:"column", gap:8 }}>
                    {unknownFiltered.map((a,i) => <ThreatCard key={a.id||`u${i}`} a={a} idx={i}/>)}
                  </div>
                </div>
              )}

              {/* ── SEPARATOR ───────────────────────────────────────────────── */}
              {unknownFiltered.length > 0 && knownFiltered.length > 0 && (
                <div style={{ display:"flex", alignItems:"center", gap:12 }}>
                  <div style={{ flex:1, height:"1px", background:"rgba(79,195,247,0.08)" }}/>
                  <span style={{ fontFamily:"monospace", fontSize:9, color:"#546E7A", letterSpacing:2 }}>MITRE ATT&CK MAPPED THREATS</span>
                  <div style={{ flex:1, height:"1px", background:"rgba(79,195,247,0.08)" }}/>
                </div>
              )}

              {/* ── KNOWN THREATS ───────────────────────────────────────────── */}
              {knownFiltered.length > 0 && (
                <div style={{ display:"flex", flexDirection:"column", gap:8 }}>
                  {knownFiltered.map((a,i) => <ThreatCard key={a.id||`k${i}`} a={a} idx={i}/>)}
                </div>
              )}

              {/* ── EMPTY STATE ─────────────────────────────────────────────── */}
              {filtered.length === 0 && (
                <div style={{ textAlign:"center", padding:"60px 0", color:"#546E7A", fontFamily:"monospace", fontSize:13 }}>
                  <div style={{ fontSize:32, marginBottom:12 }}>📡</div>
                  <div>{feedAlerts.length > 0 ? "No threats match current filters" : "No threats detected yet"}</div>
                  <div style={{ fontSize:11, marginTop:8, color:"#38516A" }}>
                    {feedAlerts.length > 0 ? "Try clearing the search or changing severity filter" : "Threat cards appear here as RLM scores anomalies"}
                  </div>
                </div>
              )}
            </div>
          );
        })()}

      </div>

      {/* ── INCIDENT DETAIL DRAWER ── */}
      {selectedIncident && (
        <div style={{
          position:"fixed", top:0, right:0, width:520, height:"100vh",
          background:"rgba(5,13,21,0.97)", borderLeft:"1px solid rgba(79,195,247,0.2)",
          zIndex:1000, overflowY:"auto", boxShadow:"-8px 0 32px rgba(0,0,0,0.6)",
          display:"flex", flexDirection:"column",
        }}>
          {/* Drawer Header */}
          <div style={{ padding:"20px 24px 16px", borderBottom:"1px solid rgba(79,195,247,0.1)", background:"rgba(79,195,247,0.03)" }}>
            <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start" }}>
              <div>
                <div style={{ fontFamily:"monospace", fontSize:10, color:"#546E7A", marginBottom:4 }}>{selectedIncident.incident_id}</div>
                <div style={{ display:"flex", gap:8, alignItems:"center", marginBottom:8 }}>
                  <SevBadge s={selectedIncident.severity}/>
                  <span style={{ fontFamily:"monospace", fontSize:10, color:STATUS_COLOR[incidentDetail?.status||selectedIncident.status]||"#546E7A", background:`${STATUS_COLOR[incidentDetail?.status||selectedIncident.status]||"#546E7A"}18`, padding:"2px 8px", borderRadius:3, border:`1px solid ${STATUS_COLOR[incidentDetail?.status||selectedIncident.status]||"#546E7A"}40`, letterSpacing:1 }}>
                    {incidentDetail?.status || selectedIncident.status}
                  </span>
                </div>
                <div style={{ fontSize:13, color:"#E2E8F0", fontWeight:500, lineHeight:1.4 }}>{selectedIncident.title}</div>
              </div>
              <button onClick={()=>{ setSelectedIncident(null); setIncidentDetail(null); setGeneratedRemediation(null); }}
                style={{ background:"none", border:"1px solid rgba(79,195,247,0.2)", color:"#546E7A", cursor:"pointer", padding:"6px 10px", borderRadius:4, fontSize:14, marginLeft:12, flexShrink:0 }}>&#x2715;</button>
            </div>

            {/* Status Action Buttons */}
            {(() => {
              const st = incidentDetail?.status || selectedIncident.status;
              const btnStyle = (bg, border) => ({ padding:"8px 16px", background:bg, border:`1px solid ${border}`, borderRadius:4, color:"#fff", cursor:"pointer", fontSize:11, fontFamily:"monospace", letterSpacing:0.5 });
              return (
                <div style={{ display:"flex", gap:8, marginTop:12, flexWrap:"wrap" }}>
                  {st === "OPEN" && (
                    <button onClick={()=>updateIncidentStatus(selectedIncident.incident_id,"INVESTIGATING")} style={btnStyle("rgba(79,195,247,0.1)","rgba(79,195,247,0.4)")}>&#x2192; MARK INVESTIGATING</button>
                  )}
                  {st === "INVESTIGATING" && (<>
                    <button onClick={()=>updateIncidentStatus(selectedIncident.incident_id,"RESOLVED")} style={btnStyle("rgba(102,187,106,0.1)","rgba(102,187,106,0.4)")}>&#x2192; MARK RESOLVED</button>
                    <button onClick={()=>updateIncidentStatus(selectedIncident.incident_id,"CLOSED")} style={btnStyle("rgba(84,110,122,0.1)","rgba(84,110,122,0.4)")}>&#x2192; MARK CLOSED</button>
                  </>)}
                  {st === "RESOLVED" && (
                    <button onClick={()=>updateIncidentStatus(selectedIncident.incident_id,"CLOSED")} style={btnStyle("rgba(84,110,122,0.1)","rgba(84,110,122,0.4)")}>&#x2192; MARK CLOSED</button>
                  )}
                </div>
              );
            })()}
          </div>

          {drawerLoading ? (
            <div style={{ padding:40, textAlign:"center", color:"#546E7A", fontFamily:"monospace", fontSize:12 }}>Loading investigation data...</div>
          ) : (
            <div style={{ padding:"20px 24px", display:"flex", flexDirection:"column", gap:20 }}>

              {/* Section: Threat Details */}
              <div>
                <div style={{ fontSize:11, color:"#4FC3F7", fontFamily:"monospace", letterSpacing:1, marginBottom:10, textTransform:"uppercase" }}>Threat Details</div>
                <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:8 }}>
                  {[
                    ["Type", selectedIncident.title?.split(" ")[0] || "—"],
                    ["MITRE", (selectedIncident.mitre_techniques||[]).join(", ") || "—"],
                    ["Affected IPs", (incidentDetail?.affected_ips||selectedIncident.affected_ips||[]).join(", ") || "—"],
                    ["Detected", new Date(selectedIncident.created_at).toLocaleString()],
                  ].map(([k,v]) => (
                    <div key={k} style={{ background:"rgba(79,195,247,0.03)", border:"1px solid rgba(79,195,247,0.08)", borderRadius:4, padding:"8px 12px" }}>
                      <div style={{ fontSize:9, color:"#546E7A", fontFamily:"monospace", marginBottom:3, textTransform:"uppercase" }}>{k}</div>
                      <div style={{ fontSize:11, color:"#E2E8F0", fontFamily:"monospace", wordBreak:"break-all" }}>{v}</div>
                    </div>
                  ))}
                </div>
                {(selectedIncident.mitre_techniques||[]).map(m => {
                  const p = MITRE_PLAYBOOK[m];
                  return p ? (
                    <div key={m} style={{ marginTop:8, background:"rgba(255,215,64,0.04)", border:"1px solid rgba(255,215,64,0.15)", borderRadius:4, padding:"8px 12px" }}>
                      <div style={{ fontSize:9, color:"#FFD740", fontFamily:"monospace", marginBottom:3 }}>{m} — {p.name}</div>
                    </div>
                  ) : null;
                })}
              </div>

              {/* Section: AI Investigation Summary */}
              {(() => {
                const aiSummary = incidentDetail?.investigation_summary || selectedIncident?.investigation_summary;
                const isPending = !aiSummary || aiSummary.startsWith('⏸');
                const sev       = selectedIncident?.severity || 'MEDIUM';
                const sevColor  = sev==='CRITICAL'?'#FF5252':sev==='HIGH'?'#FF6D00':sev==='MEDIUM'?'#FFD740':'#78909C';
                const mitre     = (selectedIncident?.mitre_techniques||[])[0] || selectedIncident?.mitre_technique || '—';
                const score     = selectedIncident?.anomaly_score;
                const affIPs    = selectedIncident?.affected_ips || [];

                return (
                  <div>
                    {/* Header row */}
                    <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:12 }}>
                      <div style={{ fontSize:11, color:"#4FC3F7", fontFamily:"monospace",
                        letterSpacing:1, textTransform:"uppercase" }}>AI Investigation</div>
                      <div style={{ display:"flex", alignItems:"center", gap:6, marginLeft:"auto" }}>
                        <div style={{ width:6, height:6, borderRadius:"50%",
                          background: isPending ? "#FFD740" : "#00E676",
                          boxShadow: isPending ? "0 0 8px #FFD740" : "0 0 8px #00E676" }}/>
                        <span style={{ fontFamily:"monospace", fontSize:9,
                          color: isPending ? "#FFD740" : "#00E676", letterSpacing:1 }}>
                          {isPending ? "PENDING" : "COMPLETE"}
                        </span>
                      </div>
                    </div>

                    {isPending ? (
                      <div style={{ background:"rgba(255,215,64,0.04)", border:"1px solid rgba(255,215,64,0.2)",
                        borderRadius:8, padding:"16px", fontSize:11, color:"#90A4AE",
                        fontFamily:"monospace", lineHeight:1.8 }}>
                        <div style={{ color:"#FFD740", marginBottom:8, fontSize:10 }}>
                          ⏸ AI Investigation Paused
                        </div>
                        AI investigation was disabled when this alert arrived. Enable AI Investigation
                        and new alerts from this host will be fully analysed automatically.
                        {score != null && (
                          <div style={{ marginTop:10, color:"#607D8B", fontSize:10 }}>
                            Anomaly score logged: <span style={{ color:"#FFD740" }}>{score.toFixed(2)}</span>
                          </div>
                        )}
                      </div>
                    ) : (
                      <div style={{ display:"flex", flexDirection:"column", gap:10 }}>

                        {/* Verdict banner */}
                        <div style={{ background:`${sevColor}0D`, border:`1px solid ${sevColor}35`,
                          borderLeft:`3px solid ${sevColor}`, borderRadius:6, padding:"10px 14px",
                          display:"flex", alignItems:"center", gap:12, flexWrap:"wrap" }}>
                          <span style={{ fontFamily:"monospace", fontSize:10, color:sevColor,
                            letterSpacing:1, fontWeight:700 }}>{sev} THREAT</span>
                          {mitre !== '—' && (
                            <span style={{ fontFamily:"monospace", fontSize:9,
                              color:"#90CAF9", background:"rgba(144,202,249,0.1)",
                              border:"1px solid rgba(144,202,249,0.2)",
                              padding:"2px 8px", borderRadius:3 }}>{mitre}</span>
                          )}
                          {score != null && (
                            <span style={{ fontFamily:"monospace", fontSize:9, color:"#607D8B",
                              marginLeft:"auto" }}>
                              anomaly <span style={{ color:sevColor }}>{score.toFixed(2)}</span>
                            </span>
                          )}
                        </div>

                        {/* Affected IPs */}
                        {affIPs.length > 0 && (
                          <div style={{ display:"flex", gap:8, flexWrap:"wrap" }}>
                            {affIPs.map(ip => (
                              <span key={ip} style={{ fontFamily:"monospace", fontSize:10,
                                color:"#FF8A65", background:"rgba(255,138,101,0.08)",
                                border:"1px solid rgba(255,138,101,0.2)",
                                padding:"3px 10px", borderRadius:4 }}>🎯 {ip}</span>
                            ))}
                          </div>
                        )}

                        {/* Analysis text — strip any REMEDIATION: block (old data) */}
                        <div style={{ background:"rgba(5,13,21,0.7)",
                          border:"1px solid rgba(79,195,247,0.08)", borderRadius:6,
                          padding:"14px 16px", fontSize:11, color:"#B0BEC5",
                          lineHeight:1.9, fontFamily:"'DM Sans',sans-serif",
                          whiteSpace:"pre-wrap", maxHeight:240, overflowY:"auto" }}>
                          {aiSummary.replace(/REMEDIATION:[\s\S]*/i, '').trim() || aiSummary}
                        </div>

                        {/* Model badge */}
                        <div style={{ display:"flex", alignItems:"center", gap:8,
                          justifyContent:"flex-end" }}>
                          <span style={{ fontFamily:"monospace", fontSize:9,
                            color:"rgba(79,195,247,0.35)", letterSpacing:1 }}>
                            🤖 GPT-4o mini · ~$0.0003/call
                          </span>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })()}

              {/* Section: Remediation — always a separate technical playbook, never from investigation_summary */}
              <div>
                <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", marginBottom:10 }}>
                  <div style={{ fontSize:11, color:"#4FC3F7", fontFamily:"monospace", letterSpacing:1, textTransform:"uppercase" }}>
                    Technical Playbook
                    <span style={{ marginLeft:8, fontSize:9, color:"#546E7A", fontWeight:"normal", letterSpacing:0, textTransform:"none" }}>
                      {generatedRemediation ? "AI-generated" : "static · click to generate AI version"}
                    </span>
                  </div>
                  <button onClick={()=>{ setGeneratedRemediation(null); generateAIRemediation(); }}
                    disabled={remediationLoading}
                    style={{ padding:"4px 12px", background:"rgba(79,195,247,0.08)",
                      border:"1px solid rgba(79,195,247,0.3)", borderRadius:4,
                      color:"#4FC3F7", cursor:remediationLoading?"wait":"pointer",
                      fontSize:10, fontFamily:"monospace", letterSpacing:0.5, flexShrink:0 }}>
                    {remediationLoading ? "⟳ Generating…" : "⚡ Generate AI Playbook"}
                  </button>
                </div>

                {generatedRemediation ? (
                  /* AI-generated technical playbook (markdown-style) */
                  <div style={{ background:"rgba(0,20,10,0.6)", border:"1px solid rgba(102,187,106,0.25)",
                    borderRadius:6, padding:"16px 18px", fontSize:11, color:"#CBD5E1",
                    lineHeight:1.85, fontFamily:"monospace", whiteSpace:"pre-wrap" }}>
                    {generatedRemediation}
                  </div>
                ) : (() => {
                  /* Static MITRE playbook while no AI version exists yet */
                  const mitre = (selectedIncident.mitre_techniques||[])[0];
                  const playbook = mitre ? (MITRE_PLAYBOOK[mitre] || MITRE_FALLBACK) : MITRE_FALLBACK;
                  const isGeneric = !mitre || !MITRE_PLAYBOOK[mitre];
                  return (
                    <div style={{ background:"rgba(102,187,106,0.03)", border:"1px solid rgba(102,187,106,0.12)",
                      borderRadius:6, padding:"14px 16px" }}>
                      {isGeneric && (
                        <div style={{ fontSize:9, color:"#FFD740", fontFamily:"monospace",
                          marginBottom:10, display:"flex", alignItems:"center", gap:6 }}>
                          ⚠ Generic playbook — click "Generate AI Playbook" for commands specific to this incident
                        </div>
                      )}
                      {playbook.steps.map((s,i) => (
                        <div key={i} style={{ fontSize:11, color:"#90A4AE", lineHeight:1.75,
                          marginBottom:5, fontFamily:"monospace", display:"flex", gap:8 }}>
                          <span style={{ color:"#4FC3F7", flexShrink:0 }}>›</span>{s}
                        </div>
                      ))}
                    </div>
                  );
                })()}
              </div>

              {/* Section: ChromaDB Threat Signatures */}
              <div>
                <div style={{ fontSize:11, color:"#4FC3F7", fontFamily:"monospace", letterSpacing:1, marginBottom:10, textTransform:"uppercase" }}>
                  Threat Signatures — ChromaDB
                  <span style={{ marginLeft:8, fontSize:9, color:"#546E7A", fontWeight:"normal", letterSpacing:0 }}>cosine similarity matches</span>
                </div>
                {threatSigs.length > 0 ? (
                  <div style={{ display:"flex", flexDirection:"column", gap:8 }}>
                    {threatSigs.slice(0,5).map((sig, i) => {
                      const raw       = typeof sig === "string" ? {} : sig;
                      const doc       = raw.document || raw.text || String(sig);
                      const meta      = raw.metadata || {};
                      const mitre     = meta.mitre || "—";
                      const severity  = meta.severity || "UNKNOWN";
                      const simScore  = raw.similarity != null ? raw.similarity : null;
                      const simPct    = simScore != null ? (simScore * 100).toFixed(1) : null;
                      const sevColor  = severity === "CRITICAL" ? "#FF5252"
                                      : severity === "HIGH"     ? "#FF6D00"
                                      : severity === "MEDIUM"   ? "#FFD740"
                                      : "#78909C";
                      // bar width — scores typically 0.30–0.70 range; normalise to 0–100 visually
                      const barWidth  = simScore != null ? Math.min(100, (simScore / 0.8) * 100) : 0;
                      return (
                        <div key={i} style={{
                          background:"rgba(5,12,22,0.8)", border:`1px solid ${sevColor}22`,
                          borderLeft:`3px solid ${sevColor}`, borderRadius:6, padding:"12px 14px",
                        }}>
                          {/* Header row */}
                          <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:8, flexWrap:"wrap" }}>
                            <span style={{ fontFamily:"monospace", fontSize:9, color:"#4FC3F7",
                              background:"rgba(79,195,247,0.1)", padding:"1px 7px", borderRadius:3 }}>#{i+1}</span>
                            <span style={{ fontFamily:"monospace", fontSize:9, color:sevColor,
                              background:`${sevColor}18`, border:`1px solid ${sevColor}30`,
                              padding:"1px 8px", borderRadius:3, letterSpacing:0.5 }}>{severity}</span>
                            <span style={{ fontFamily:"monospace", fontSize:9, color:"#90CAF9",
                              background:"rgba(144,202,249,0.1)", border:"1px solid rgba(144,202,249,0.2)",
                              padding:"1px 8px", borderRadius:3 }}>{mitre}</span>
                            {simPct && (
                              <span style={{ marginLeft:"auto", fontFamily:"monospace", fontSize:9,
                                color:"#4FC3F7" }}>sim {simPct}%</span>
                            )}
                          </div>
                          {/* Similarity bar */}
                          {simPct && (
                            <div style={{ height:3, background:"rgba(255,255,255,0.06)", borderRadius:2, marginBottom:9 }}>
                              <div style={{ height:"100%", width:`${barWidth}%`, borderRadius:2,
                                background:`linear-gradient(90deg,${sevColor}80,${sevColor})`,
                                transition:"width 0.5s ease" }}/>
                            </div>
                          )}
                          {/* Document text */}
                          <div style={{ fontSize:11, color:"#90A4AE", lineHeight:1.7, fontFamily:"'DM Sans',sans-serif" }}>
                            {doc}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                ) : (
                  <div style={{ fontSize:11, color:"#546E7A", fontFamily:"monospace", fontStyle:"italic",
                    padding:"12px 14px", background:"rgba(5,12,22,0.6)", borderRadius:6,
                    border:"1px solid rgba(79,195,247,0.06)" }}>
                    No matching signatures found in ChromaDB knowledge base.
                  </div>
                )}
              </div>

              {/* Section: Notes */}
              <div>
                <div style={{ fontSize:11, color:"#4FC3F7", fontFamily:"monospace", letterSpacing:1, marginBottom:10, textTransform:"uppercase" }}>Resolution Notes</div>
                <textarea
                  value={incidentNotes}
                  onChange={e=>setIncidentNotes(e.target.value)}
                  placeholder="Document what you did — e.g. Blocked IP on firewall rule #47, isolated host 10.0.1.45, confirmed clean..."
                  style={{ width:"100%", minHeight:90, background:"rgba(5,13,21,0.8)", border:"1px solid rgba(79,195,247,0.2)", borderRadius:6, padding:"10px 14px", color:"#E2E8F0", fontSize:11, fontFamily:"monospace", outline:"none", resize:"vertical", boxSizing:"border-box" }}
                />
                {incidentDetail?.notes && incidentDetail.notes !== incidentNotes && (
                  <div style={{ fontSize:10, color:"#546E7A", fontFamily:"monospace", marginTop:4 }}>Previously saved: {incidentDetail.notes.substring(0,80)}...</div>
                )}
              </div>

            </div>
          )}
        </div>
      )}

        {/* ── AUTOMATION TAB ── */}
        {tab==="automation" && (() => {
          const N8N = n8nUrl.replace(/\/$/, "");

          const WORKFLOWS = [
            {
              id: "soar",
              name: "Critical Alert SOAR",
              file: "01_critical_alert_soar.json",
              trigger: "Event-driven",
              schedule: "Fires on every CRITICAL/HIGH alert",
              desc: "Enriches alerts via AbuseIPDB + host intel, auto-blocks confirmed threats, posts to Slack.",
              manual: false,
              color: "#E53935",
              icon: "🚨",
            },
            {
              id: "daily",
              name: "Daily SOC Report",
              file: "02_daily_soc_report.json",
              trigger: "Schedule",
              schedule: "7AM Mon–Fri",
              desc: "Fetches 24h metrics, generates AI analyst report, posts 5-section summary to Slack.",
              manual: true,
              webhook: `${N8N}/webhook/run-daily-report`,
              color: "#4FC3F7",
              icon: "📊",
            },
            {
              id: "cve",
              name: "CVE Intel Pipeline",
              file: "03_cve_intel_pipeline.json",
              trigger: "Event-driven",
              schedule: "Fires on incoming CVE webhook",
              desc: "Receives CVE data, runs AI risk analysis, posts severity-rated alert to Slack.",
              manual: false,
              color: "#FF6D00",
              icon: "🔍",
            },
            {
              id: "sla",
              name: "SLA Watchdog",
              file: "04_sla_watchdog.json",
              trigger: "Schedule",
              schedule: "Every 15 minutes",
              desc: "Checks open incidents against SLA thresholds (CRITICAL=30m, HIGH=2h), alerts on breach.",
              manual: true,
              webhook: `${N8N}/webhook/run-sla-check`,
              color: "#FFD740",
              icon: "⏱",
            },
            {
              id: "board",
              name: "Weekly Board Report",
              file: "05_weekly_board_report.json",
              trigger: "Schedule",
              schedule: "Monday 8AM",
              desc: "Aggregates weekly metrics, generates AI executive report with 5 sections, posts to Slack.",
              manual: true,
              webhook: `${N8N}/webhook/run-board-report`,
              color: "#00E676",
              icon: "📋",
            },
          ];

          async function triggerWorkflow(wf) {
            setWfStatus(s => ({ ...s, [wf.id]: "running" }));
            try {
              const r = await fetch(`${API}/api/v1/workflows/trigger/${wf.id}`, {
                method: "POST",
                headers: { Authorization: `Bearer ${token}` },
              });
              if (r.ok) {
                localStorage.setItem(`cs_wf_last_${wf.id}`, new Date().toISOString());
                setWfStatus(s => ({ ...s, [wf.id]: "done" }));
                setTimeout(() => setWfStatus(s => ({ ...s, [wf.id]: "idle" })), 4000);
              } else {
                const err = await r.json().catch(() => ({}));
                setWfStatus(s => ({ ...s, [wf.id]: "error", [`${wf.id}_msg`]: err.detail || "Failed" }));
                setTimeout(() => setWfStatus(s => ({ ...s, [wf.id]: "idle" })), 5000);
              }
            } catch {
              setWfStatus(s => ({ ...s, [wf.id]: "error" }));
              setTimeout(() => setWfStatus(s => ({ ...s, [wf.id]: "idle" })), 5000);
            }
          }

          return (
            <div className="tab-content" style={{ padding:"20px 24px", display:"flex", flexDirection:"column", gap:20 }}>
              {/* Header + n8n URL config */}
              <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", flexWrap:"wrap", gap:12 }}>
                <div>
                  <div style={{ fontFamily:"'Rajdhani',sans-serif", fontSize:18, fontWeight:700, color:"#E2E8F0", letterSpacing:2 }}>AUTOMATION WORKFLOWS</div>
                  <div style={{ fontFamily:"monospace", fontSize:10, color:"#546E7A", marginTop:2 }}>5 n8n workflows · Slack Bot API · Multi-provider LLM</div>
                </div>
                <div style={{ display:"flex", alignItems:"center", gap:8 }}>
                  <span style={{ fontFamily:"monospace", fontSize:10, color:"#546E7A" }}>n8n URL:</span>
                  <input
                    value={n8nUrl}
                    onChange={e => { setN8nUrl(e.target.value); localStorage.setItem("cs_n8n_url", e.target.value); }}
                    style={{ fontFamily:"monospace", fontSize:11, background:"rgba(8,18,30,0.8)", border:"1px solid rgba(79,195,247,0.2)", borderRadius:4, padding:"4px 10px", color:"#90CAF9", width:220, outline:"none" }}
                    placeholder="http://localhost:5678"
                  />
                </div>
              </div>

              {/* Workflow cards grid */}
              <div style={{ display:"grid", gridTemplateColumns:"repeat(auto-fill,minmax(380px,1fr))", gap:16 }}>
                {WORKFLOWS.map(wf => {
                  const st = wfStatus[wf.id] || "idle";
                  const lastRun = localStorage.getItem(`cs_wf_last_${wf.id}`);
                  const btnColor = st === "done" ? "#00E676" : st === "error" ? "#E53935" : st === "running" ? "#FFD740" : wf.color;
                  const errMsg = wfStatus[`${wf.id}_msg`];
                  const btnLabel = st === "running" ? "RUNNING..." : st === "done" ? "✓ TRIGGERED" : st === "error" ? `✗ ${errMsg || "FAILED"}` : "▶ RUN NOW";

                  return (
                    <div key={wf.id} className="dash-panel" style={{
                      background:"rgba(7,16,27,0.85)", backdropFilter:"blur(12px)",
                      border:`1px solid ${wf.color}22`, borderRadius:12, padding:0, overflow:"hidden",
                      transition:"border-color 0.2s",
                    }}
                    onMouseEnter={e => e.currentTarget.style.borderColor = `${wf.color}55`}
                    onMouseLeave={e => e.currentTarget.style.borderColor = `${wf.color}22`}
                    >
                      {/* Card header */}
                      <div style={{ padding:"14px 18px 12px", borderBottom:`1px solid ${wf.color}18`, display:"flex", alignItems:"flex-start", justifyContent:"space-between", gap:12 }}>
                        <div style={{ display:"flex", alignItems:"center", gap:10 }}>
                          <span style={{ fontSize:22 }}>{wf.icon}</span>
                          <div>
                            <div style={{ fontFamily:"'Share Tech Mono',monospace", fontSize:12, color:"#E2E8F0", letterSpacing:1 }}>{wf.name}</div>
                            <div style={{ fontFamily:"monospace", fontSize:9, color:wf.color, marginTop:2, letterSpacing:1 }}>{wf.file}</div>
                          </div>
                        </div>
                        <span style={{ fontFamily:"monospace", fontSize:9, color:wf.color, background:`${wf.color}18`, border:`1px solid ${wf.color}30`, borderRadius:4, padding:"2px 8px", whiteSpace:"nowrap" }}>
                          {wf.trigger}
                        </span>
                      </div>

                      {/* Card body */}
                      <div style={{ padding:"12px 18px 16px", display:"flex", flexDirection:"column", gap:10 }}>
                        <div style={{ fontFamily:"monospace", fontSize:10, color:"#90A4AE", lineHeight:1.7 }}>{wf.desc}</div>
                        <div style={{ display:"flex", alignItems:"center", gap:6 }}>
                          <span style={{ fontSize:9, color:"#38516A", fontFamily:"monospace", letterSpacing:1 }}>SCHEDULE:</span>
                          <span style={{ fontFamily:"monospace", fontSize:9, color:"#546E7A" }}>{wf.schedule}</span>
                        </div>
                        {lastRun && (
                          <div style={{ display:"flex", alignItems:"center", gap:6 }}>
                            <span style={{ fontSize:9, color:"#38516A", fontFamily:"monospace", letterSpacing:1 }}>LAST RUN:</span>
                            <span style={{ fontFamily:"monospace", fontSize:9, color:"#546E7A" }}>{ago(lastRun)}</span>
                          </div>
                        )}

                        {/* Action row */}
                        <div style={{ display:"flex", gap:8, marginTop:4 }}>
                          {wf.manual ? (
                            <button
                              onClick={() => triggerWorkflow(wf)}
                              disabled={st === "running"}
                              style={{
                                fontFamily:"'Share Tech Mono',monospace", fontSize:10, letterSpacing:1,
                                padding:"6px 18px", borderRadius:4, cursor: st === "running" ? "not-allowed" : "pointer",
                                background:`${btnColor}18`, border:`1px solid ${btnColor}50`, color:btnColor,
                                transition:"all 0.2s", opacity: st === "running" ? 0.7 : 1,
                              }}
                              onMouseEnter={e => { if (st !== "running") e.currentTarget.style.background = `${btnColor}30`; }}
                              onMouseLeave={e => { e.currentTarget.style.background = `${btnColor}18`; }}
                            >{btnLabel}</button>
                          ) : (
                            <span style={{ fontFamily:"monospace", fontSize:9, color:"#38516A", padding:"6px 0", letterSpacing:1 }}>AUTO-TRIGGERED · NO MANUAL RUN</span>
                          )}
                          <span style={{ fontFamily:"monospace", fontSize:9, color:"#263238", alignSelf:"center", marginLeft:"auto" }}>
                            {wf.manual ? `POST ${wf.webhook.replace(N8N, "")}` : ""}
                          </span>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* ── APPROVAL QUEUE ── */}
              <div>
                <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:12 }}>
                  <span style={{ fontFamily:"'Share Tech Mono',monospace", fontSize:10, color:"#4FC3F7", letterSpacing:2 }}>PENDING APPROVAL</span>
                  {pendingReports.length > 0 && (
                    <span style={{ background:"#E53935", color:"#fff", fontSize:9, fontWeight:700, padding:"2px 7px", borderRadius:8 }}>{pendingReports.length}</span>
                  )}
                  <span style={{ fontFamily:"monospace", fontSize:9, color:"#38516A", marginLeft:"auto" }}>auto-refreshes every 20s</span>
                </div>

                {pendingReports.length === 0 ? (
                  <div style={{ padding:"24px", background:"rgba(7,16,27,0.6)", border:"1px solid rgba(79,195,247,0.07)", borderRadius:10, textAlign:"center", fontFamily:"monospace", fontSize:10, color:"#38516A" }}>
                    No reports pending approval — all clear
                  </div>
                ) : (
                  <div style={{ display:"flex", flexDirection:"column", gap:12 }}>
                    {pendingReports.map(rep => {
                      const WORKFLOW_META = {
                        daily_soc:    { label:"Daily SOC Report",    color:"#4FC3F7", icon:"📊" },
                        sla_watchdog: { label:"SLA Watchdog Alert",  color:"#FFD740", icon:"⏱" },
                        board_report: { label:"Weekly Board Report", color:"#00E676", icon:"📋" },
                      };
                      const meta = WORKFLOW_META[rep.workflow] || { label: rep.workflow, color:"#90A4AE", icon:"📄" };
                      const act = reportAction[rep.report_id] || "idle";

                      async function handleAction(action) {
                        setReportAction(s => ({ ...s, [rep.report_id]: action === "approve" ? "approving" : "denying" }));
                        try {
                          const r = await fetch(`${API}/api/v1/reports/${rep.report_id}/${action}`, {
                            method: "POST", headers: { Authorization: `Bearer ${token}` }
                          });
                          if (r.ok) {
                            setReportAction(s => ({ ...s, [rep.report_id]: "done" }));
                            setTimeout(() => { fetchPendingReports(); setReportAction(s => { const n={...s}; delete n[rep.report_id]; return n; }); }, 1200);
                          } else {
                            setReportAction(s => ({ ...s, [rep.report_id]: "error" }));
                            setTimeout(() => setReportAction(s => ({ ...s, [rep.report_id]: "idle" })), 3000);
                          }
                        } catch {
                          setReportAction(s => ({ ...s, [rep.report_id]: "error" }));
                          setTimeout(() => setReportAction(s => ({ ...s, [rep.report_id]: "idle" })), 3000);
                        }
                      }

                      return (
                        <div key={rep.report_id} className="dash-panel" style={{
                          background:"rgba(7,16,27,0.85)", border:`1px solid ${meta.color}30`,
                          borderRadius:10, overflow:"hidden",
                          animation: act === "done" ? "none" : undefined,
                          opacity: act === "done" ? 0.4 : 1, transition:"opacity 0.4s",
                        }}>
                          {/* Header row */}
                          <div style={{ padding:"12px 18px", borderBottom:`1px solid ${meta.color}15`, display:"flex", alignItems:"center", gap:10, background:`${meta.color}08` }}>
                            <span style={{ fontSize:18 }}>{meta.icon}</span>
                            <div style={{ flex:1, minWidth:0 }}>
                              <div style={{ fontFamily:"'Share Tech Mono',monospace", fontSize:11, color:"#E2E8F0", letterSpacing:1, whiteSpace:"nowrap", overflow:"hidden", textOverflow:"ellipsis" }}>{rep.title}</div>
                              <div style={{ fontFamily:"monospace", fontSize:9, color:"#546E7A", marginTop:2 }}>
                                <span style={{ color:meta.color }}>{meta.label}</span>
                                {"  ·  "}received {ago(rep.created_at)}
                                {"  ·  "}ID: <span style={{ color:"#38516A" }}>{rep.report_id}</span>
                              </div>
                            </div>
                            {/* Pulsing pending dot */}
                            {act === "idle" && <ThreatDot color={meta.color} size={6}/>}
                          </div>

                          {/* Action row */}
                          <div style={{ padding:"10px 18px", display:"flex", alignItems:"center", gap:10 }}>
                            <span style={{ fontFamily:"monospace", fontSize:9, color:"#546E7A", flex:1 }}>
                              {act === "approving" ? "Sending to Slack..." : act === "denying" ? "Discarding..." : act === "done" ? "Done ✓" : act === "error" ? "Action failed — try again" : "Review and approve to send to Slack, or deny to discard."}
                            </span>
                            <button
                              onClick={() => handleAction("approve")}
                              disabled={act !== "idle"}
                              style={{
                                fontFamily:"'Share Tech Mono',monospace", fontSize:10, letterSpacing:1,
                                padding:"6px 20px", borderRadius:4, cursor: act !== "idle" ? "not-allowed" : "pointer",
                                background: act === "approving" ? "rgba(0,230,118,0.08)" : "rgba(0,230,118,0.12)",
                                border:"1px solid rgba(0,230,118,0.4)", color:"#00E676",
                                opacity: act !== "idle" ? 0.5 : 1, transition:"all 0.15s",
                              }}
                            >✓ APPROVE & SEND</button>
                            <button
                              onClick={() => handleAction("deny")}
                              disabled={act !== "idle"}
                              style={{
                                fontFamily:"'Share Tech Mono',monospace", fontSize:10, letterSpacing:1,
                                padding:"6px 16px", borderRadius:4, cursor: act !== "idle" ? "not-allowed" : "pointer",
                                background:"rgba(229,57,53,0.08)", border:"1px solid rgba(229,57,53,0.3)", color:"#EF5350",
                                opacity: act !== "idle" ? 0.5 : 1, transition:"all 0.15s",
                              }}
                            >✗ DENY</button>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>

              {/* Info bar */}
              <div style={{ padding:"12px 16px", background:"rgba(79,195,247,0.03)", border:"1px solid rgba(79,195,247,0.08)", borderRadius:8, fontFamily:"monospace", fontSize:10, color:"#38516A", lineHeight:1.8 }}>
                <span style={{ color:"#4FC3F7" }}>HOW IT WORKS</span>
                {"  ·  "}Scheduled workflows fire automatically. Manual workflows need n8n running at the URL above.
                {"  ·  "}Results are posted to your <span style={{ color:"#4FC3F7" }}>SLACK_CHANNEL_ID</span>.
                {"  ·  "}AI calls use <span style={{ color:"#4FC3F7" }}>{"{"}LLM_PROVIDER{"}"}</span> from your <span style={{ color:"#4FC3F7" }}>.env</span>.
              </div>
            </div>
          );
        })()}

      {/* STATUS BAR */}
      <div style={{
        height:28, background:"rgba(5,13,21,0.95)", borderTop:"1px solid rgba(79,195,247,0.08)",
        display:"flex", alignItems:"center", justifyContent:"space-between", padding:"0 16px",
        fontFamily:"monospace", fontSize:10, color:"#546E7A",
      }}>
        <div style={{ display:"flex", gap:20 }}>
          {[["DPI","ACTIVE","#00E676"],["RLM","ACTIVE","#00E676"],["MCP","ACTIVE","#00E676"],["n8n","ACTIVE","#00E676"],["KAFKA","ACTIVE","#00E676"]].map(([s,st,c]) => (
            <span key={s}><span style={{color:"#38516A"}}>{s}: </span><span style={{color:c}}>{st}</span></span>
          ))}
        </div>
        <div>CyberSentinel AI v1.3.0 · Capstone 2026 · {authed&&token?"Authenticated":""}</div>
        <div style={{ display:"flex", gap:16 }}>
          <span>Alerts: <span style={{color:"#4FC3F7"}}>{apiLive?(data.alerts?.length??0):8}</span></span>
          <span>Incidents: <span style={{color:"#FFD740"}}>{apiLive?(data.incidents?.length??0):4}</span></span>
          <span>Campaigns: <span style={{color:"#EF9A9A"}}>{apiLive?campaigns.length:MOCK.campaigns.length}</span></span>
          <span>Risk: <span style={{color:riskColor}}>{riskPct}%</span></span>
        </div>
      </div>
      </div>{/* end inner zIndex wrapper */}
    </div>
  );
}
