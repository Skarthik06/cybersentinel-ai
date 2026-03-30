import { useState, useEffect, useCallback, useRef } from "react";
import { LineChart, Line, AreaChart, Area, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, RadarChart, Radar, PolarGrid, PolarAngleAxis } from "recharts";

const API = "http://localhost:8080";

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
  return (
    <div style={{
      background:"rgba(13,27,42,0.9)", border:`1px solid ${color}30`,
      borderRadius:10, padding:"20px 22px",
      boxShadow:`inset 0 1px 0 ${color}15, 0 4px 20px rgba(0,0,0,0.3)`,
    }}>
      <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start", marginBottom:12 }}>
        <div style={{ display:"flex", alignItems:"center", gap:6 }}>
          {live && <ThreatDot color={color} size={5}/>}
          <span style={{ fontFamily:"'Share Tech Mono',monospace", fontSize:9, color:"#546E7A", letterSpacing:2, textTransform:"uppercase" }}>{label}</span>
        </div>
        <span style={{ fontSize:18, opacity:0.6 }}>{icon}</span>
      </div>
      <div style={{ fontFamily:"'Share Tech Mono',monospace", fontSize:34, fontWeight:700, color, lineHeight:1, marginBottom:4 }}>{value}</div>
      {sub && <div style={{ fontSize:11, color:"#546E7A" }}>{sub}</div>}
    </div>
  );
}

function Panel({ title, badge, children, style={} }) {
  return (
    <div style={{
      background:"rgba(13,27,42,0.85)", border:"1px solid rgba(79,195,247,0.1)",
      borderRadius:10, overflow:"hidden", display:"flex", flexDirection:"column", ...style
    }}>
      <div style={{
        padding:"12px 18px", borderBottom:"1px solid rgba(79,195,247,0.08)",
        display:"flex", alignItems:"center", justifyContent:"space-between",
        background:"rgba(79,195,247,0.03)",
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
  const [data, setData] = useState({ dash:MOCK.dashboard, alerts:[], incidents:[] });
  const [apiLive, setApiLive] = useState(false);
  const [timeData, setTimeData] = useState(genTimeData);
  const [investigationsPaused, setInvestigationsPaused] = useState(false);
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
  const [incidentDetail, setIncidentDetail] = useState(null);
  const [threatSigs, setThreatSigs] = useState([]);
  const [drawerLoading, setDrawerLoading] = useState(false);
  const [incidentNotes, setIncidentNotes] = useState('');
  const [remediationLoading, setRemediationLoading] = useState(false);
  const [generatedRemediation, setGeneratedRemediation] = useState(null);
  const [blockRecs, setBlockRecs] = useState([]);
  const [blockAction, setBlockAction] = useState({});

  // Live clock
  useEffect(() => { const t = setInterval(()=>setTick(x=>x+1), 1000); return ()=>clearInterval(t); }, []);

  const fetchData = useCallback(async (tok) => {
    const t = tok || token;
    if (!t) return;
    const h = { Authorization:`Bearer ${t}` };
    try {
      const [d, a, i, ctrl] = await Promise.all([
        fetch(`${API}/api/v1/dashboard`, {headers:h}).then(r=>r.json()),
        fetch(`${API}/api/v1/alerts?limit=20`, {headers:h}).then(r=>r.json()),
        fetch(`${API}/api/v1/incidents`, {headers:h}).then(r=>r.json()),
        fetch(`${API}/api/v1/control`, {headers:h}).then(r=>r.json()).catch(()=>({})),
      ]);
      // When API is live, always use real data — never fall back to MOCK
      setData({
        dash: d,
        alerts: Array.isArray(a) ? a : [],
        incidents: Array.isArray(i) ? i : [],
      });
      // Build time chart from real data (zeros if no data yet — not random)
      setTimeData(buildTimeData(d.alerts_by_hour));
      if (ctrl.investigations_paused !== undefined) setInvestigationsPaused(ctrl.investigations_paused);
      setApiLive(true);
    } catch { setApiLive(false); }
  }, [token]);

  useEffect(() => { if (authed) { fetchData(); const t = setInterval(()=>fetchData(), 30000); return ()=>clearInterval(t); } }, [authed, fetchData]);

  const fetchBlockRecs = useCallback(async () => {
    if (!token) return;
    try {
      const r = await fetch(`${API}/api/v1/block-recommendations`, { headers:{ Authorization:`Bearer ${token}` } });
      if (r.ok) setBlockRecs(await r.json());
    } catch {}
  }, [token]);

  useEffect(() => { if (authed) { fetchBlockRecs(); const t = setInterval(()=>fetchBlockRecs(), 30000); return ()=>clearInterval(t); } }, [authed, fetchBlockRecs]);

  async function login() {
    setLoading(true); setLoginError("");
    try {
      const r = await fetch(`${API}/auth/token`, { method:"POST", headers:{"Content-Type":"application/x-www-form-urlencoded"}, body:`username=${loginUser}&password=${loginPass}` });
      if (r.ok) { const j = await r.json(); setToken(j.access_token); setAuthed(true); fetchData(j.access_token); }
      else { setLoginError("Invalid credentials. Check username and password."); }
    } catch { setLoginError("API offline — ensure all containers are running."); }
    setLoading(false);
  }

  async function toggleInvestigations() {
    const newState = !investigationsPaused;
    try {
      await fetch(`${API}/api/v1/control`, {
        method: "POST",
        headers: { Authorization:`Bearer ${token}`, "Content-Type":"application/json" },
        body: JSON.stringify({ investigations_paused: newState }),
      });
      setInvestigationsPaused(newState);
    } catch { /* offline — toggle locally for visual feedback */ setInvestigationsPaused(newState); }
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
        fetch(`${API}/api/v1/incidents`, { headers: h }).then(r => r.json()),
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

  // ── Login screen ──────────────────────────────────────────────────────
  if (!authed) return (
    <div style={{ minHeight:"100vh", background:"#050D15", display:"flex", alignItems:"center", justifyContent:"center", fontFamily:"'Share Tech Mono',monospace" }}>
      <style>{`@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@700&display=swap'); @keyframes ping{0%{transform:scale(1);opacity:0.6}75%,100%{transform:scale(2.5);opacity:0}} * { box-sizing:border-box; }`}</style>
      <div style={{ width:420, background:"rgba(13,27,42,0.95)", border:"1px solid rgba(79,195,247,0.2)", borderRadius:12, overflow:"hidden", boxShadow:"0 0 80px rgba(21,101,192,0.2)" }}>
        <div style={{ background:"rgba(79,195,247,0.05)", padding:"24px 32px", borderBottom:"1px solid rgba(79,195,247,0.1)", textAlign:"center" }}>
          <div style={{ fontSize:40, marginBottom:8 }}>🛡️</div>
          <div style={{ fontFamily:"'Rajdhani',sans-serif", fontSize:24, fontWeight:700, color:"#E2E8F0", letterSpacing:3 }}>CYBERSENTINEL AI</div>
          <div style={{ fontSize:10, color:"#546E7A", letterSpacing:3, marginTop:4 }}>SOC COMMAND CENTER</div>
        </div>
        <div style={{ padding:32 }}>
          {["Username","Password"].map((label,i) => (
            <div key={label} style={{ marginBottom:16 }}>
              <div style={{ fontSize:9, color:"#546E7A", letterSpacing:2, marginBottom:6 }}>{label.toUpperCase()}</div>
              <input type={i===1?"password":"text"} value={i===0?loginUser:loginPass}
                onChange={e => i===0 ? setLoginUser(e.target.value) : setLoginPass(e.target.value)}
                onKeyDown={e => e.key==="Enter" && login()}
                style={{ width:"100%", background:"rgba(5,13,21,0.8)", border:"1px solid rgba(79,195,247,0.2)", borderRadius:6, padding:"10px 14px", color:"#E2E8F0", fontFamily:"'Share Tech Mono',monospace", fontSize:13, outline:"none" }}
              />
            </div>
          ))}
          {loginError && <div style={{ fontSize:11, color:"#FF6D00", marginBottom:16 }}>{loginError}</div>}
          <button onClick={login} disabled={loading} style={{
            width:"100%", padding:"12px", background:"#1565C0", border:"none", borderRadius:6,
            color:"#fff", fontFamily:"'Share Tech Mono',monospace", fontSize:13, letterSpacing:1,
            cursor:"pointer", transition:"background 0.2s",
          }}
          onMouseEnter={e=>e.target.style.background="#1976D2"} onMouseLeave={e=>e.target.style.background="#1565C0"}
          >{loading?"AUTHENTICATING...":"▶ ACCESS PLATFORM"}</button>
          <div style={{ textAlign:"center", marginTop:16, fontSize:10, color:"#546E7A" }}>Default credentials: admin / cybersentinel2025</div>
        </div>
      </div>
    </div>
  );

  // ── Main dashboard ────────────────────────────────────────────────────
  return (
    <div style={{ minHeight:"100vh", background:"#050D15", color:"#E2E8F0", display:"flex", flexDirection:"column" }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@700&family=DM+Sans:wght@400;500&display=swap');
        @keyframes ping{0%{transform:scale(1);opacity:0.6}75%,100%{transform:scale(2.5);opacity:0}}
        @keyframes pulse{0%,100%{opacity:1}50%{opacity:0.4}}
        * { box-sizing:border-box; margin:0; padding:0; }
        ::-webkit-scrollbar{width:3px;background:#050D15}
        ::-webkit-scrollbar-thumb{background:#1565C0;border-radius:2px}
        input,button{font-family:'Share Tech Mono',monospace}
      `}</style>

      {/* TOP BAR */}
      <div style={{
        height:52, background:"rgba(5,13,21,0.95)", borderBottom:"1px solid rgba(79,195,247,0.12)",
        display:"flex", alignItems:"center", justifyContent:"space-between", padding:"0 20px",
        position:"sticky", top:0, zIndex:100,
      }}>
        <div style={{ display:"flex", alignItems:"center", gap:16 }}>
          <span style={{ fontSize:18 }}>🛡️</span>
          <span style={{ fontFamily:"'Rajdhani',sans-serif", fontSize:17, fontWeight:700, letterSpacing:2, color:"#E2E8F0" }}>CYBERSENTINEL</span>
          <span style={{ fontFamily:"monospace", fontSize:9, color:"#4FC3F7", background:"rgba(79,195,247,0.1)", padding:"2px 8px", borderRadius:3, letterSpacing:2 }}>SOC v1.0</span>
          <div style={{ display:"flex", gap:1, marginLeft:8 }}>
            {[["overview","◉ OVERVIEW"],["alerts","⚡ ALERTS"],["incidents","🚨 INCIDENTS"],["response","🛡️ RESPONSE"],["intel","🔍 THREAT INTEL"],["hosts","💻 HOSTS"]].map(([k,l]) => (
              <button key={k} onClick={()=>setTab(k)} style={{
                padding:"6px 14px", border:"none", background: tab===k?"rgba(79,195,247,0.12)":"transparent",
                color: tab===k?"#4FC3F7":"#546E7A", fontFamily:"'Share Tech Mono',monospace", fontSize:10,
                letterSpacing:1, cursor:"pointer", borderRadius:4,
                borderBottom: tab===k?"1px solid #4FC3F7":"1px solid transparent",
                transition:"all 0.15s", position:"relative",
              }}>
                {l}
                {k==="response" && blockRecs.length > 0 && (
                  <span style={{ marginLeft:6, background:"#E53935", color:"#fff", fontSize:9, fontWeight:700, padding:"1px 5px", borderRadius:8, verticalAlign:"middle" }}>{blockRecs.length}</span>
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
          {apiLive && (
            <button onClick={toggleInvestigations} style={{
              padding:"3px 10px", border:`1px solid ${investigationsPaused?"#546E7A":"#00E676"}`,
              borderRadius:4, background:investigationsPaused?"rgba(84,110,122,0.15)":"rgba(0,230,118,0.1)",
              color:investigationsPaused?"#546E7A":"#00E676",
              fontFamily:"'Share Tech Mono',monospace", fontSize:9, letterSpacing:1,
              cursor:"pointer", transition:"all 0.2s",
            }}>
              {investigationsPaused?"▶ AI INVEST OFF":"⏸ AI INVEST ON"}
            </button>
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

      {/* INVESTIGATIONS PAUSED BANNER */}
      {apiLive && investigationsPaused && (
        <div style={{
          background:"rgba(84,110,122,0.12)", borderBottom:"1px solid rgba(84,110,122,0.3)",
          padding:"6px 20px", display:"flex", alignItems:"center", gap:10,
          fontFamily:"'Share Tech Mono',monospace", fontSize:10, color:"#78909C", letterSpacing:1,
        }}>
          <span>⏸</span>
          <span>AI INVESTIGATIONS PAUSED — Alerts are being logged but no OpenAI API calls are being made. Click <strong style={{color:"#B0BEC5"}}>AI INVEST OFF</strong> in the top bar to resume.</span>
        </div>
      )}

      {/* CONTENT */}
      <div style={{ flex:1, padding:16, overflow:"auto" }}>

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
        {tab==="alerts" && (
          <Panel title="All Alerts" badge={`${(data.alerts||[]).length} results`} style={{ height:"calc(100vh - 100px)" }}>
            <div style={{ overflow:"auto" }}>
              <table style={{ width:"100%", borderCollapse:"collapse", fontFamily:"monospace", fontSize:12 }}>
                <thead>
                  <tr style={{ borderBottom:"1px solid rgba(79,195,247,0.15)" }}>
                    {["Severity","Type","Source IP","Destination","MITRE","Score","Time"].map(h => (
                      <th key={h} style={{ padding:"10px 14px", textAlign:"left", fontFamily:"'Share Tech Mono',monospace", fontSize:9, color:"#546E7A", letterSpacing:2, fontWeight:400 }}>{h.toUpperCase()}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {(data.alerts||[]).map((a,i) => (
                    <tr key={a.id||i} style={{ borderBottom:"1px solid rgba(255,255,255,0.03)", transition:"background 0.15s" }}
                      onMouseEnter={e=>e.currentTarget.style.background="rgba(79,195,247,0.04)"}
                      onMouseLeave={e=>e.currentTarget.style.background="transparent"}>
                      <td style={{ padding:"10px 14px" }}><SevBadge s={a.severity}/></td>
                      <td style={{ padding:"10px 14px", color:"#CBD5E1", fontSize:11 }}>{a.type?.replace("_DETECTED","").replace(/_/g," ")}</td>
                      <td style={{ padding:"10px 14px", color:"#4FC3F7" }}>{a.src_ip}</td>
                      <td style={{ padding:"10px 14px", color:"#8899AA" }}>{a.dst_ip||"—"}</td>
                      <td style={{ padding:"10px 14px" }}><span style={{ color:"#FFD740", fontSize:11 }}>{a.mitre_technique||"—"}</span></td>
                      <td style={{ padding:"10px 14px" }}>
                        <div style={{ display:"flex", alignItems:"center", gap:8 }}>
                          <div style={{ flex:1, height:3, background:"rgba(255,255,255,0.08)", borderRadius:2 }}>
                            <div style={{ width:`${(a.anomaly_score||0)*100}%`, height:"100%", background:SEV_COLOR[a.severity]||"#4FC3F7", borderRadius:2 }}/>
                          </div>
                          <span style={{ color:"#8899AA", fontSize:10 }}>{((a.anomaly_score||0)*100).toFixed(0)}%</span>
                        </div>
                      </td>
                      <td style={{ padding:"10px 14px", color:"#546E7A", fontSize:10 }}>{ago(a.timestamp)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Panel>
        )}

        {/* ── RESPONSE TAB ── */}
        {tab==="response" && (
          <div style={{ display:"flex", flexDirection:"column", gap:16 }}>
            <div style={{ display:"grid", gridTemplateColumns:"repeat(3,1fr)", gap:12 }}>
              <MetricCard label="Pending Block Actions" value={blockRecs.length} color="#E53935" live={blockRecs.length>0} icon="🚫"/>
              <MetricCard label="Blocked IPs (24h)" value={data.dash.blocked_ips??0} color="#FF6D00" icon="🔒"/>
              <MetricCard label="Active Incidents" value={data.dash.active_incidents??0} color="#FFD740" icon="📋"/>
            </div>
            <div style={{ background:"rgba(13,27,42,0.85)", border:`1px solid ${blockRecs.length > 0 ? "rgba(229,57,53,0.35)" : "rgba(79,195,247,0.1)"}`, borderRadius:10, overflow:"hidden" }}>
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
          </div>
        )}

        {/* ── INCIDENTS TAB ── */}
        {tab==="incidents" && (
          <div style={{ display:"flex", flexDirection:"column", gap:16 }}>
            <div style={{ display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:12 }}>
              {Object.entries(STATUS_COLOR).map(([s,c]) => (
                <MetricCard key={s} label={s} icon="" color={c}
                  value={(data.incidents||[]).filter(i=>i.status===s).length}
                  sub={`incidents ${s.toLowerCase()}`}/>
              ))}
            </div>
            <Panel title="Incident Registry" badge={`${(data.incidents||[]).length} total`} style={{ flex:1 }}>
              <div style={{ padding:16, display:"flex", flexDirection:"column", gap:12 }}>
                {(data.incidents||[]).length===0 ? (
                  <div style={{ textAlign:"center", padding:40, color:"#546E7A", fontFamily:"monospace", fontSize:12 }}>
                    {investigationsPaused ? "AI investigations paused — no incidents being created" : "No incidents yet — waiting for AI investigations to complete"}
                  </div>
                ) : (data.incidents||[]).map(inc => (
                  <div key={inc.incident_id}
                    onClick={() => openIncidentDrawer(inc)}
                    style={{
                      background:"rgba(5,13,21,0.6)", border:`1px solid ${STATUS_COLOR[inc.status]||"#546E7A"}30`,
                      borderLeft:`3px solid ${STATUS_COLOR[inc.status]||"#546E7A"}`,
                      borderRadius:8, padding:"16px 20px",
                      transition:"all 0.2s",
                      cursor: "pointer",
                    }}
                    onMouseEnter={e=>e.currentTarget.style.background="rgba(79,195,247,0.08)"}
                    onMouseLeave={e=>e.currentTarget.style.background="rgba(5,13,21,0.6)"}>
                    <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start", marginBottom:10 }}>
                      <div>
                        <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:6 }}>
                          <span style={{ fontFamily:"monospace", fontSize:10, color:"#546E7A" }}>{inc.incident_id}</span>
                          <SevBadge s={inc.severity}/>
                          <span style={{ fontFamily:"monospace", fontSize:10, color:STATUS_COLOR[inc.status], background:`${STATUS_COLOR[inc.status]}18`, padding:"2px 8px", borderRadius:3, border:`1px solid ${STATUS_COLOR[inc.status]}40`, letterSpacing:1 }}>{inc.status}</span>
                        </div>
                        <div style={{ fontSize:13, color:"#E2E8F0", fontWeight:500 }}>{inc.title}</div>
                      </div>
                      <div style={{ textAlign:"right", fontFamily:"monospace", fontSize:10, color:"#546E7A" }}>{ago(inc.created_at)}</div>
                    </div>
                    <div style={{ display:"flex", gap:16, flexWrap:"wrap" }}>
                      <div style={{ fontSize:11, color:"#8899AA" }}>
                        <span style={{ color:"#546E7A" }}>IPs: </span>
                        {(inc.affected_ips||[]).map(ip => <span key={ip} style={{ color:"#4FC3F7", marginRight:8 }}>{ip}</span>)}
                      </div>
                      <div style={{ fontSize:11, color:"#8899AA" }}>
                        <span style={{ color:"#546E7A" }}>MITRE: </span>
                        {(inc.mitre_techniques||[]).map(m => <span key={m} style={{ color:"#FFD740", marginRight:8 }}>{m}</span>)}
                      </div>
                    </div>
                    <div style={{marginTop:8, fontSize:10, color:"#546E7A", fontFamily:"monospace"}}>click to investigate →</div>
                  </div>
                ))}
              </div>
            </Panel>
          </div>
        )}

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
              <div>
                <div style={{ fontSize:11, color:"#4FC3F7", fontFamily:"monospace", letterSpacing:1, marginBottom:10, textTransform:"uppercase" }}>AI Investigation Summary</div>
                {(() => {
                  const aiSummary = incidentDetail?.investigation_summary || selectedIncident?.investigation_summary;
                  return aiSummary ? (
                    <div style={{ background:"rgba(5,13,21,0.6)", border:"1px solid rgba(79,195,247,0.1)", borderRadius:6, padding:"14px 16px", fontSize:11, color:"#CBD5E1", lineHeight:1.8, fontFamily:"monospace", whiteSpace:"pre-wrap", maxHeight:200, overflowY:"auto" }}>
                      {aiSummary}
                    </div>
                  ) : (
                    <div style={{ background:"rgba(5,13,21,0.4)", border:"1px solid rgba(84,110,122,0.2)", borderRadius:6, padding:"14px 16px", fontSize:11, color:"#546E7A", fontFamily:"monospace", fontStyle:"italic" }}>
                      No AI investigation was run for this alert (investigations were paused when alert arrived).
                    </div>
                  );
                })()}
              </div>

              {/* Section: Remediation */}
              <div>
                <div style={{ fontSize:11, color:"#4FC3F7", fontFamily:"monospace", letterSpacing:1, marginBottom:10, textTransform:"uppercase" }}>Remediation</div>
                {(() => {
                  // Priority: AI summary REMEDIATION block > generated AI > static playbook > fallback
                  const summary = incidentDetail?.investigation_summary || '';
                  const remIdx = summary.indexOf('REMEDIATION:');
                  if (remIdx !== -1) {
                    return (
                      <div style={{ background:"rgba(102,187,106,0.04)", border:"1px solid rgba(102,187,106,0.2)", borderRadius:6, padding:"14px 16px", fontSize:11, color:"#CBD5E1", lineHeight:1.8, fontFamily:"monospace", whiteSpace:"pre-wrap" }}>
                        {summary.substring(remIdx)}
                      </div>
                    );
                  }
                  if (generatedRemediation) {
                    return (
                      <div style={{ background:"rgba(102,187,106,0.04)", border:"1px solid rgba(102,187,106,0.2)", borderRadius:6, padding:"14px 16px", fontSize:11, color:"#CBD5E1", lineHeight:1.8, fontFamily:"monospace", whiteSpace:"pre-wrap" }}>
                        {generatedRemediation}
                      </div>
                    );
                  }
                  const mitre = (selectedIncident.mitre_techniques||[])[0];
                  const playbook = mitre ? (MITRE_PLAYBOOK[mitre] || MITRE_FALLBACK) : MITRE_FALLBACK;
                  const isGeneric = !mitre || !MITRE_PLAYBOOK[mitre];
                  return (
                    <div>
                      <div style={{ background:"rgba(102,187,106,0.04)", border:"1px solid rgba(102,187,106,0.15)", borderRadius:6, padding:"14px 16px", marginBottom:10 }}>
                        {isGeneric && <div style={{ fontSize:9, color:"#FFD740", fontFamily:"monospace", marginBottom:8 }}>&#x26A0; GENERIC PLAYBOOK — click below for AI-specific guidance</div>}
                        {playbook.steps.map((s,i) => (
                          <div key={i} style={{ fontSize:11, color:"#CBD5E1", lineHeight:1.7, marginBottom:4, fontFamily:"monospace" }}>&#x2022; {s}</div>
                        ))}
                      </div>
                      {isGeneric && (
                        <button onClick={generateAIRemediation} disabled={remediationLoading}
                          style={{ width:"100%", padding:"10px", background:"rgba(79,195,247,0.08)", border:"1px solid rgba(79,195,247,0.3)", borderRadius:4, color:"#4FC3F7", cursor:remediationLoading?"wait":"pointer", fontSize:11, fontFamily:"monospace" }}>
                          {remediationLoading ? "Generating AI Remediation..." : "&#x26A1; Generate AI Remediation (1 API call)"}
                        </button>
                      )}
                    </div>
                  );
                })()}
              </div>

              {/* Section: ChromaDB Threat Signatures */}
              <div>
                <div style={{ fontSize:11, color:"#4FC3F7", fontFamily:"monospace", letterSpacing:1, marginBottom:10, textTransform:"uppercase" }}>Threat Signatures — ChromaDB</div>
                {threatSigs.length > 0 ? (
                  <div style={{ display:"flex", flexDirection:"column", gap:8 }}>
                    {threatSigs.slice(0,3).map((sig,i) => (
                      <div key={i} style={{ background:"rgba(79,195,247,0.03)", border:"1px solid rgba(79,195,247,0.1)", borderRadius:6, padding:"10px 14px" }}>
                        <div style={{ display:"flex", gap:8, alignItems:"flex-start" }}>
                          <span style={{ fontFamily:"monospace", fontSize:9, color:"#4FC3F7", background:"rgba(79,195,247,0.1)", padding:"2px 6px", borderRadius:2, marginTop:1, flexShrink:0 }}>{i+1}</span>
                          <span style={{ fontSize:11, color:"#CBD5E1", lineHeight:1.6, fontFamily:"monospace" }}>{typeof sig==="string"?sig:JSON.stringify(sig)}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div style={{ fontSize:11, color:"#546E7A", fontFamily:"monospace", fontStyle:"italic" }}>No matching signatures found in knowledge base.</div>
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
        <div>CyberSentinel AI v1.0 · Capstone 2025 · {authed&&token?"Authenticated":""}</div>
        <div style={{ display:"flex", gap:16 }}>
          <span>Alerts: <span style={{color:"#4FC3F7"}}>{apiLive?(data.alerts?.length??0):8}</span></span>
          <span>Incidents: <span style={{color:"#FFD740"}}>{apiLive?(data.incidents?.length??0):4}</span></span>
          <span>Risk: <span style={{color:riskColor}}>{riskPct}%</span></span>
        </div>
      </div>
    </div>
  );
}
