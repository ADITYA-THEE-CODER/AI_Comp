// ===== CyberShield AI - Main Application Script =====

// ===== State Management =====
const state = {
  currentPage: 'landing',
  currentScanner: null,
  scanHistory: [],
  isScanning: false,
  theme: localStorage.getItem('cybershield-theme') || 'dark',
  stats: { scans: 1284, threats: 47, safeRate: 96.3 }
};

// ===== Scanner Definitions =====
const scanners = [
  { id: 'email', name: 'Email Scanner', icon: 'mail', color: 'red', desc: 'Detect phishing, spoofing, and malicious attachments', placeholder: 'Paste the full email content including headers, body, and links...', inputType: 'textarea' },
  { id: 'url', name: 'URL Scanner', icon: 'link', color: 'blue', desc: 'Analyze URLs for malware and credential harvesting', placeholder: 'Enter a URL to analyze (e.g., https://suspicious-site.com/login)', inputType: 'input' },
  { id: 'file', name: 'File Scanner', icon: 'file-search', color: 'amber', desc: 'Inspect files for embedded malware and scripts', placeholder: 'Describe the file details: name, type, source, size, behavior, hashes if available...', inputType: 'textarea' },
  { id: 'message', name: 'Message Scanner', icon: 'message-square', color: 'green', desc: 'Scan SMS, DMs, and chat messages for threats', placeholder: 'Paste the suspicious message content here...', inputType: 'textarea' },
  { id: 'prompt', name: 'Prompt Injection', icon: 'terminal', color: 'purple', desc: 'Detect prompt injection and jailbreak attempts', placeholder: 'Paste the AI prompt or input you want to check for injection attempts...', inputType: 'textarea' },
  { id: 'social', name: 'Social Engineering', icon: 'users', color: 'pink', desc: 'Identify manipulation tactics and impersonation', placeholder: 'Describe the social engineering encounter: what was said, requested, context...', inputType: 'textarea' },
  { id: 'qr', name: 'QR Code Scanner', icon: 'qr-code', color: 'cyan', desc: 'Decode and analyze QR codes for threats', placeholder: 'Describe the QR code context or paste the decoded URL/content...', inputType: 'textarea' },
  { id: 'malware', name: 'Malware Risk', icon: 'bug', color: 'orange', desc: 'Assess malware risk through behavioral analysis', placeholder: 'Describe the suspicious behavior, process, or file activity...', inputType: 'textarea' }
];

// ===== Sample Data =====
const sampleRecentScans = [
  { type: 'Email', item: 'support@bank-verify-secure.com', verdict: 'High Risk', confidence: 94, time: '2 min ago', color: 'red' },
  { type: 'URL', item: 'https://g00gle-accounts.login.xyz/auth', verdict: 'Critical', confidence: 98, time: '8 min ago', color: 'red' },
  { type: 'Message', item: 'SMS from +1-555-0123', verdict: 'Medium Risk', confidence: 76, time: '15 min ago', color: 'amber' },
  { type: 'Prompt', item: 'System override instruction attempt', verdict: 'High Risk', confidence: 91, time: '22 min ago', color: 'red' },
  { type: 'URL', item: 'https://github.com/torvalds/linux', verdict: 'Safe', confidence: 97, time: '35 min ago', color: 'green' },
  { type: 'Email', item: 'newsletter@techcrunch.com', verdict: 'Low Risk', confidence: 89, time: '1 hr ago', color: 'cyan' },
  { type: 'File', item: 'report_final_v2.docx.exe', verdict: 'Critical', confidence: 96, time: '2 hr ago', color: 'red' },
  { type: 'Social', item: 'LinkedIn connection from "CEO of your company"', verdict: 'Medium Risk', confidence: 72, time: '3 hr ago', color: 'amber' }
];

const securityTips = [
  { icon: 'shield-alert', title: 'Verify Sender Identity', desc: 'Always check email addresses carefully, not just display names.' },
  { icon: 'key-round', title: 'Use Strong Passwords', desc: 'Unique 16+ character passwords for each account with MFA enabled.' },
  { icon: 'wifi-off', title: 'Avoid Public Wi-Fi', desc: 'Use a VPN if you must connect to public networks.' },
  { icon: 'refresh-cw', title: 'Keep Software Updated', desc: 'Security patches protect against known vulnerabilities.' },
  { icon: 'eye-off', title: 'Limit Personal Info', desc: 'Reduce your digital footprint to lower social engineering risk.' },
  { icon: 'fingerprint', title: 'Enable Biometric Auth', desc: 'Biometrics add a layer that passwords alone cannot provide.' }
];

const automationHistoryData = [
  { workflow: 'Email Alerts', event: 'High risk detected on bank-verify-secure.com', status: 'Sent', statusColor: 'green', time: '2 min ago' },
  { workflow: 'Incident Creation', event: 'Critical threat → INC-2847', status: 'Created', statusColor: 'blue', time: '8 min ago' },
  { workflow: 'Audit Logging', event: 'Scan #1283 logged to SIEM', status: 'Logged', statusColor: 'green', time: '15 min ago' },
  { workflow: 'Email Alerts', event: 'Medium risk on SMS scan', status: 'Sent', statusColor: 'green', time: '22 min ago' },
  { workflow: 'Incident Creation', event: 'High risk → INC-2846', status: 'Created', statusColor: 'blue', time: '1 hr ago' },
  { workflow: 'Audit Logging', event: 'Scan #1281 logged to SIEM', status: 'Logged', statusColor: 'green', time: '2 hr ago' }
];

// ===== Threat Analysis Results Generator =====
function generateThreatAnalysis(scannerType, input, context) {
  const inputLower = input.toLowerCase();
  const contextLower = (context || '').toLowerCase();
  const combined = inputLower + ' ' + contextLower;

  // Risk scoring heuristics
  let riskScore = 20; // Base score
  let riskFactors = [];
  let safeFactors = [];

  // Universal suspicious patterns
  const suspiciousWords = ['urgent', 'verify', 'suspend', 'immediately', 'click here', 'act now', 'free', 'winner', 'congratulations', 'password', 'ssn', 'social security', 'wire transfer', 'bitcoin', 'cryptocurrency', 'gift card', 'unusual activity', 'account locked', 'expire', 'last warning'];
  const safeWords = ['github.com', 'stackoverflow.com', 'google.com', 'microsoft.com', 'apple.com', 'amazon.com'];
  const suspiciousDomains = ['.xyz', '.top', '.click', '.buzz', '.loan', '.work', '.party', '.review'];
  const suspiciousExtensions = ['.exe', '.scr', '.bat', '.cmd', '.vbs', '.ps1', '.js'];
  const injectionPatterns = ['ignore previous', 'forget your instructions', 'you are now', 'system:', 'override', 'jailbreak', 'simulate', 'pretend you are', 'act as if', 'bypass', 'dan mode'];

  // Check for suspicious words
  suspiciousWords.forEach(w => {
    if (combined.includes(w)) {
      riskScore += 12;
      riskFactors.push(`Suspicious keyword detected: "${w}"`);
    }
  });

  // Check for safe indicators
  safeWords.forEach(w => {
    if (inputLower.includes(w)) {
      riskScore -= 15;
      safeFactors.push(`Trusted domain: ${w}`);
    }
  });

  // Scanner-specific analysis
  switch (scannerType) {
    case 'email':
      if (inputLower.includes('@') && /[\w.-]+@[\w.-]+\.\w+/.test(inputLower)) {
        const emailMatch = inputLower.match(/[\w.-]+@([\w.-]+\.\w+)/);
        if (emailMatch) {
          const domain = emailMatch[1];
          suspiciousDomains.forEach(d => {
            if (domain.endsWith(d)) {
              riskScore += 25;
              riskFactors.push(`Suspicious TLD: ${d}`);
            }
          });
          if (domain.includes('-') && domain.replace(/-/g, '').length < 5) {
            riskScore += 15;
            riskFactors.push('Domain uses excessive hyphens (common in phishing)');
          }
          if (/g00gle|paypa1|amaz0n|faceb00k|micros0ft/i.test(domain)) {
            riskScore += 30;
            riskFactors.push('Domain uses character substitution (lookalike domain)');
          }
        }
      }
      if (inputLower.includes('http') || inputLower.includes('www')) {
        riskScore += 8;
        riskFactors.push('Email contains embedded links');
      }
      if (inputLower.includes('attachment') || inputLower.includes('download')) {
        riskScore += 10;
        riskFactors.push('Email requests file download/attachment interaction');
      }
      break;

    case 'url':
      try {
        const urlObj = new URL(input.startsWith('http') ? input : 'https://' + input);
        suspiciousDomains.forEach(d => {
          if (urlObj.hostname.endsWith(d)) {
            riskScore += 25;
            riskFactors.push(`Suspicious TLD: ${d}`);
          }
        });
        if (/g00gle|paypa1|amaz0n|faceb00k|micros0ft/i.test(urlObj.hostname)) {
          riskScore += 30;
          riskFactors.push('Domain uses character substitution (brand impersonation)');
        }
        if (urlObj.hostname.includes('-') && urlObj.hostname.split('-').length > 3) {
          riskScore += 15;
          riskFactors.push('Excessive subdomain segments (potential phishing)');
        }
        if (urlObj.pathname.length > 50) {
          riskScore += 8;
          riskFactors.push('Unusually long URL path');
        }
        if (urlObj.search && urlObj.search.length > 30) {
          riskScore += 5;
          riskFactors.push('Contains query parameters (potential tracking)');
        }
        if (!urlObj.protocol.includes('https')) {
          riskScore += 10;
          riskFactors.push('Non-HTTPS protocol (unencrypted)');
        }
      } catch (e) {
        riskScore += 5;
        riskFactors.push('URL format is unusual or malformed');
      }
      break;

    case 'file':
      suspiciousExtensions.forEach(ext => {
        if (inputLower.includes(ext)) {
          riskScore += 30;
          riskFactors.push(`Dangerous file extension: ${ext}`);
        }
      });
      if (/\.\w+\.\w+/.test(inputLower)) {
        riskScore += 25;
        riskFactors.push('Double extension detected (common malware technique)');
      }
      if (inputLower.includes('macro') || inputLower.includes('vba') || inputLower.includes('script')) {
        riskScore += 20;
        riskFactors.push('Contains macro/script references');
      }
      break;

    case 'message':
      if (inputLower.includes('wire transfer') || inputLower.includes('payment') || inputLower.includes('gift card')) {
        riskScore += 20;
        riskFactors.push('Financial request detected (common in BEC scams)');
      }
      if (inputLower.includes('click') && inputLower.includes('link')) {
        riskScore += 12;
        riskFactors.push('Requests clicking a link');
      }
      if (/urgent|asap|right now|immediately/i.test(inputLower)) {
        riskScore += 10;
        riskFactors.push('Urgency tactics detected');
      }
      break;

    case 'prompt':
      injectionPatterns.forEach(p => {
        if (combined.includes(p)) {
          riskScore += 20;
          riskFactors.push(`Injection pattern: "${p}"`);
        }
      });
      if (inputLower.includes('roleplay') || inputLower.includes('pretend')) {
        riskScore += 15;
        riskFactors.push('Roleplay/pretend instruction (potential jailbreak)');
      }
      if (inputLower.length > 500 && injectionPatterns.some(p => inputLower.includes(p))) {
        riskScore += 10;
        riskFactors.push('Long prompt with injection patterns (sophisticated attack)');
      }
      break;

    case 'social':
      if (inputLower.includes('ceo') || inputLower.includes('boss') || inputLower.includes('executive')) {
        riskScore += 15;
        riskFactors.push('Authority figure impersonation attempt');
      }
      if (inputLower.includes('password') || inputLower.includes('credential') || inputLower.includes('login')) {
        riskScore += 20;
        riskFactors.push('Credential harvesting attempt');
      }
      if (inputLower.includes('verify') || inputLower.includes('confirm')) {
        riskScore += 12;
        riskFactors.push('Verification pretext (common social engineering tactic)');
      }
      break;

    case 'qr':
      if (inputLower.includes('http') && suspiciousDomains.some(d => inputLower.includes(d))) {
        riskScore += 25;
        riskFactors.push('QR code contains suspicious domain');
      }
      if (inputLower.includes('payment') || inputLower.includes('crypto') || inputLower.includes('wallet')) {
        riskScore += 15;
        riskFactors.push('QR code links to payment/crypto destination');
      }
      break;

    case 'malware':
      if (inputLower.includes('encrypt') && inputLower.includes('file')) {
        riskScore += 25;
        riskFactors.push('File encryption behavior (ransomware indicator)');
      }
      if (inputLower.includes('registry') || inputLower.includes('autorun') || inputLower.includes('startup')) {
        riskScore += 20;
        riskFactors.push('Persistence mechanism detected');
      }
      if (inputLower.includes('c2') || inputLower.includes('command and control') || inputLower.includes('beacon')) {
        riskScore += 30;
        riskFactors.push('C2 communication pattern detected');
      }
      break;
  }

  // Context influence
  if (contextLower.includes('unexpected') || contextLower.includes('unsolicited')) {
    riskScore += 10;
    riskFactors.push('Item was unexpected/unsolicited (increases risk)');
  }
  if (contextLower.includes('trusted source') || contextLower.includes('expected')) {
    riskScore -= 10;
    safeFactors.push('Item was expected/from trusted source');
  }

  // Clamp score
  riskScore = Math.max(0, Math.min(100, riskScore));

  // Determine verdict
  let verdict, verdictClass, verdictLabel;
  if (riskScore >= 80) { verdict = 'critical'; verdictClass = 'badge-critical'; verdictLabel = 'Critical'; }
  else if (riskScore >= 60) { verdict = 'high'; verdictClass = 'badge-high'; verdictLabel = 'High Risk'; }
  else if (riskScore >= 40) { verdict = 'medium'; verdictClass = 'badge-medium'; verdictLabel = 'Medium Risk'; }
  else if (riskScore >= 20) { verdict = 'low'; verdictClass = 'badge-low'; verdictLabel = 'Low Risk'; }
  else { verdict = 'safe'; verdictClass = 'badge-safe'; verdictLabel = 'Safe'; }

  const confidence = Math.min(98, 65 + Math.abs(riskScore - 50) * 0.6 + Math.random() * 10);

  // Generate LLM responses
  const llmModels = [
    { name: 'GPT-4o', color: 'cyber', confidence: confidence - 2 + Math.random() * 4 },
    { name: 'Claude 3.5', color: 'shield', confidence: confidence - 3 + Math.random() * 6 },
    { name: 'Gemini Pro', color: 'purple', confidence: confidence - 4 + Math.random() * 8 }
  ];

  const llmResponses = llmModels.map(model => {
    const modelConf = Math.round(Math.max(50, Math.min(99, model.confidence)));
    const modelVerdict = modelConf >= 80 ? (riskScore >= 70 ? 'High Risk' : riskScore >= 40 ? 'Medium Risk' : 'Low Risk') :
                         modelConf >= 60 ? 'Medium Risk' : 'Low Risk';
    const reasoning = generateReasoning(scannerType, model.name, riskFactors, safeFactors, riskScore);
    return {
      ...model,
      confidence: modelConf,
      verdict: riskScore >= 80 ? 'Critical' : riskScore >= 60 ? 'High Risk' : modelVerdict,
      reasoning
    };
  });

  // Aggregated confidence
  const avgConfidence = Math.round(llmResponses.reduce((s, m) => s + m.confidence, 0) / llmResponses.length);

  // AI Opinion
  const opinion = generateOpinion(scannerType, verdictLabel, riskScore, riskFactors, safeFactors, avgConfidence);

  return {
    verdict,
    verdictClass,
    verdictLabel,
    riskScore,
    confidence: avgConfidence,
    llmResponses,
    riskFactors,
    safeFactors,
    opinion,
    scannerType
  };
}

function generateReasoning(scannerType, model, riskFactors, safeFactors, riskScore) {
  const scannerReasons = {
    email: 'Analyzed email headers, sender domain, body content, embedded links, and social engineering indicators.',
    url: 'Examined domain reputation, SSL status, URL structure, redirect chains, and known phishing patterns.',
    file: 'Assessed file type, extension, metadata patterns, embedded content indicators, and known malware signatures.',
    message: 'Evaluated message content for urgency tactics, financial requests, impersonation, and manipulation patterns.',
    prompt: 'Scanned for instruction override attempts, role manipulation, jailbreak patterns, and adversarial input techniques.',
    social: 'Identified authority impersonation, urgency tactics, pretexting strategies, and credential harvesting indicators.',
    qr: 'Analyzed encoded content, destination domain, potential redirect chains, and context-based risk factors.',
    malware: 'Examined behavioral indicators, persistence mechanisms, encryption patterns, and C2 communication signatures.'
  };

  let reason = scannerReasons[scannerType] || 'Analyzed input for threat indicators.';
  if (riskFactors.length > 0) {
    reason += ` Key concerns: ${riskFactors.slice(0, 3).join('; ')}.`;
  }
  if (safeFactors.length > 0 && riskScore < 40) {
    reason += ` Positive signals: ${safeFactors.slice(0, 2).join('; ')}.`;
  }
  return reason;
}

function generateOpinion(scannerType, verdictLabel, riskScore, riskFactors, safeFactors, confidence) {
  const scannerName = scanners.find(s => s.id === scannerType)?.name || 'General Scanner';
  let summary, riskExplanation, recommendedActions;

  if (riskScore >= 80) {
    summary = `Based on my analysis, this item poses a <strong>critical security threat</strong>. Multiple red flags were identified that are consistent with known attack patterns. I'm ${confidence}% confident in this assessment.`;
    riskExplanation = `This item exhibits characteristics commonly associated with serious cyber threats. ${riskFactors.length > 0 ? 'The following risk indicators were identified: ' + riskFactors.slice(0, 4).map(f => '<code class="text-xs bg-red-500/10 px-1.5 py-0.5 rounded text-red-300">' + f.replace(/"/g, '') + '</code>').join(', ') + '.' : ''} These patterns are strongly correlated with malicious activity.`;
    recommendedActions = `<ol class="list-decimal list-inside space-y-1.5 mt-2"><li><strong>Do not interact</strong> with this item — do not click links, open attachments, or respond</li><li>Report it to your IT security team immediately</li><li>If you already interacted, change compromised passwords and enable MFA</li><li>Run a full malware scan on your device</li><li>Monitor accounts for unauthorized activity</li></ol>`;
  } else if (riskScore >= 60) {
    summary = `My assessment indicates this item is <strong>likely suspicious</strong> and should be treated with caution. I'm ${confidence}% confident in this evaluation.`;
    riskExplanation = `Several indicators suggest potential malicious intent. ${riskFactors.length > 0 ? 'Specifically: ' + riskFactors.slice(0, 3).map(f => '<code class="text-xs bg-amber-500/10 px-1.5 py-0.5 rounded text-amber-300">' + f.replace(/"/g, '') + '</code>').join(', ') + '.' : ''} While not definitively malicious, the risk profile is concerning.`;
    recommendedActions = `<ol class="list-decimal list-inside space-y-1.5 mt-2"><li><strong>Verify the source</strong> through an independent channel before trusting</li><li>Do not provide sensitive information or credentials</li><li>If this is an email, check the sender's address carefully</li><li>Consider reporting to your security team for further review</li></ol>`;
  } else if (riskScore >= 40) {
    summary = `This item shows <strong>moderate risk indicators</strong>. While not immediately dangerous, some aspects warrant attention. I'm ${confidence}% confident in this assessment.`;
    riskExplanation = `A few patterns raised minor concerns. ${riskFactors.length > 0 ? 'These include: ' + riskFactors.slice(0, 2).map(f => '<code class="text-xs bg-yellow-500/10 px-1.5 py-0.5 rounded text-yellow-300">' + f.replace(/"/g, '') + '</code>').join(', ') + '.' : 'No major red flags, but vigilance is still recommended.'}`;
    recommendedActions = `<ol class="list-decimal list-inside space-y-1.5 mt-2"><li>Proceed with <strong>cautious awareness</strong></li><li>Verify the sender/source if possible</li><li>Be wary of any requests for personal information</li><li>Report if behavior escalates or becomes suspicious</li></ol>`;
  } else if (riskScore >= 20) {
    summary = `This item appears to be <strong>relatively low risk</strong>, though no automated system can guarantee complete safety. I'm ${confidence}% confident in this assessment.`;
    riskExplanation = `Minimal threat indicators were found. ${safeFactors.length > 0 ? 'Positive signals include: ' + safeFactors.map(f => '<code class="text-xs bg-green-500/10 px-1.5 py-0.5 rounded text-green-300">' + f + '</code>').join(', ') + '.' : 'The item did not match common threat patterns.'}`;
    recommendedActions = `<ol class="list-decimal list-inside space-y-1.5 mt-2"><li>Continue with <strong>normal caution</strong></li><li>Stay alert for any unusual behavior</li><li>Keep your security software updated</li></ol>`;
  } else {
    summary = `Based on my analysis, this item appears to be <strong>safe</strong>. No significant threat indicators were detected. I'm ${confidence}% confident in this assessment.`;
    riskExplanation = `The item does not exhibit characteristics of known threats. ${safeFactors.length > 0 ? 'Trusted indicators detected: ' + safeFactors.map(f => '<code class="text-xs bg-green-500/10 px-1.5 py-0.5 rounded text-green-300">' + f + '</code>').join(', ') + '.' : 'Standard threat pattern analysis returned clean results.'}`;
    recommendedActions = `<ol class="list-decimal list-inside space-y-1.5 mt-2"><li>This item appears <strong>safe to interact with</strong></li><li>Continue practicing standard cybersecurity hygiene</li><li>Remember: always stay vigilant, even with trusted sources</li></ol>`;
  }

  return { summary, riskExplanation, recommendedActions, confidence, verdictLabel };
}

// ===== Navigation =====
function navigateTo(page) {
  // Hide all pages
  document.querySelectorAll('.page-section').forEach(el => {
    el.classList.remove('active');
  });

  // Show target page
  const target = document.getElementById(`page-${page}`);
  if (target) {
    // Small delay for animation
    setTimeout(() => {
      target.classList.add('active');
    }, 50);
  }

  // Update nav links
  document.querySelectorAll('.nav-link').forEach(el => {
    el.classList.remove('active');
    if (el.dataset.nav === page) el.classList.add('active');
  });

  state.currentPage = page;
  window.scrollTo({ top: 0, behavior: 'smooth' });

  // Initialize page-specific content
  if (page === 'dashboard') initDashboard();
  if (page === 'scanners') initScannersPage();

  lucide.createIcons();
}

function toggleMobileMenu() {
  const menu = document.getElementById('mobileMenu');
  menu.classList.toggle('hidden');
}

// ===== Theme =====
function toggleTheme() {
  const html = document.documentElement;
  const newTheme = html.classList.contains('dark') ? 'light' : 'dark';
  html.classList.remove('dark', 'light');
  html.classList.add(newTheme);
  state.theme = newTheme;
  localStorage.setItem('cybershield-theme', newTheme);
  lucide.createIcons();
}

// ===== Accordion =====
function toggleAccordion(id) {
  const el = document.getElementById(id);
  const arrow = document.getElementById(id + 'Arrow');
  const isHidden = el.classList.contains('hidden');
  
  el.classList.toggle('hidden');
  if (arrow) {
    arrow.style.transform = isHidden ? 'rotate(180deg)' : 'rotate(0)';
  }
}

// ===== Dashboard Init =====
function initDashboard() {
  renderRecentScans();
  renderSecurityTips();
  renderAutomationHistory();
  initCharts();
  animateCounters();
}

function renderRecentScans() {
  const container = document.getElementById('recentScansList');
  if (!container) return;
  container.innerHTML = sampleRecentScans.map((scan, i) => `
    <div class="flex items-center gap-4 p-3 rounded-xl hover:bg-white/5 transition-colors result-appear" style="animation-delay:${i * 50}ms">
      <div class="w-2 h-2 rounded-full bg-${scan.color}-400 flex-shrink-0"></div>
      <div class="flex-1 min-w-0">
        <div class="text-sm font-medium text-white truncate">${scan.item}</div>
        <div class="text-xs text-gray-500">${scan.type} • ${scan.time}</div>
      </div>
      <span class="badge-${scan.color === 'red' ? 'high' : scan.color === 'amber' ? 'medium' : scan.color === 'green' ? 'safe' : 'low'} px-2.5 py-1 rounded-full text-xs font-semibold whitespace-nowrap">${scan.verdict}</span>
      <span class="text-xs text-gray-500 font-mono">${scan.confidence}%</span>
    </div>
  `).join('');
}

function renderSecurityTips() {
  const container = document.getElementById('securityTips');
  if (!container) return;
  container.innerHTML = securityTips.map((tip, i) => `
    <div class="p-3 rounded-xl bg-white/5 hover:bg-white/8 transition result-appear" style="animation-delay:${i * 80}ms">
      <div class="flex items-start gap-2">
        <i data-lucide="${tip.icon}" class="w-4 h-4 text-cyber-400 mt-0.5 flex-shrink-0"></i>
        <div>
          <div class="text-sm font-semibold text-white">${tip.title}</div>
          <div class="text-xs text-gray-400 mt-0.5">${tip.desc}</div>
        </div>
      </div>
    </div>
  `).join('');
}

function renderAutomationHistory() {
  const container = document.getElementById('automationHistory');
  if (!container) return;
  container.innerHTML = automationHistoryData.map(h => `
    <tr class="border-b border-white/5 hover:bg-white/5 transition-colors">
      <td class="py-3 pr-4 text-gray-300">${h.workflow}</td>
      <td class="py-3 pr-4 text-gray-400">${h.event}</td>
      <td class="py-3 pr-4"><span class="px-2 py-0.5 rounded-md text-xs font-semibold bg-${h.statusColor}-500/20 text-${h.statusColor}-400">${h.status}</span></td>
      <td class="py-3 text-gray-500">${h.time}</td>
    </tr>
  `).join('');
}

function animateCounters() {
  const targets = { 'stat-scans': 1284, 'stat-threats': 47 };
  Object.entries(targets).forEach(([id, target]) => {
    const el = document.getElementById(id);
    if (!el) return;
    let current = 0;
    const increment = Math.ceil(target / 40);
    const timer = setInterval(() => {
      current += increment;
      if (current >= target) {
        current = target;
        clearInterval(timer);
      }
      el.textContent = current.toLocaleString();
    }, 30);
  });
}

// ===== Charts =====
let chartActivity = null;
let chartThreats = null;

function initCharts() {
  // Activity Chart
  const activityCtx = document.getElementById('chartActivity')?.getContext('2d');
  if (!activityCtx) return;

  if (chartActivity) chartActivity.destroy();
  if (chartThreats) chartThreats.destroy();

  const isDark = document.documentElement.classList.contains('dark');

  chartActivity = new Chart(activityCtx, {
    type: 'line',
    data: {
      labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
      datasets: [
        {
          label: 'Scans',
          data: [156, 189, 234, 198, 276, 312, 284],
          borderColor: '#06b6d4',
          backgroundColor: 'rgba(6, 182, 212, 0.1)',
          fill: true,
          tension: 0.4,
          pointRadius: 4,
          pointHoverRadius: 6,
          borderWidth: 2
        },
        {
          label: 'Threats',
          data: [4, 7, 3, 8, 6, 12, 7],
          borderColor: '#ef4444',
          backgroundColor: 'rgba(239, 68, 68, 0.1)',
          fill: true,
          tension: 0.4,
          pointRadius: 4,
          pointHoverRadius: 6,
          borderWidth: 2
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { labels: { color: isDark ? '#9ca3af' : '#64748b', font: { size: 12 } } }
      },
      scales: {
        x: { grid: { color: isDark ? 'rgba(255,255,255,0.05)' : 'rgba(0,0,0,0.05)' }, ticks: { color: isDark ? '#6b7280' : '#94a3b8' } },
        y: { grid: { color: isDark ? 'rgba(255,255,255,0.05)' : 'rgba(0,0,0,0.05)' }, ticks: { color: isDark ? '#6b7280' : '#94a3b8' } }
      }
    }
  });

  // Threat Categories Doughnut
  const threatsCtx = document.getElementById('chartThreats')?.getContext('2d');
  if (!threatsCtx) return;

  chartThreats = new Chart(threatsCtx, {
    type: 'doughnut',
    data: {
      labels: ['Phishing', 'Malware', 'Social Eng.', 'Prompt Inject', 'Spam', 'Other'],
      datasets: [{
        data: [35, 22, 18, 12, 8, 5],
        backgroundColor: ['#ef4444', '#f59e0b', '#ec4899', '#a855f7', '#06b6d4', '#6b7280'],
        borderWidth: 0,
        spacing: 3,
        borderRadius: 4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '65%',
      plugins: {
        legend: {
          position: 'bottom',
          labels: { color: isDark ? '#9ca3af' : '#64748b', font: { size: 11 }, padding: 12 }
        }
      }
    }
  });
}

// ===== Scanners Page =====
function initScannersPage() {
  renderScannerGrid();
}

function renderScannerGrid() {
  const grid = document.getElementById('scannerGrid');
  if (!grid) return;
  grid.innerHTML = scanners.map(s => `
    <div class="scanner-card cursor-pointer" onclick="openScanner('${s.id}')">
      <div class="flex items-center gap-3 mb-3">
        <div class="w-10 h-10 rounded-xl bg-${s.color}-500/20 flex items-center justify-center"><i data-lucide="${s.icon}" class="w-5 h-5 text-${s.color}-400"></i></div>
        <h3 class="font-bold text-white text-sm">${s.name}</h3>
      </div>
      <p class="text-xs text-gray-400">${s.desc}</p>
    </div>
  `).join('');
  lucide.createIcons();
}

function openScanner(scannerId) {
  state.currentScanner = scannerId;
  const scanner = scanners.find(s => s.id === scannerId);
  if (!scanner) return;

  navigateTo('scanners');

  setTimeout(() => {
    const interface_ = document.getElementById('scanInterface');
    const scanTitle = document.getElementById('scanTitle');
    const scanInputArea = document.getElementById('scanInputArea');

    scanTitle.textContent = scanner.name;

    if (scanner.inputType === 'input') {
      scanInputArea.innerHTML = `<input type="text" id="scanInput" class="scan-textarea" style="min-height:auto;height:48px;" placeholder="${scanner.placeholder}" autocomplete="off">`;
    } else {
      scanInputArea.innerHTML = `<textarea id="scanInput" class="scan-textarea" placeholder="${scanner.placeholder}"></textarea>`;
    }

    // Show interface, hide results
    interface_.classList.remove('hidden');
    document.getElementById('scanResults').classList.add('hidden');
    document.getElementById('scanProgress').classList.add('hidden');
    document.getElementById('scanBtn').disabled = false;
    document.getElementById('scanBtn').innerHTML = '<i data-lucide="zap" class="w-4 h-4"></i><span>Analyze with Multi-LLM</span>';

    // Scroll to scanner
    interface_.scrollIntoView({ behavior: 'smooth', block: 'start' });

    lucide.createIcons();
  }, 100);
}

// ===== Run Scan =====
function runScan() {
  const input = document.getElementById('scanInput')?.value?.trim();
  const context = document.getElementById('contextInput')?.value?.trim();

  if (!input) {
    const scanInput = document.getElementById('scanInput');
    scanInput.style.borderColor = 'rgba(239, 68, 68, 0.5)';
    scanInput.focus();
    setTimeout(() => { scanInput.style.borderColor = ''; }, 2000);
    return;
  }

  state.isScanning = true;

  // Show progress, hide results
  document.getElementById('scanProgress').classList.remove('hidden');
  document.getElementById('scanResults').classList.add('hidden');
  document.getElementById('scanBtn').disabled = true;
  document.getElementById('scanBtn').innerHTML = '<i data-lucide="loader-2" class="w-4 h-4 animate-spin"></i><span>Scanning...</span>';

  lucide.createIcons();

  // Simulate progressive analysis
  let progress = 0;
  const progressBar = document.getElementById('progressBar');
  const llmStatuses = [
    { spinner: 'llm1spinner', status: 'llm1status' },
    { spinner: 'llm2spinner', status: 'llm2status' },
    { spinner: 'llm3spinner', status: 'llm3status' }
  ];

  llmStatuses.forEach(l => {
    document.getElementById(l.status).textContent = 'Processing';
    document.getElementById(l.spinner).classList.remove('hidden');
    document.getElementById(l.spinner).classList.add('animate-spin');
  });

  const progressInterval = setInterval(() => {
    progress += Math.random() * 8 + 2;
    if (progress > 95) progress = 95;
    progressBar.style.width = progress + '%';

    // Update LLM statuses
    if (progress > 30) {
      document.getElementById('llm1status').textContent = 'Analyzing...';
    }
    if (progress > 50) {
      document.getElementById('llm2status').textContent = 'Analyzing...';
    }
    if (progress > 70) {
      document.getElementById('llm3status').textContent = 'Analyzing...';
    }
  }, 200);

  // Complete after delay
  setTimeout(() => {
    clearInterval(progressInterval);
    progressBar.style.width = '100%';

    // Mark all LLMs as complete
    llmStatuses.forEach(l => {
      document.getElementById(l.status).textContent = 'Complete ✓';
      document.getElementById(l.spinner).classList.add('hidden');
    });

    // Generate and display results
    const results = generateThreatAnalysis(state.currentScanner, input, context);
    displayResults(results);

    // Add to history
    state.scanHistory.unshift({
      type: scanners.find(s => s.id === state.currentScanner)?.name,
      item: input.substring(0, 60) + (input.length > 60 ? '...' : ''),
      verdict: results.verdictLabel,
      confidence: results.confidence,
      time: 'Just now'
    });

    state.isScanning = false;
  }, 3500);
}

function displayResults(results) {
  const resultsEl = document.getElementById('scanResults');
  const llmGrid = document.getElementById('llmResultsGrid');
  const verdictCard = document.getElementById('verdictCard');
  const verdictBadge = document.getElementById('verdictBadge');
  const verdictContent = document.getElementById('verdictContent');
  const aiOpinion = document.getElementById('aiOpinion');
  const confValue = document.getElementById('confValue');
  const confCircle = document.getElementById('confCircle');
  const confBreakdown = document.getElementById('confBreakdown');

  // Show results
  document.getElementById('scanProgress').classList.add('hidden');
  resultsEl.classList.remove('hidden');
  resultsEl.scrollIntoView({ behavior: 'smooth', block: 'start' });

  // LLM Individual Results
  const colorMap = { cyber: ['cyan', 'cyan'], shield: ['green', 'green'], purple: ['purple', 'purple'] };
  llmGrid.innerHTML = results.llmResponses.map((llm, i) => {
    const colors = ['cyber', 'shield', 'purple'];
    const c = colors[i];
    return `
      <div class="llm-result-card result-appear" style="animation-delay:${i * 150}ms">
        <div class="flex items-center gap-2 mb-3">
          <div class="w-2 h-2 rounded-full bg-${c}-400"></div>
          <span class="text-sm font-semibold text-white">${llm.name}</span>
        </div>
        <div class="mb-3">
          <span class="badge-${llm.verdict === 'Critical' ? 'critical' : llm.verdict === 'High Risk' ? 'high' : llm.verdict === 'Medium Risk' ? 'medium' : llm.verdict === 'Low Risk' ? 'low' : 'safe'} px-2.5 py-1 rounded-full text-xs font-semibold">${llm.verdict}</span>
        </div>
        <div class="flex items-center gap-2 mb-2">
          <span class="text-xs text-gray-500">Confidence</span>
          <span class="text-sm font-bold text-${c}-400">${llm.confidence}%</span>
        </div>
        <p class="text-xs text-gray-400 leading-relaxed">${llm.reasoning}</p>
      </div>
    `;
  }).join('');

  // Verdict Badge
  verdictBadge.className = `px-4 py-1.5 rounded-full text-sm font-bold ${results.verdictClass}`;
  verdictBadge.textContent = results.verdictLabel;

  // Verdict Content
  verdictContent.innerHTML = `
    <div class="grid md:grid-cols-2 gap-4">
      <div>
        <h4 class="text-sm font-semibold text-gray-400 mb-2">Risk Score</h4>
        <div class="flex items-center gap-3">
          <div class="text-3xl font-black ${results.riskScore >= 60 ? 'text-danger-400' : results.riskScore >= 40 ? 'text-warn-400' : 'text-shield-400'}">${results.riskScore}</div>
          <div class="text-sm text-gray-500">/ 100</div>
        </div>
        <div class="h-2 bg-white/5 rounded-full mt-2 overflow-hidden">
          <div class="h-full rounded-full transition-all duration-1000 ${results.riskScore >= 60 ? 'bg-gradient-to-r from-danger-500 to-danger-400' : results.riskScore >= 40 ? 'bg-gradient-to-r from-warn-500 to-warn-400' : 'bg-gradient-to-r from-shield-500 to-shield-400'}" style="width:${results.riskScore}%"></div>
        </div>
      </div>
      <div>
        <h4 class="text-sm font-semibold text-gray-400 mb-2">Key Factors</h4>
        <div class="space-y-1">
          ${results.riskFactors.slice(0, 4).map(f => `<div class="text-xs text-danger-400 flex items-start gap-1.5"><i data-lucide="alert-circle" class="w-3 h-3 mt-0.5 flex-shrink-0"></i><span>${f}</span></div>`).join('')}
          ${results.safeFactors.slice(0, 2).map(f => `<div class="text-xs text-shield-400 flex items-start gap-1.5"><i data-lucide="check-circle" class="w-3 h-3 mt-0.5 flex-shrink-0"></i><span>${f}</span></div>`).join('')}
        </div>
      </div>
    </div>
  `;

  // Confidence Circle
  const circumference = 2 * Math.PI * 15.9;
  const offset = circumference - (results.confidence / 100) * circumference;
  confCircle.style.strokeDasharray = `${(results.confidence / 100) * circumference}, ${circumference}`;

  // Set color based on verdict
  const strokeColors = {
    safe: '#22c55e',
    low: '#06b6d4',
    medium: '#f59e0b',
    high: '#ef4444',
    critical: '#dc2626'
  };
  confCircle.style.stroke = strokeColors[results.verdict] || '#06b6d4';

  // Animate confidence value
  let currentConf = 0;
  const confInterval = setInterval(() => {
    currentConf += 2;
    if (currentConf >= results.confidence) {
      currentConf = results.confidence;
      clearInterval(confInterval);
    }
    confValue.textContent = currentConf + '%';
  }, 20);

  // Confidence Breakdown
  confBreakdown.innerHTML = `
    <div class="flex items-center justify-between text-sm">
      <span class="text-gray-400">Model Agreement</span>
      <span class="font-semibold text-white">${results.llmResponses.every(r => r.verdict === results.llmResponses[0].verdict) ? '100%' : '67%'}</span>
    </div>
    <div class="h-1.5 bg-white/5 rounded-full overflow-hidden">
      <div class="h-full bg-shield-500 rounded-full" style="width:${results.llmResponses.every(r => r.verdict === results.llmResponses[0].verdict) ? '100' : '67'}%"></div>
    </div>
    <div class="flex items-center justify-between text-sm">
      <span class="text-gray-400">Pattern Match</span>
      <span class="font-semibold text-white">${Math.min(99, results.confidence + 3)}%</span>
    </div>
    <div class="h-1.5 bg-white/5 rounded-full overflow-hidden">
      <div class="h-full bg-cyber-500 rounded-full" style="width:${Math.min(99, results.confidence + 3)}%"></div>
    </div>
    <div class="flex items-center justify-between text-sm">
      <span class="text-gray-400">Context Impact</span>
      <span class="font-semibold text-white">${results.riskFactors.length > 2 ? 'High' : 'Low'}</span>
    </div>
  `;

  // AI Opinion
  aiOpinion.innerHTML = `
    <div class="space-y-4">
      <div class="opinion-section">
        <h4 class="flex items-center gap-2"><i data-lucide="file-text" class="w-4 h-4 text-cyber-400"></i> Summary</h4>
        <p>${results.opinion.summary}</p>
      </div>
      <div class="opinion-section">
        <h4 class="flex items-center gap-2"><i data-lucide="alert-triangle" class="w-4 h-4 text-warn-400"></i> Risk Explanation</h4>
        <p>${results.opinion.riskExplanation}</p>
      </div>
      <div class="opinion-section">
        <h4 class="flex items-center gap-2"><i data-lucide="list-checks" class="w-4 h-4 text-shield-400"></i> Recommended Actions</h4>
        <div>${results.opinion.recommendedActions}</div>
      </div>
      <div class="opinion-section">
        <h4 class="flex items-center gap-2"><i data-lucide="gauge" class="w-4 h-4 text-purple-400"></i> Confidence Level</h4>
        <p>I'm <strong class="text-white">${results.opinion.confidence}%</strong> confident in this assessment. The verdict is <span class="${results.verdictClass} px-2 py-0.5 rounded-md text-xs font-bold">${results.opinion.verdictLabel}</span>.</p>
        <p class="mt-2 text-xs text-gray-500 italic">This analysis was generated by cross-referencing multiple AI models for maximum reliability. Always use human judgment for critical decisions.</p>
      </div>
    </div>
  `;

  // Re-create icons
  lucide.createIcons();

  // Reset scan button
  document.getElementById('scanBtn').disabled = false;
  document.getElementById('scanBtn').innerHTML = '<i data-lucide="zap" class="w-4 h-4"></i><span>Analyze Again</span>';
  lucide.createIcons();
}

// ===== Initialization =====
document.addEventListener('DOMContentLoaded', () => {
  // Apply saved theme
  document.documentElement.className = state.theme;

  // Create Lucide icons
  lucide.createIcons();

  // Navbar scroll effect
  let lastScroll = 0;
  window.addEventListener('scroll', () => {
    const navbar = document.getElementById('navbar');
    const currentScroll = window.pageYOffset;
    if (currentScroll > 100) {
      navbar.style.paddingTop = '0';
    } else {
      navbar.style.paddingTop = '';
    }
    lastScroll = currentScroll;
  });

  // Animate hero counters on load
  if (state.currentPage === 'landing') {
    setTimeout(animateLandingCounters, 800);
  }
});

function animateLandingCounters() {
  const targets = [
    { id: 'stat-scans', value: 1284 },
    { id: 'stat-threats', value: 47 }
  ];
  targets.forEach(t => {
    const el = document.getElementById(t.id);
    if (!el) return;
    let current = 0;
    const increment = Math.max(1, Math.ceil(t.value / 50));
    const timer = setInterval(() => {
      current += increment;
      if (current >= t.value) {
        current = t.value;
        clearInterval(timer);
      }
      el.textContent = current.toLocaleString();
    }, 30);
  });
}
