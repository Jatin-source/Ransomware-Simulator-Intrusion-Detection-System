<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Ransomware Simulator & Intrusion Detection System (IDS)</title>
  <style>
    :root{
      --bg:#0b0f12;
      --card:#0f1720;
      --muted:#9aa6b2;
      --accent:#00ff7f;
      --accent-2:#3ee0ff;
      --max-width:900px;
      --radius:12px;
      --mono: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
      --sans: system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial;
    }
    html,body{height:100%;}
    body{
      margin:0;
      font-family:var(--sans);
      background:linear-gradient(180deg,#071019 0%, #08111a 60%);
      color:#e6eef3;
      display:flex;
      align-items:flex-start;
      justify-content:center;
      padding:34px 18px;
      -webkit-font-smoothing:antialiased;
      -moz-osx-font-smoothing:grayscale;
    }
    .container{
      width:100%;
      max-width:var(--max-width);
    }
    .banner{
      background:linear-gradient(90deg, rgba(0,0,0,0.45), rgba(0,0,0,0.25));
      border-radius:var(--radius);
      overflow:hidden;
      box-shadow:0 8px 30px rgba(2,8,23,0.6), inset 0 -2px 12px rgba(0,0,0,0.25);
      margin-bottom:20px;
    }
    .banner img{
      width:100%;
      display:block;
      height:220px;
      object-fit:cover;
    }
    header{
      display:flex;
      align-items:center;
      gap:18px;
      margin-bottom:18px;
    }
    h1{
      margin:0;
      font-size:20px;
      letter-spacing:0.2px;
    }
    .subtitle{
      color:var(--muted);
      margin-top:6px;
      font-size:13px;
    }
    .card{
      background:linear-gradient(180deg, rgba(255,255,255,0.02), rgba(255,255,255,0.01));
      border-radius:12px;
      padding:20px;
      box-shadow: 0 6px 22px rgba(3,8,20,0.6);
      margin-bottom:18px;
    }
    .grid{
      display:grid;
      grid-template-columns: 1fr;
      gap:12px;
    }
    @media(min-width:820px){
      .grid{ grid-template-columns: 1fr 340px; }
    }
    .meta{
      font-size:13px;
      color:var(--muted);
      line-height:1.6;
    }
    h2{ margin: 8px 0 10px 0; font-size:16px;}
    pre{
      background:#07101a;
      border-radius:8px;
      padding:12px;
      overflow:auto;
      color:#bfe9d6;
      font-family:var(--mono);
      font-size:13px;
    }
    code{ background:rgba(255,255,255,0.02); padding:2px 6px; border-radius:6px; color:#9be7ff; }
    ul{ margin:0 0 12px 18px; color:var(--muted); }
    .pill{ display:inline-block; padding:6px 10px; border-radius:999px; background:rgba(255,255,255,0.03); color:var(--accent-2); font-weight:600; font-size:13px; }
    .btn{
      display:inline-block;
      background:linear-gradient(90deg,var(--accent),#00d28a);
      color:#021217;
      padding:10px 14px;
      border-radius:10px;
      text-decoration:none;
      font-weight:700;
      box-shadow:0 4px 18px rgba(0,255,127,0.1);
    }
    footer{ color:var(--muted); font-size:13px; margin-top:18px; text-align:center;}
    .section{ margin-bottom:14px; }
    .toc{ font-size:14px; margin-bottom:12px; color:var(--muted); }
    .kbd{ background:#031118; border:1px solid rgba(255,255,255,0.03); padding:4px 8px; border-radius:6px; font-family:var(--mono); }
    .badge{ display:inline-block; padding:6px 8px; border-radius:6px; font-size:12px; color:#021217; background:var(--accent-2); margin-right:6px; font-weight:700; }
  </style>
</head>
<body>
  <div class="container">
    <div class="banner" role="banner">
      <!-- local banner file. Replace if hosting remotely -->
      <img src="/mnt/data/A_digital_graphic_design_banner_displays_the_text_.png" alt="Ransomware Simulator & IDS Banner">
    </div>

    <header>
      <div style="flex:1">
        <h1>🔐 Ransomware Simulator & Intrusion Detection System (IDS)</h1>
        <div class="subtitle">A safe, sandboxed educational demo that simulates ransomware behavior and provides a Watchdog-based IDS with GUI recovery and alerting.</div>
      </div>
      <div style="text-align:right">
        <div class="badge">Python 3.10–3.12</div><br><br>
        <a class="btn" href="#usage">Get started</a>
      </div>
    </header>

    <div class="grid">
      <main class="card">
        <section class="section">
          <h2>Overview</h2>
          <p class="meta">This project is a controlled, educational simulation that demonstrates how ransomware encrypts files and how an IDS can detect and report such activity. It is intentionally sandboxed — only the <code>sandbox/</code> folder is modified.</p>
        </section>

        <section class="section">
          <h2>Key Features</h2>
          <ul>
            <li><strong>Ransomware Simulator</strong> — encrypts files inside <code>sandbox/</code> using Fernet (AES-based).</li>
            <li><strong>Recovery GUI</strong> — Tkinter window to enter the decryption key and restore files.</li>
            <li><strong>IDS</strong> — Watchdog-based real-time monitor that detects rapid file activity, logs events and issues desktop/email alerts.</li>
            <li><strong>Safe & Reversible</strong> — only sandboxed files are affected; a backup folder and decrypt option exist.</li>
          </ul>
        </section>

        <section class="section">
          <h2 id="installation">Requirements & Installation</h2>
          <p class="meta">Tested on Ubuntu (22.04 / 24.04) with Python 3.12. Minimal requirements:</p>
          <ul>
            <li>Python <strong>3.10 – 3.12</strong></li>
            <li>System: Linux (Ubuntu recommended)</li>
            <li>System package: <code>python3-tk</code> (for Tkinter)</li>
          </ul>

          <h3>Install & setup (copy/paste)</h3>
          <pre><code>sudo apt update
sudo apt install -y python3 python3-venv python3-pip python3-tk
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
</code></pre>
        </section>

        <section class="section">
          <h2 id="usage">Usage</h2>

          <h3>1. Start the IDS (monitor)</h3>
          <pre><code># Terminal A
source venv/bin/activate
python3 monitor/fs_monitor.py
</code></pre>

          <h3>2. Run the ransomware simulation</h3>
          <pre><code># Terminal B
source venv/bin/activate
python3 simulator/safe_simulator.py --encrypt
</code></pre>
          <p class="meta">This will encrypt sandbox files, create <code>RANSOM_NOTE.txt</code> and automatically launch the recovery GUI.</p>

          <h3>3. Decrypt files</h3>
          <pre><code># via CLI
python3 simulator/safe_simulator.py --decrypt

# or open the GUI and enter the key
python3 gui/ransom_gui.py
</code></pre>
        </section>

        <section class="section">
          <h2>Configuration</h2>
          <p class="meta">The repository does NOT include sensitive credentials. Create a local <code>config/</code> folder and add these files:</p>
          <pre><code>mkdir -p config
# create config/creds.json (for email alerts)
# key.bin is auto-generated on first encryption
</code></pre>

          <h4>creds.json (example)</h4>
          <pre><code>{
  "smtp": "smtp.gmail.com",
  "port": 587,
  "user": "your.email@gmail.com",
  "pass": "your_app_password",
  "to": "recipient@example.com"
}</code></pre>
          <p class="meta">Use an app-specific password (for Gmail) and never commit <code>config/creds.json</code> or <code>config/key.bin</code> to GitHub. These are blocked by <code>.gitignore</code>.</p>
        </section>

        <section class="section">
          <h2>Project Layout</h2>
          <pre><code>Ransomware-Simulator-and-IDS/
 ├── config/              # local-only: key & creds (ignored)
 ├── docs/                # assets, sample configs
 ├── gui/                 # ransom_gui.py
 ├── monitor/             # fs_monitor.py (IDS)
 ├── sandbox/             # target folder (demo)
 ├── sandbox_backup/      # backup of clean files
 ├── simulator/           # safe_simulator.py (encrypt/decrypt)
 ├── requirements.txt
 ├── .gitignore
 └── README.md
</code></pre>
        </section>

        <section class="section">
          <h2>Security & Ethics</h2>
          <p class="meta">This tool is for education only. Run it inside a VM or isolated environment. Do not use it to target real systems or data. The MIT license protects the author from liability, but ethical responsibility remains with the user.</p>
        </section>

        <section class="section">
          <h2>License</h2>
          <p class="meta">Released under the <strong>MIT License</strong>. See <code>LICENSE</code> for full text.</p>
        </section>

      </main>

      <aside class="card">
        <div class="section">
          <div class="pill">Quick Links</div>
          <ul style="margin-top:10px;">
            <li><a href="#installation">Installation</a></li>
            <li><a href="#usage">Usage</a></li>
            <li><a href="#configuration">Configuration</a></li>
          </ul>
        </div>

        <div class="section">
          <h3>Commands</h3>
          <pre><code>git clone <repo-url>
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
</code></pre>
        </div>

        <div class="section">
          <h3>Notes</h3>
          <p class="meta">• Keep <code>config/</code> local. <br>• Use VM snapshots before running tests. <br>• Do not run on production systems.</p>
        </div>

        <div class="section">
          <h3>Support</h3>
          <p class="meta">Open an issue on GitHub or create a PR to contribute. Star the repo if you find it useful.</p>
        </div>

        <div class="section" style="margin-top:10px;">
          <h3>Contact</h3>
          <p class="meta">Maintainer: Lieutenant J</p>
        </div>
      </aside>
    </div>

    <footer>
      <p>© <span id="year"></span> Lieutenant J — Ransomware Simulator & IDS • MIT License</p>
    </footer>
  </div>

  <script>
    document.getElementById('year').textContent = new Date().getFullYear();
  </script>
</body>
</html>
