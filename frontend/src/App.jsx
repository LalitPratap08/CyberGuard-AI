import { useState } from "react";
import "./App.css";

function App() {
  const [scanning, setScanning] = useState(false);
  const [lastScan, setLastScan] = useState("Just now");

  const startScan = () => {
    setScanning(true);

    setTimeout(() => {
      setScanning(false);
      setLastScan("Just now");
    }, 3000);
  };

  return (
    <div className="app">
      {/* NAVBAR */}
      <header className="navbar">
        <div className="logo">
          <span className="shield">🛡️</span>
          CyberGuard-AI
        </div>

        <nav>
          <a href="#dashboard">Dashboard</a>
          <a href="#security">Security</a>
          <a href="#reports">Reports</a>
        </nav>
      </header>

      {/* HERO */}
      <main id="dashboard">
        <section className="hero-section">
          <p className="subtitle">AI-POWERED CYBERSECURITY</p>

          <h1>
            Protect your digital world{" "}
            <span>with intelligence.</span>
          </h1>

          <p className="description">
            CyberGuard-AI continuously analyzes your system and helps identify
            potential security threats before they become problems.
          </p>

          <button
            className="scan-button"
            onClick={startScan}
            disabled={scanning}
          >
            {scanning ? "Scanning..." : "Start Security Scan"}
          </button>

          <div className="ready">
            <div className="big-shield">🛡️</div>

            <h2>{scanning ? "Scanning system..." : "Ready to scan"}</h2>

            <p>AI security engine</p>
          </div>
        </section>

        {/* FEATURE CARDS */}
        <section id="security" className="features">
          <div className="feature-card">
            <div className="feature-icon">🔍</div>
            <h2>Threat Detection</h2>
            <p>
              Analyze activity and identify suspicious behavior.
            </p>
            <strong>Active</strong>
          </div>

          <div className="feature-card">
            <div className="feature-icon">🤖</div>
            <h2>AI Analysis</h2>
            <p>
              Use intelligent analysis to understand security risks.
            </p>
            <strong>Online</strong>
          </div>

          <div className="feature-card">
            <div className="feature-icon">🔒</div>
            <h2>System Protection</h2>
            <p>
              Monitor your security status from one dashboard.
            </p>
            <strong>Protected</strong>
          </div>
        </section>

        {/* SECURITY OVERVIEW */}
        <section className="overview">
          <h2>Security Overview</h2>

          <div className="status-grid">
            <div className="status-card">
              <p>System status</p>
              <strong>
                <span className="status-dot"></span>
                Protected
              </strong>
            </div>

            <div className="status-card">
              <p>Security engine</p>
              <strong>
                <span className="status-dot"></span>
                Running
              </strong>
            </div>

            <div className="status-card">
              <p>Threat monitoring</p>
              <strong>
                <span className="status-dot"></span>
                Active
              </strong>
            </div>

            <div className="status-card">
              <p>Last scan</p>
              <strong>
                <span className="status-dot"></span>
                {lastScan}
              </strong>
            </div>
          </div>
        </section>

        {/* REPORTS */}
        <section id="reports" className="reports">
          <h2>Security Reports</h2>

          <div className="report-box">
            <div>
              <span className="report-icon">📊</span>
              <div>
                <h3>Security analysis</h3>
                <p>
                  Your system is currently being monitored by CyberGuard-AI.
                </p>
              </div>
            </div>

            <span className="safe">SECURE</span>
          </div>

          <div className="report-box">
            <div>
              <span className="report-icon">🛡️</span>
              <div>
                <h3>Threat protection</h3>
                <p>
                  Real-time threat monitoring is active.
                </p>
              </div>
            </div>

            <span className="safe">ACTIVE</span>
          </div>
        </section>
      </main>

      {/* FOOTER */}
      <footer>
        <p>© 2026 CyberGuard-AI</p>
        <p>AI-powered cybersecurity dashboard</p>
      </footer>
    </div>
  );
}

export default App;