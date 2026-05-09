<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Adaptive Shield Firewall (ASF)</title>
  <style>
    body {
      font-family: Arial, Helvetica, sans-serif;
      line-height: 1.6;
      margin: 40px;
      color: #111;
      background: #fff;
    }
    h1, h2, h3 {
      border-bottom: 1px solid #ddd;
      padding-bottom: 6px;
    }
    code, pre {
      background: #f6f8fa;
      padding: 10px;
      display: block;
      overflow-x: auto;
    }
    table {
      border-collapse: collapse;
      width: 100%;
    }
    td, th {
      border: 1px solid #ddd;
      padding: 8px;
    }
    th {
      background: #f0f0f0;
    }
  </style>
</head>

<body>

<h1>Adaptive Shield Firewall (ASF)</h1>

<p>
Adaptive Shield Firewall (ASF) is an intelligent, behavior-aware security gateway designed to protect modern web applications and APIs from unauthorized access, bot traffic, API abuse, race condition exploitation, and distributed attack patterns.
</p>

<hr/>

<h2>Overview</h2>

<p>
Traditional firewall systems rely on static rules such as IP blocking or simple rate limiting. ASF introduces a modern security architecture based on behavioral analysis, adaptive risk scoring, and real-time anomaly detection.
</p>

<p>
The system evaluates each request as a behavioral event rather than a simple network packet.
</p>

<hr/>

<h2>Core Security Model</h2>

<h3>Risk Scoring Engine</h3>

<p>
Each request is assigned a dynamic risk score:
</p>

<pre>
RiskScore =
(BotRisk * 0.2) +
(SpamRisk * 0.3) +
(RaceRisk * 0.3) +
(BehaviorRisk * 0.2)
</pre>

<p>Decision thresholds:</p>

<table>
  <tr>
    <th>Score</th>
    <th>Action</th>
  </tr>
  <tr>
    <td>0 - 40</td>
    <td>Allow</td>
  </tr>
  <tr>
    <td>40 - 70</td>
    <td>Monitor / Rate limit</td>
  </tr>
  <tr>
    <td>70 - 90</td>
    <td>Block / Challenge</td>
  </tr>
  <tr>
    <td>90 - 100</td>
    <td>Hard block / blacklist</td>
  </tr>
</table>

<hr/>

<h2>Key Features</h2>

<h3>Behavioral Analysis</h3>
<ul>
  <li>Request frequency tracking</li>
  <li>Timing pattern analysis</li>
  <li>Endpoint sequence detection</li>
  <li>Concurrency anomaly detection</li>
</ul>

<h3>Race Condition Protection</h3>
<ul>
  <li>Redis distributed locking</li>
  <li>Atomic queue processing</li>
  <li>Transaction synchronization</li>
</ul>

<h3>Bot Detection</h3>
<ul>
  <li>Detection of automation tools</li>
  <li>Headless browser identification</li>
  <li>User-agent pattern analysis</li>
</ul>

<h3>Fingerprint Engine</h3>
<ul>
  <li>IP tracking</li>
  <li>User-agent hashing</li>
  <li>Header entropy analysis</li>
  <li>Device consistency checks</li>
</ul>

<hr/>

<h2>System Architecture</h2>

<pre>
Client
  |
  v
NGINX Gateway (Rate Limit / WAF)
  |
  v
ASF Core Gateway
  |
  |-- Fingerprint Engine
  |-- Threat Detection Engine
  |-- Race Condition Protector
  |-- AI Analysis Engine
  |
  v
Application Server
  |
  v
Database (PostgreSQL + Redis)
</pre>

<hr/>

<h2>Technology Stack</h2>

<ul>
  <li>NestJS (Backend framework)</li>
  <li>TypeScript</li>
  <li>Redis (Distributed locking)</li>
  <li>PostgreSQL (Database)</li>
  <li>NGINX (Reverse proxy / WAF)</li>
  <li>Docker (Containerization)</li>
  <li>Socket.io (Realtime monitoring)</li>
</ul>

<hr/>

<h2>Installation Guide</h2>

<h3>1. Clone repository</h3>
<pre>git clone https://github.com/your-username/asf.git
cd asf</pre>

<h3>2. Install dependencies</h3>
<pre>npm install</pre>

<h3>3. Configure environment</h3>

<pre>
PORT=3000
REDIS_HOST=localhost
REDIS_PORT=6379
DATABASE_URL=postgresql://user:pass@localhost:5432/asf
JWT_SECRET=secret
</pre>

<h3>4. Start infrastructure</h3>
<pre>docker-compose up -d</pre>

<h3>5. Run application</h3>
<pre>npm run start:dev</pre>

<hr/>

<h2>API Usage</h2>

<h3>Protected Endpoint Example</h3>

<pre>
POST /redeem
Authorization: Bearer TOKEN
</pre>

<h3>Success Response</h3>

<pre>
{
  "success": true,
  "message": "Request approved",
  "riskScore": 25
}
</pre>

<h3>Blocked Response</h3>

<pre>
{
  "success": false,
  "message": "Suspicious activity detected",
  "riskScore": 87
}
</pre>

<hr/>

<h2>System Features</h2>

<ul>
  <li>Real-time threat detection</li>
  <li>AI-based anomaly scoring</li>
  <li>Race condition protection</li>
  <li>Distributed lock system</li>
  <li>IP reputation filtering</li>
  <li>Request fingerprinting</li>
  <li>Behavioral analysis engine</li>
</ul>

<hr/>

<h2>Project Structure</h2>

<pre>
apps/
  gateway/
  ai-engine/
libs/
  firewall/
  race-protection/
  threat-engine/
</pre>

<hr/>

<h2>Use Cases</h2>

<ul>
  <li>Fintech systems</li>
  <li>E-commerce platforms</li>
  <li>API gateways</li>
  <li>Enterprise backend systems</li>
  <li>Learning management systems</li>
</ul>

<hr/>

<h2>Future Improvements</h2>

<ul>
  <li>Machine learning anomaly detection</li>
  <li>Isolation Forest integration</li>
  <li>LSTM-based timing prediction</li>
  <li>GeoIP intelligence filtering</li>
  <li>Kubernetes scaling support</li>
</ul>

<hr/>

<h2>License</h2>

<p>
This project is intended for educational and research purposes in cybersecurity and backend system design.
</p>

<hr/>

<h2>Credits</h2>

<p>
Developed as a research project in modern API security, behavioral analysis systems, and distributed protection architectures.
</p>

</body>
</html>
