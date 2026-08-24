

a Human security researcher sits in front of a GUI tool like Burp Suite and proxies their browser traffic, sends interesting requests to a Repeater, and clicks through various tabs to configure Intruder payloads or Active Scans, then we got Autonomous AI agents they use MCP to communicate with tools, take screenshots and move mouse and click buttons on their own.

But GUI was made for humans. **AI agents are not made to move mouse and click GUI buttons.**

I experienced this bottleneck myself so decided to work on it, i call it **AgentBurp** an open-source, CLI-native, agent-first web application security testing tool.

## The GUI Bottleneck

Recently, the gap between AI and traditional tools like Burp Suite has started to close. The introduction of MCP (Model Context Protocol) and native AI extensions allow LLMs to analyze proxy history, suggest payloads, and even drive Burp Suite to some extent.

But, Using an MCP server to translate AI intent into proprietary API calls for a GUI tool works well but it is not what we asked for, really.

## Why AgentBurp

![alt text](agentburp-arch.png)
AgentBurp is a single, lightweight, compiled Go binary to test web applications security, you can just give it to any Agent running in your terminal and it will know what to do the results depends on how good your LLM agent is and your system prompt, it has the proxy, fuzzer, crawler, repeater, and more. all that your LLM Agent needs to test an app without opening Burp.

### 1. Native Autonomy (CLI & JSON)
Every single command in AgentBurp from `proxy start` to `fuzz run` to `scan active` supports a `--json` flag. It speaks the native language of AI agents and shell scripts. An autonomous agent doesn't need a translation layer, it can execute a command, instantly parse the structured JSON response, and autonomously decide what to attack next. 

### 2. Open Data via SQLite
AgentBurp stores all project data (requests, responses, endpoints, findings) in a standard **SQLite WAL database**. 
So a AI Model doesn't even need to use the AgentBurp CLI to analyze a target. It can write a SQL query `SELECT * FROM requests WHERE method = 'POST'` to analyze traffic, track false positives, or build custom dashboards. The data is open and accessible.

### 3. Real-World Hardening
Simple CLI scanners (like `gobuster` or `nuclei`) make noise when faced with modern web applications with complex steps logins, complex OAuth flows, or WAF rate limits. 
I wanted AgentBurp to not be a dumb scanner. It includes custom stateful engines (Will Improve progressively):
- **Auth Macros:** To bypass complex authentication flows.
- **Browser Sessions:** Using headless Chrome (`go-rod`) to handle heavy JavaScript and DOM-based routing.
- **Adaptations:** To automatically back off, rotate proxies, or switch transports when WAFs or rate limits are detected.

### 4. CI/CD Ready (SARIF 2.1)
Because it runs as a lightweight, CGO-free binary, you can drop it into any GitHub Action or Docker container. It natively exports findings in **SARIF 2.1**, integrating directly into GitHub Security alerts and GitLab dashboards without complex parsing.

## Conclusion

So It is the toolkit for an **autonomous AI agent** that needs a lightweight and native engine tool to do the hacking on it's own where humans just review the findings.

***

Repo Link: https://github.com/msdbg/AgentBurp 

*Check out the repository, run `make dev`, and try running your first `agentburp scan passive --all --json` to see it in action.*

-msdbg