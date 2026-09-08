I remember one of my favorite documentaries which was released back in 2017, named [**AlphaGo**](https://www.youtube.com/watch?v=WXuK6gekU1Y&t=4s), where the world's No. 1 Go player, Lee Sedol, lost the five-game match against AlphaGo, an AI program by DeepMind.

![alt text](alphago-doc.png)

Initially, Lee believed there was no chance AlphaGo could beat him at his own game, that he mastered and dedicated his life playing.

Before the match with AlphaGo, Lee believed the AI was not at his level yet.

he said:
> "Not even close game, 5-0 for me or maybe 4-1."

His confidence was justified, as he had defeated every top human player of his generation and was regarded as one of the greatest players in Go history.

 People were also skeptical about AI playing Go, as Go is not like Chess or only about calculation, it is about human intuition and creativity. 

**How could an AI even play a game like Go that requires thinking like humans?**

The match was set. The winning prize was **$1 million dollars**, and everyone was surprised by the results, because AlphaGo won **4 games out of 5**. It was **4-1**, but not for Lee,

from world champion to the only player who managed to secure a round against AlphaGo.

Lee acknowledged that AlphaGo showed him moves that he had never discovered before. He referred to AlphaGo as an "Entity". A few years later, Lee retired and stopped competing.

During the retirement, he said:
> "I've realized that I'm not at the top even if I become the number one through frantic efforts. There is an entity that cannot be defeated."

This was not like the **Deep Blue vs. Kasparov** match that happened in 1997. In chess, supercomputers could brute-force millions of moves, and Deep Blue was like a faster calculator of chess. But Go is considered way more complex than chess.

Counting the number of possible board configurations in Go is like counting the total number of atoms in the observable universe, 

making brute force calculation mathematically impossible. So AlphaGo had to choose a different approach to mimic human intuition and cognition. DeepMind did this by building synthetic neural networks like neurons in the human brain.

---
Now we are in **2026**. It's been 10 years since the AlphaGo vs. Lee Sedol match.

AI has taken over programming now.

This is what Mikhail Mirzayanov, the founder of Codeforces, said in 2024:

> "It seems that neural networks are working technological wonders. Not long ago, they struggled with even the simplest tasks in our competitions, but now they are reaching new heights that cannot be overlooked."

https://codeforces.com/blog/entry/133941

2-year-old comments from Mikhail's post:

![alt text](codeforces-post-comments.png)

We have scaled AI to programming, and the LLMs have successfully managed to distort every popular programming leaderboard in 2026. Even a cheaper model like **DeepSeek V4 Pro** can solve **3000+ Legendary Grandmaster** problems on Codeforces.

![alt text](deepseek-codeforces-benchmarks.png)

## Memorizing Syntax Is Obsolete

AI has solved **80-year-old math problems**, discovered **decade-old vulnerabilities in the Linux kernel**, and is not far from solving real-world software engineering challenges.

So what happens to your **$100 30-day Python courses** and software development bootcamps that you signed up for?

Yes, they'll died long ago and be replaced by prompts or rebranded.

AI has produced more code in a short time. More code means more things become outdated faster. Surviving now means a willingness to unlearn outdated skills and embrace new tools instead of clinging to old ones.

So do you still need to learn programming when AI writes better code? Yes, but learning **what** has changed.

---

## From Punch Cards to C
![alt text](punchcards.png)
Imagine no libraries or compilers, and you don't even use a keyboard to write code.

If you want to flex your raw C skills to vibecoders, or you could write binary, you're not considered a genius to early programmers.

They typed code onto paper cards using a keypunch machine, where each hole meant a bit (1 or 0). Errors meant a 24-hour struggle just to catch a single typo.

Then we went to assembler to make it human-readable, like `MOV`, `ADD`, and `JMP`, mapped to CPU instructions. But we can't use the same instructions for different CPU architectures, so we went to compilers to translate these instructions to machine code.

So, from:

* Punch cards
* Assemblers
* Compilers
* Interpreters
* Runtimes

Programmers have kept inventing methods to translate code to machines, and now we're at the point where LLMs translate human language into source code.

### Did early programmers "master" 0s and 1s ?

![alt text](evolution-chart.jpg)

---

## So What's the New Tools to Learn ?

The programmer's new skill is **Adaptability**, which requires mastering how to properly communicate with agents and define context.

It's like you've been promoted to a Context Architect or an Agent Manager who manages AI-driven workflows.

Well, this section deserves a separate post to cover the newer tools.

But I still want to share some resources that you will find useful if you already are using agentic IDEs like Open Code, Codex, Claude Code, etc.
Below are the tools you must give a thought:

### System Prompts of AI Coding Tools

A community archive of the full leaked/extracted system prompts of dozens of AI coding tools (Claude Code, Cursor, Copilot, Devin, Replit, Lovable, Manus, and more), useful for reverse-engineering how these agents are instructed.

[https://github.com/x1xhlol/system-prompts-and-models-of-ai-tools](https://github.com/x1xhlol/system-prompts-and-models-of-ai-tools)

### Awesome Claude Code

A hand-curated awesome list of the best Claude Code resources: skills, agents, status lines, hooks, developer tooling, and plugins.

[https://github.com/hesreallyhim/awesome-claude-code](https://github.com/hesreallyhim/awesome-claude-code)

### Awesome Cursor Rules

A collection of ready-to-use `.mdc` Cursor Project Rules files covering frameworks, languages, testing, and security—drop them into `.cursor/rules/` to make Cursor follow project-specific conventions.

[https://github.com/PatrickJS/awesome-cursorrules](https://github.com/PatrickJS/awesome-cursorrules)

### Superpowers

An installable agentic-skills framework that forces coding agents through a disciplined workflow:

> Brainstorm → Plan → TDD → Subagent-driven execution → Two-stage review

Available as a plugin for Claude Code, Cursor, Codex, Gemini CLI, and 10+ other agents.

[https://github.com/obra/superpowers](https://github.com/obra/superpowers)

### DeepSeek Harness

An open-source, plugin-driven harness for developers who want to build, host, and customize their own specialized coding agents.

[https://github.com/deepseek-ai/deepseek-harness](https://github.com/deepseek-ai/deepseek-harness)

---

It is difficult for people to change their long-standing habits to adopt new technology, but it is necessary for the longevity of their careers. Or else,
> you can't teach an old dog new tricks

Until then.

-msdbg

* GitHub: [github.com/msdbg](https://github.com/msdbg)
* X/Twitter: [x.com/0xmsdbg](https://x.com/0xmsdbg)