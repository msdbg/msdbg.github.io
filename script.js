function escapeHtml(text) {
  if (text === null || text === undefined) return '';
  const div = document.createElement('div');
  div.textContent = String(text);
  return div.innerHTML;
}

class Offensive32Blog {
  constructor() {
    this.posts = [];
    this.postsContainer = document.getElementById('posts-list');
    this.modal = document.getElementById('post-modal');
    this.postContent = document.getElementById('post-content');
    this.modalCloseBtn = document.getElementById('modal-close-btn');
    this.timestampInterval = null;
    this.isZooming = false;
    this.init();
  }

  async init() {
    this.timestampInterval = setInterval(() => {
      if (!this.isZooming) {
        this.updateTimestamp();
      }
    }, 1000);
    this.updateTimestamp();
    this.updateBattery();
    this.updateIpAddress();
    await this.loadPosts();
    this.setupEventListeners();
    this.handleHashChange();
    this.setupZoomDetection();
  }
  
  setupZoomDetection() {
    let lastInnerWidth = window.innerWidth;
    let lastInnerHeight = window.innerHeight;
    let zoomTimeout = null;
    
    window.addEventListener('resize', () => {
      const widthChanged = Math.abs(window.innerWidth - lastInnerWidth) > 30;
      const heightChanged = Math.abs(window.innerHeight - lastInnerHeight) > 30;
      
      if (widthChanged || heightChanged) {
        this.isZooming = true;
        if (zoomTimeout) clearTimeout(zoomTimeout);
        zoomTimeout = setTimeout(() => {
          this.isZooming = false;
          lastInnerWidth = window.innerWidth;
          lastInnerHeight = window.innerHeight;
        }, 500);
      }
    });
  }

  updateTimestamp() {
    const timestamp = document.getElementById('timestamp');
    if (timestamp) {
      const now = new Date();
      timestamp.textContent = `[${now.toISOString()}]`;
    }
  }

  async updateBattery() {
    const batteryEl = document.getElementById('battery');
    if (!batteryEl) return;

    try {
      if ('getBattery' in navigator) {
        const battery = await navigator.getBattery();
        
        const updateBatteryDisplay = () => {
          const level = Math.round(battery.level * 100);
          const charging = battery.charging ? '⚡' : '';
          batteryEl.textContent = `[BAT: ${level}%${charging}]`;
        };

        updateBatteryDisplay();
        battery.addEventListener('levelchange', updateBatteryDisplay);
        battery.addEventListener('chargingchange', updateBatteryDisplay);
      } else {
        batteryEl.textContent = '[BAT: N/A]';
      }
    } catch (error) {
      batteryEl.textContent = '[BAT: N/A]';
    }
  }

  async updateIpAddress() {
    const ipEl = document.getElementById('ip-address');
    if (!ipEl) return;

    try {
      const response = await fetch('https://api.ipify.org?format=json');
      if (!response.ok) throw new Error('IP_FETCH_FAILED');
      const data = await response.json();
      ipEl.textContent = `[IP: ${data.ip}]`;
    } catch (error) {
      ipEl.textContent = '[IP: UNKNOWN]';
    }
  }

  async loadPosts() {
        try {
            const response = await fetch('posts.json');
            if (!response.ok) throw new Error('CONNECTION_REFUSED');
            
		const data = await response.json();
		this.posts = data.posts.sort((a, b) => {
			
			if (a.pinned && !b.pinned) return -1;
			if (!a.pinned && b.pinned) return 1;
			
			return new Date(b.date) - new Date(a.date);
		});
		this.renderPosts();
        } catch (error) {
            console.error('Error:', error);
            this.postsContainer.innerHTML = `
                <div class="loading">
                    [ ERROR: UNABLE_TO_RETRIEVE_DATA ]<br>
                    <span style="color: var(--neon-magenta);">// Check connection and try again</span>
                </div>
            `;
        }
    }

    renderPosts() {
        if (this.posts.length === 0) {
            this.postsContainer.innerHTML = `
                <div class="loading">
                    [ NO_RECORDS_FOUND ]<br>
                    <span style="color: var(--text-dim);">// Database empty</span>
                </div>
            `;
            return;
        }

        this.postsContainer.innerHTML = this.posts.map(post => this.createPostCard(post)).join('');
    }

	createPostCard(post) {
	  const formattedDate = this.formatDate(post.date);
	  const escapedId = escapeHtml(post.id);
	  const escapedFile = escapeHtml(post.file);
	  const escapedTitle = escapeHtml(post.title);
	  const escapedExcerpt = escapeHtml(post.excerpt || 'Click to decrypt...');
	  const tags = post.tags
	    ? post.tags.map(tag => `<span class="tag">${escapeHtml(tag)}</span>`).join('')
	    : '';

	  return `
	    <article class="post-card" data-post-id="${escapedId}" data-post-file="${escapedFile}">
	      <div class="post-header">
	        <h3 class="post-title">${escapedTitle}</h3>
	        <span class="post-date">${formattedDate}</span>
	      </div>
	      <p class="post-excerpt">${escapedExcerpt}</p>
	      ${tags ? `<div class="post-tags">${tags}</div>` : ''}
	    </article>
	  `;
	}

    formatDate(dateString) {
        const date = new Date(dateString);
        return date.toISOString().split('T')[0];
    }

    rewriteImagePaths(html, assetsDir) {
      
      const container = document.createElement('div');
      container.innerHTML = html;
  
      
      const images = container.querySelectorAll('img');
      images.forEach(img => {
        const src = img.getAttribute('src');
        if (src && !src.startsWith('http') && !src.startsWith('data:') && !src.startsWith('/')) {
          
          
          if (assetsDir) {
            img.setAttribute('src', `assets/posts/${assetsDir}/${src}`);
          } else {
            img.setAttribute('src', `assets/posts/${src}`);
          }
        }
      });
  
      return container.innerHTML;
    }
  
    async openPost(postId) {
const post = this.posts.find(p => p.id === postId);
if (!post) return;

try {
const response = await fetch(`posts/${post.file}`);
if (!response.ok) throw new Error('DECRYPTION_FAILED');

const markdown = await response.text();

if (typeof marked === 'undefined') {
throw new Error('MARKED_LIBRARY_NOT_LOADED');
}

    const renderer = new marked.Renderer();
    renderer.heading = ({ text, depth }) => {
      const escapedText = escapeHtml(text);
      const id = escapedText
        .toLowerCase()
        .replace(/—/g, '--')
        .replace(/:/g, '--')
        .replace(/[^\w\s-]/g, '')
        .replace(/\s+/g, '-')
        .replace(/-+/g, '-')
        .trim();
      return `<h${depth} id="${escapeHtml(id)}">${escapedText}</h${depth}>`;
    };

    const htmlContent = marked.parse(markdown, { renderer });


    const processedHtml = this.rewriteImagePaths(htmlContent, post.assetsDir);

    const formattedDate = this.formatDate(post.date);
    
    const escapedTitle = escapeHtml(post.title);
    const escapedAuthor = post.author ? escapeHtml(post.author) : '';

    this.postContent.innerHTML = `
      <h1>${escapedTitle}</h1>
      <p class="post-meta">// DECRYPTED: ${formattedDate}${escapedAuthor ? ` | AUTHOR: ${escapedAuthor}` : ''}</p>
      <div class="post-body">${processedHtml}</div>
    `;

    this.modal.classList.add('active');
    document.body.style.overflow = 'hidden';

    
    window.history.pushState(null, '', `#post/${encodeURIComponent(postId)}`);
} catch (error) {
console.error('Error:', error);
let errorMessage = 'Unable to decrypt the requested data. The file may be corrupted or missing.';
if (error.message === 'MARKED_LIBRARY_NOT_LOADED') {
errorMessage = 'Markdown parser not loaded. Please check your internet connection and refresh the page.';
}
this.postContent.innerHTML = `
<h1>[ ERROR ]</h1>
<p class="post-meta">// DECRYPTION_FAILED</p>
<p>${errorMessage}</p>
`;
this.modal.classList.add('active');
}
}

    closeModal() {
        this.modal.classList.remove('active');
        document.body.style.overflow = '';
        window.history.pushState(null, '', window.location.pathname);
    }

    setupEventListeners() {

this.postsContainer.addEventListener('click', (e) => {
const card = e.target.closest('.post-card');
if (card) {
const postId = card.dataset.postId;
this.openPost(postId);
}
});


this.modal.addEventListener('click', (e) => {
if (e.target === this.modal) {
this.closeModal();
}
});


if (this.modalCloseBtn) {
this.modalCloseBtn.addEventListener('click', () => {
this.closeModal();
});
}

this.postContent.addEventListener('click', (e) => {
const link = e.target.closest('a[href^="#"]');
if (link) {
e.preventDefault();
const targetId = link.getAttribute('href').substring(1);
const targetElement = this.postContent.querySelector(`[id="${targetId}"], h1[id="${targetId}"], h2[id="${targetId}"], h3[id="${targetId}"], h4[id="${targetId}"], h5[id="${targetId}"], h6[id="${targetId}"]`);
if (targetElement) {
targetElement.scrollIntoView({ behavior: 'smooth', block: 'start' });
}
}
});


document.addEventListener('keydown', (e) => {
if (e.key === 'Escape' && this.modal.classList.contains('active')) {
this.closeModal();
}
});


window.addEventListener('popstate', () => {
this.handleHashChange();
});
}

    handleHashChange() {
      const hash = window.location.hash;
      if (hash.startsWith('#post/')) {
        
        const postId = decodeURIComponent(hash.replace('#post/', ''));
        this.openPost(postId);
      }
    }
}


function closeModal() {
    if (window.Offensive32Blog) {
        window.Offensive32Blog.closeModal();
    }
}


class GlitchCursor {
  constructor() {
    this.cursor = null;
    this.trails = [];
    this.maxTrails = 0; 
    this.mouseX = 0;
    this.mouseY = 0;
    this.lastTrailTime = 0;
    this.trailInterval = 200; 

    this.isDraggingScrollbar = false;
    this.scrollableElement = null;
    this.dragStartMouseY = 0;
    this.dragStartScrollTop = 0;
    this.dragStartThumbTop = 0;

    
    this.animationFrameId = null;
    this.lastUpdateTime = 0;
    this.updateThrottle = 16;

    
    this.isZooming = false;
    this.zoomTimeout = null;
    this.lastInnerWidth = window.innerWidth;
    this.lastInnerHeight = window.innerHeight;
    this.trailsEnabled = false; 

    this.init();
  }

  init() {
    this.createCursor();
    this.setupEventListeners();
  }

  createCursor() {
    
    this.cursor = document.createElement('div');
    this.cursor.className = 'cursor-triangle';
    this.cursor.innerHTML = `
      <div class="triangle-outline"></div>
      <div class="triangle-main"></div>
    `;
    document.body.appendChild(this.cursor);
  }

  createTrail(x, y) {
    
    if (!this.trailsEnabled || document.hidden || this.isZooming) return;

    const trail = document.createElement('div');
    trail.className = 'cursor-trail';
    trail.style.left = x + 'px';
    trail.style.top = y + 'px';
    document.body.appendChild(trail);


    setTimeout(() => {
      trail.remove();
    }, 400);

    this.trails.push(trail);


    if (this.trails.length > this.maxTrails) {
      const oldTrail = this.trails.shift();
      if (oldTrail && oldTrail.parentNode) {
        oldTrail.remove();
      }
    }
  }

  setupEventListeners() {
    
    document.addEventListener('mousemove', (e) => {
      this.mouseX = e.clientX;
      this.mouseY = e.clientY;
      
      
      const now = Date.now();
      if (now - this.lastUpdateTime >= this.updateThrottle) {
        this.lastUpdateTime = now;
        this.updateCursorPosition();
      }
    });
  
  
  document.addEventListener('scroll', (e) => {
    if (this.isDraggingScrollbar && this.scrollableElement) {
      
      this.updateCursorForScrollbarDrag();
    } else {
      this.updateCursorPosition();
    }
  }, true);


  document.addEventListener('mousedown', (e) => {
    
    const scrollbarWidth = 15; 
    
    
    const modalContent = document.querySelector('.modal-content');
    if (modalContent && modalContent.scrollHeight > modalContent.clientHeight) {
      const rect = modalContent.getBoundingClientRect();
      const isOnScrollbar = e.clientX > rect.right - scrollbarWidth &&
                            e.clientX <= rect.right &&
                            e.clientY >= rect.top &&
                            e.clientY <= rect.bottom;
      
      if (isOnScrollbar) {
        this.isDraggingScrollbar = true;
        this.scrollableElement = modalContent;
        this.dragStartMouseY = e.clientY;
        this.dragStartScrollTop = modalContent.scrollTop;
        
        const thumbHeight = (modalContent.clientHeight / modalContent.scrollHeight) * modalContent.clientHeight;
        const thumbTop = (modalContent.scrollTop / (modalContent.scrollHeight - modalContent.clientHeight)) * (modalContent.clientHeight - thumbHeight);
        this.dragStartThumbTop = rect.top + thumbTop;
        return;
      }
    }
    
    
    if (document.body.scrollHeight > window.innerHeight) {
      const isOnScrollbar = e.clientX > window.innerWidth - scrollbarWidth &&
                            e.clientX <= window.innerWidth &&
                            e.clientY >= 0 &&
                            e.clientY <= window.innerHeight;
      
      if (isOnScrollbar) {
        this.isDraggingScrollbar = true;
        this.scrollableElement = document.documentElement;
        this.dragStartMouseY = e.clientY;
        this.dragStartScrollTop = window.scrollY;
        
        const thumbHeight = (window.innerHeight / document.body.scrollHeight) * window.innerHeight;
        const thumbTop = (window.scrollY / (document.body.scrollHeight - window.innerHeight)) * (window.innerHeight - thumbHeight);
        this.dragStartThumbTop = thumbTop;
      }
    }
  });

  document.addEventListener('mouseup', () => {
    this.isDraggingScrollbar = false;
    this.scrollableElement = null;
  });
  
  
    document.addEventListener('mousedown', () => {
  if (this.cursor && !this.isZooming) {
    this.cursor.classList.add('clicking');
    
  }
});
  
  document.addEventListener('mouseup', () => {
  if (this.cursor) {
  this.cursor.classList.remove('clicking');
  }
  });
  
  
  document.addEventListener('mouseleave', () => {
  if (this.cursor) {
  this.cursor.style.opacity = '0';
  }
  });
  
  document.addEventListener('mouseenter', () => {
      if (this.cursor) {
          this.cursor.style.opacity = '1';
      }
  });

    
  document.addEventListener('touchstart', (e) => {
    const touch = e.touches[0];
    this.mouseX = touch.clientX;
    this.mouseY = touch.clientY;
    this.updateCursorPosition();

    if (this.cursor && !this.isZooming) {
      this.cursor.classList.add('clicking');
      
    }
  }, { passive: true });

    document.addEventListener('touchmove', (e) => {
      const touch = e.touches[0];
      this.mouseX = touch.clientX;
      this.mouseY = touch.clientY;
      
      const now = Date.now();
      if (now - this.lastUpdateTime >= this.updateThrottle) {
        this.lastUpdateTime = now;
        this.updateCursorPosition();
      }
    }, { passive: true });

    document.addEventListener('touchend', () => {
      if (this.cursor) {
        this.cursor.classList.remove('clicking');
      }
    }, { passive: true });

    
    window.addEventListener('resize', () => {
      const widthChanged = Math.abs(window.innerWidth - this.lastInnerWidth) > 30;
      const heightChanged = Math.abs(window.innerHeight - this.lastInnerHeight) > 30;

      if (widthChanged || heightChanged) {
        this.isZooming = true;
        this.trailsEnabled = false;
        
        
        this.trails.forEach(trail => trail.remove());
        this.trails = [];
        
        if (this.zoomTimeout) clearTimeout(this.zoomTimeout);
        this.zoomTimeout = setTimeout(() => {
          this.isZooming = false;
          this.trailsEnabled = true;
          this.lastInnerWidth = window.innerWidth;
          this.lastInnerHeight = window.innerHeight;
        }, 500);
      }
    });

    
    document.addEventListener('visibilitychange', () => {
      if (document.hidden) {
        this.isZooming = true;
        this.trailsEnabled = false;
      } else {
        this.isZooming = false;
        this.trailsEnabled = true;
      }
    });
  }

  updateCursorPosition() {
    if (this.cursor) {
      this.cursor.style.left = this.mouseX + 'px';
      this.cursor.style.top = this.mouseY + 'px';
    }
    
  }

  updateCursorForScrollbarDrag() {
    if (!this.scrollableElement) return;

    
    let currentScrollTop, maxScroll, containerHeight, containerTop;
    
    if (this.scrollableElement === document.documentElement) {
      currentScrollTop = window.scrollY;
      maxScroll = document.body.scrollHeight - window.innerHeight;
      containerHeight = window.innerHeight;
      containerTop = 0;
    } else {
      currentScrollTop = this.scrollableElement.scrollTop;
      maxScroll = this.scrollableElement.scrollHeight - this.scrollableElement.clientHeight;
      const rect = this.scrollableElement.getBoundingClientRect();
      containerHeight = rect.height;
      containerTop = rect.top;
    }

    
    const scrollableHeight = this.scrollableElement === document.documentElement
      ? document.body.scrollHeight
      : this.scrollableElement.scrollHeight;
    const thumbHeight = (containerHeight / scrollableHeight) * containerHeight;
    const thumbTop = containerTop + (currentScrollTop / maxScroll) * (containerHeight - thumbHeight);

    
    const mouseOffsetOnThumb = this.dragStartMouseY - this.dragStartThumbTop;
    const newCursorY = thumbTop + mouseOffsetOnThumb;

    
    if (this.cursor) {
      this.cursor.style.top = newCursorY + 'px';
    }

    
    this.mouseY = newCursorY;
  }
}


document.addEventListener('DOMContentLoaded', () => {
    window.Offensive32Blog = new Offensive32Blog();
    window.glitchCursor = new GlitchCursor();
    window.terminal = new Terminal();
});


class Terminal {
constructor() {
this.output = document.getElementById('terminal-output');
this.input = document.getElementById('terminal-input');
this.posts = [];
this.ipAddress = 'fetching...';
this.postsLoaded = false;
this.init();
}

async init() {
  if (window.Offensive32Blog && window.Offensive32Blog.posts && window.Offensive32Blog.posts.length > 0) {
    this.posts = window.Offensive32Blog.posts;
    this.postsLoaded = true;
  } else {
    await this.loadPosts();
  }
  await this.fetchIpAddress();
  this.setupEventListeners();
}

async loadPosts() {
if (this.postsLoaded) return;
try {
const response = await fetch('posts.json');
if (!response.ok) throw new Error('Failed to load posts');
const data = await response.json();
this.posts = data.posts.sort((a, b) => {
if (a.pinned && !b.pinned) return -1;
if (!a.pinned && b.pinned) return 1;
return new Date(b.date) - new Date(a.date);
});
this.postsLoaded = true;
} catch (error) {
console.error('Error loading posts:', error);
}
}

    async fetchIpAddress() {
if (window.Offensive32Blog && window.Offensive32Blog.cachedIp) {
this.ipAddress = window.Offensive32Blog.cachedIp;
return;
}
try {
const response = await fetch('https://api.ipify.org?format=json');
if (!response.ok) throw new Error('IP_FETCH_FAILED');
const data = await response.json();
this.ipAddress = data.ip;
if (window.Offensive32Blog) {
window.Offensive32Blog.cachedIp = data.ip;
}
} catch (error) {
this.ipAddress = 'UNKNOWN';
}
}

    setupEventListeners() {
        
        this.input.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                const command = this.input.value.trim();
                this.executeCommand(command);
                this.input.value = '';
            }
        });

        
        const terminalHeader = document.getElementById('terminal-header');
        if (terminalHeader) {
            terminalHeader.addEventListener('click', (e) => {
                this.input.focus();
            });
        }
    }

    executeCommand(command) {
        if (!command) return;

        
        this.printLine(`root@system:~# ${command}`, 'info');

        const parts = command.toLowerCase().split(' ');
        const cmd = parts[0];
        const args = parts.slice(1);

        switch (cmd) {
            case 'cat':
                this.handleCat(args);
                break;
            case 'ls':
                this.handleLs(args);
                break;
            case 'pwd':
                this.handlePwd();
                break;
            case 'whoami':
                this.handleWhoami();
                break;
            case 'clear':
                this.handleClear();
                break;
            case 'sudo':
                this.handleSudo();
                break;
            case 'help':
                this.handleHelp();
                break;
            case 'ifconfig':
            case 'ipconfig':
                this.handleIfconfig();
                break;
            case 'top':
                this.handleTop();
                break;
            default:
              this.printLine(`command not found: ${escapeHtml(cmd)}`, 'error');
              this.printLine(`Type 'help' for available commands`, 'info');
            }
    }

    handleCat(args) {
      if (args.length === 0) {
        this.printLine('usage: cat <file>', 'error');
        return;
      }
  
      const filePath = args.join(' ');
  
  
      if (filePath === '/var/log/posts.log') {
        this.displayAllPosts();
        return;
      }
  
  
      const postName = args.join(' ').replace(/^posts\//, '');
      const post = this.posts.find(p =>
        p.file.toLowerCase().includes(postName.toLowerCase()) ||
        p.id.toLowerCase() === postName.toLowerCase()
      );
  
      if (post) {
        this.displayPostContent(post);
      } else {
        this.printLine(`cat: ${escapeHtml(filePath)}: No such file or directory`, 'error');
      }
    }

    displayAllPosts() {
      this.printLine('=== /var/log/posts.log ===', 'success');
      this.printLine(`Total posts: ${this.posts.length}`, 'info');
      this.printLine('');
  
      this.posts.forEach((post, index) => {
        const date = new Date(post.date).toISOString().split('T')[0];
        const escapedTitle = escapeHtml(post.title);
        const escapedAuthor = escapeHtml(post.author || 'unknown');
        const escapedFile = escapeHtml(post.file);
        const escapedExcerpt = post.excerpt ? escapeHtml(post.excerpt) : '';
        
        this.printLine(`[${index + 1}] ${escapedTitle}`, 'info');
        this.printLine(` Date: ${date} | Author: ${escapedAuthor}`, '');
        this.printLine(` File: posts/${escapedFile}`, '');
        if (escapedExcerpt) {
          this.printLine(` Excerpt: ${escapedExcerpt}`, '');
        }
        this.printLine('');
      });
    }

  async displayPostContent(post) {
    try {
      const response = await fetch(`posts/${post.file}`);
      if (!response.ok) throw new Error('File not found');
      const content = await response.text();

      const escapedTitle = escapeHtml(post.title);
      const escapedFile = escapeHtml(post.file);
      const escapedDate = escapeHtml(post.date);

      this.printLine(`=== ${escapedTitle} ===`, 'success');
      this.printLine(`File: posts/${escapedFile}`, 'info');
      this.printLine(`Date: ${escapedDate}`, 'info');
      this.printLine('');

      const lines = content.split('\n').slice(0, 50);
      lines.forEach(line => {
        if (line.trim()) {
          this.printLine(escapeHtml(line.replace(/[#*`]/g, '')));
        }
      });

      if (content.split('\n').length > 50) {
        this.printLine('', '');
        this.printLine('... [content truncated, click on post card to read full article]', 'info');
      }
    } catch (error) {
      this.printLine(`Error reading file: ${escapeHtml(error.message)}`, 'error');
    }
  }

    async handleLs(args) {
      if (!this.postsLoaded) {
        await this.loadPosts();
      }
      
      this.printLine('Listing posts:', 'success');
      this.printLine('');
  
      if (this.posts.length === 0) {
        this.printLine('No posts found.', 'error');
      } else {
        this.posts.forEach(post => {
          const escapedId = escapeHtml(post.id);
          const escapedFile = escapeHtml(post.file);
          const encodedId = encodeURIComponent(post.id);
          this.printLine(`<a href="#post/${encodedId}" data-post-id="${escapedId}" class="post-link">${escapedFile}</a>`, '');
        });
      }
  
      this.printLine('');
      this.printLine('Contact:', 'success');
      this.printLine(' Email: contact@offensive32.com', '');
      this.printLine(' Website: Offensive32.com'');
      
    }

    handlePwd() {
        this.printLine('/home/Offensive32/blogsite', 'success');
    }

    async handleWhoami() {
        try {
            const response = await fetch('posts/WHOAMI.md');
            if (!response.ok) throw new Error('File not found');
            const content = await response.text();
            
            this.printLine('=== whoami.md ===', 'success');
            this.printLine('');
            
            
            const lines = content.split('\n');
            lines.forEach(line => {
                if (line.trim() && !line.startsWith('---')) {
                    const cleanedLine = line
                        .replace(/^#+ /g, '')
                        .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '$1: $2')
                        .replace(/[*`]/g, '');
                    this.printLine(cleanedLine, '');
                }
            });
        } catch (error) {
            this.printLine('offensive32', 'success');
            this.printLine('Cybersecurity Botique specializing in:', '');
            this.printLine('  - Malware Analysis & Reverse Engineering', '');
            this.printLine('  - Adversary Simulation', '');
            this.printLine('  - Threat Hunting & Detection Engineering', '');
        }
    }

    handleClear() {
        this.output.innerHTML = '';
    }

    handleSudo() {
        this.printLine('not that easy to get root try again', 'error');
        this.printLine('');
        this.printLine('[sudo] password for root: ********', 'info');
        this.printLine('sudo: no tty present and no askpass program specified', 'error');
    }

    handleHelp() {
        this.printLine('=== Available Commands ===', 'success');
        this.printLine('');
        this.printLine('cat <file>      - Display file contents', '');
        this.printLine('                  cat /var/log/posts.log - Show all posts', '');
        this.printLine('                  cat posts/<filename>   - Show specific post', '');
        this.printLine('ls              - List all posts with links and contact info', '');
        this.printLine('pwd             - Print current directory', '');
        this.printLine('whoami          - Display whoami.md post content', '');
        this.printLine('clear           - Clear terminal output', '');
        this.printLine('sudo            - Try to get root access', '');
        this.printLine('ifconfig        - Display IP address information', '');
        this.printLine('ipconfig        - Display IP address information', '');
        this.printLine('top             - Display system information', '');
        this.printLine('help            - Show this help message', '');
    }

    handleIfconfig() {
        this.printLine('=== Network Configuration ===', 'success');
        this.printLine('');
        this.printLine(`eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>`, 'info');
        this.printLine(`    inet ${this.ipAddress}  netmask 255.255.255.0`, '');
        this.printLine(`    ether 00:00:00:00:00:00`, '');
        this.printLine('');
        this.printLine(`lo: flags=73<UP,LOOPBACK,RUNNING>`, 'info');
        this.printLine(`    inet 127.0.0.1  netmask 255.0.0.0`, '');
    }

    handleTop() {
        const cpuCores = navigator.hardwareConcurrency || 'Unknown';
        const platform = navigator.platform;
        let osName = 'Unknown OS';

        if (platform.includes('Win')) {
            osName = 'Windows';
        } else if (platform.includes('Mac')) {
            osName = 'macOS';
        } else if (platform.includes('Linux')) {
            osName = 'Linux';
        } else if (platform.includes('iPhone') || platform.includes('iPad')) {
            osName = 'iOS';
        } else if (platform.includes('Android')) {
            osName = 'Android';
        }

        const userAgent = navigator.userAgent;
        if (userAgent.includes('Windows NT 10')) osName = 'Windows 10/11';
        else if (userAgent.includes('Windows NT 6.3')) osName = 'Windows 8.1';
        else if (userAgent.includes('Windows NT 6.2')) osName = 'Windows 8';
        else if (userAgent.includes('Windows NT 6.1')) osName = 'Windows 7';
        else if (userAgent.includes('Mac OS X')) {
            const match = userAgent.match(/Mac OS X (\d+[._]\d+)/);
            if (match) osName = `macOS ${match[1].replace('_', '.')}`;
        }

        const memory = navigator.deviceMemory ? `${navigator.deviceMemory} GB` : 'Unknown';

        
        const graphId = `cpu-graph-${Date.now()}`;

        this.printLine('=== System Information ===', 'success');
        this.printLine('');
        this.printLine(`CPU Cores: ${cpuCores}`, 'info');
        this.printLine(`OS: ${osName}`, '');
        this.printLine(`Memory: ${memory}`, '');
        this.printLine(`Platform: ${platform}`, '');
        this.printLine(`IP Address: ${this.ipAddress}`, '');
        this.printLine('');
        this.printLine(`CPU Usage:`, 'info');
        this.printLine(`<canvas id="${graphId}" class="cpu-graph"></canvas>`, '');

        
        setTimeout(() => this.startCPUGraphAnimation(graphId), 50);
    }

    startCPUGraphAnimation(canvasId) {
const canvas = document.getElementById(canvasId);
if (!canvas) return;

const ctx = canvas.getContext('2d');
canvas.width = canvas.parentElement ? canvas.parentElement.offsetWidth - 20 : 280;
canvas.height = 80;

const dataPoints = [];
const maxPoints = Math.floor(canvas.width / 3);
let animationId = null;
let isRunning = true;

const draw = () => {
if (!document.getElementById(canvasId) || !isRunning) {
if (animationId) {
cancelAnimationFrame(animationId);
}
return;
}


ctx.fillStyle = 'rgba(10, 10, 10, 0.15)';
ctx.fillRect(0, 0, canvas.width, canvas.height);


const baseUsage = 40 + Math.sin(Date.now() / 2000) * 20;
const noise = (Math.random() - 0.5) * 15;
const newValue = Math.max(5, Math.min(95, baseUsage + noise));
dataPoints.push(newValue);


if (dataPoints.length > maxPoints) {
dataPoints.shift();
}


ctx.strokeStyle = 'rgba(0, 255, 65, 0.1)';
ctx.lineWidth = 1;
for (let y = 0; y <= 100; y += 25) {
const yPos = canvas.height - (y / 100) * canvas.height;
ctx.beginPath();
ctx.moveTo(0, yPos);
ctx.lineTo(canvas.width, yPos);
ctx.stroke();
}


ctx.strokeStyle = '#00ff41';
ctx.lineWidth = 2;
ctx.shadowColor = '#00ff41';
ctx.shadowBlur = 8;
ctx.beginPath();

for (let i = 0; i < dataPoints.length; i++) {
const x = (i / maxPoints) * canvas.width;
const y = canvas.height - (dataPoints[i] / 100) * canvas.height;
if (i === 0) {
ctx.moveTo(x, y);
} else {
ctx.lineTo(x, y);
}
}

ctx.stroke();


ctx.shadowBlur = 0;
ctx.lineTo((dataPoints.length - 1) / maxPoints * canvas.width, canvas.height);
ctx.lineTo(0, canvas.height);
ctx.closePath();
ctx.fillStyle = 'rgba(0, 255, 65, 0.1)';
ctx.fill();


if (dataPoints.length > 0) {
const currentValue = Math.round(dataPoints[dataPoints.length - 1]);
ctx.fillStyle = '#00ff41';
ctx.font = '12px "Share Tech Mono", monospace';
ctx.fillText(`${currentValue}%`, canvas.width - 35, 15);
}

animationId = requestAnimationFrame(draw);
};

draw();

canvas.dataset.animationId = canvasId;
}

stopCPUGraphAnimation(canvasId) {
const canvas = document.getElementById(canvasId);
if (canvas) {
canvas.remove();
}
}

 printLine(text, type = '') {
 const line = document.createElement('div');
 line.className = `output-line ${type}`;
 line.innerHTML = text;
 this.output.appendChild(line);
 this.output.scrollTop = this.output.scrollHeight;
 }
}


class ImageZoom {
 constructor() {
 this.overlay = null;
 this.zoomedImage = null;
 this.originalImage = null;
 this.scrollPosition = 0;
 this.isZoomed = false;
 this.init();
 }

 init() {
 this.createOverlay();
 this.setupEventListeners();
 }

 createOverlay() {
 
 this.overlay = document.createElement('div');
 this.overlay.className = 'image-zoom-overlay';
 this.overlay.setAttribute('role', 'dialog');
 this.overlay.setAttribute('aria-modal', 'true');
 this.overlay.setAttribute('aria-label', 'Zoomed image view');

 
 this.zoomedImage = document.createElement('img');
 this.zoomedImage.setAttribute('alt', 'Zoomed image');
 this.overlay.appendChild(this.zoomedImage);

 document.body.appendChild(this.overlay);
 }

 setupEventListeners() {
 
 document.addEventListener('click', (e) => {
 const img = e.target.closest('.post-article img');
 if (img && !this.isZoomed) {
 e.preventDefault();
 e.stopPropagation();
 this.zoom(img);
 }
 });

 
 this.overlay.addEventListener('click', (e) => {
 if (e.target === this.overlay) {
 this.close();
 }
 });

 
 document.addEventListener('keydown', (e) => {
 if (e.key === 'Escape' && this.isZoomed) {
 this.close();
 }
 });

 
 let scrollTimeout = null;
 window.addEventListener('scroll', () => {
 if (this.isZoomed) {
 
 if (scrollTimeout) clearTimeout(scrollTimeout);
 scrollTimeout = setTimeout(() => {
 if (this.isZoomed) {
 this.close();
 }
 }, 50);
 }
 }, { passive: true });

 
 window.addEventListener('resize', () => {
 if (this.isZoomed) {
 this.close();
 }
 }, { passive: true });

 
 this.overlay.addEventListener('touchstart', (e) => {
 if (e.target === this.overlay) {
 e.preventDefault();
 this.close();
 }
 }, { passive: false });
 }

 zoom(img) {
 if (this.isZoomed) return;

 this.originalImage = img;
 this.isZoomed = true;


 this.scrollPosition = window.scrollY;

 
 const src = img.src;

 
 this.zoomedImage.src = src;
 this.zoomedImage.alt = img.alt || 'Zoomed image';

 
 img.classList.add('zooming');


 this.overlay.classList.add('active');

 
 document.body.style.overflow = 'hidden';
 }

 close() {
 if (!this.isZoomed) return;

 this.isZoomed = false;

 
 this.overlay.classList.remove('active');

 
 if (this.originalImage) {
 this.originalImage.classList.remove('zooming');
 this.originalImage = null;
 }

 
 document.body.style.overflow = '';
 }

 
 refresh() {
 
 }
}


document.addEventListener('DOMContentLoaded', () => {
 window.imageZoom = new ImageZoom();
});
