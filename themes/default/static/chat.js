// The messenger's web page: one WebSocket, JSON frames (see the README's
// "Messenger" section). Everything a person wrote is put on the page as
// text, never as markup.
'use strict';
(function () {
  const root = document.getElementById('chat');
  if (!root) return;
  const $ = (id) => document.getElementById(id);
  const status = $('chat-status');
  const list = $('chat-list');
  const log = $('chat-log');
  const older = $('chat-older');
  const sendForm = $('chat-send');
  const inviteForm = $('chat-invite');
  const invites = $('chat-invites');
  const roomList = $('chat-rooms');
  const people = $('chat-people');
  const peopleTitle = $('chat-people-title');
  let room = null; // the room this page is in, or null
  const scheme = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const url = scheme + '//' + location.host + root.dataset.socket;

  let ws = null;
  let me = '';
  let current = null; // the open conversation's id
  let more = null; // where older messages start, or null
  let nonce = 0;
  let pages = 0; // pages of the conversation list read since the first
  const MAX_PAGES = 20;
  const conversations = new Map(); // id -> summary
  const pending = new Map(); // nonce -> the text sent, until it is answered
  const shown = new Set(); // numbers on the page, for the open conversation

  const say = (text) => { status.textContent = text; };
  const send = (frame) => { if (ws && ws.readyState === 1) ws.send(JSON.stringify(frame)); };
  const other = (c) => (c.members || []).find((m) => m !== me) || '';

  // A span as elements: text, wrapped by its marks.
  function span(s) {
    let node = document.createTextNode(s.text);
    const marks = s.marks || [];
    const wrap = (tag) => { const el = document.createElement(tag); el.appendChild(node); node = el; };
    if (marks.includes('code')) wrap('code');
    if (marks.includes('pre')) wrap('pre');
    if (marks.includes('bold')) wrap('strong');
    if (marks.includes('italic')) wrap('em');
    if (marks.includes('strike')) wrap('s');
    if (marks.includes('quote')) wrap('blockquote');
    if (marks.includes('link') && typeof s.href === 'string' && /^(https?:\/\/|\/(?!\/))/.test(s.href) && !/\\|%5c/i.test(s.href)) {
      const a = document.createElement('a');
      a.href = s.href;
      a.rel = 'noopener noreferrer';
      a.appendChild(node);
      node = a;
    }
    return node;
  }

  function line(m) {
    const li = document.createElement('li');
    li.dataset.number = m.number;
    if (m.author === me) li.className = 'mine';
    (m.body || []).forEach((s) => li.appendChild(span(s)));
    return li;
  }

  // Adds messages to the open conversation, in number order.
  function show(messages) {
    for (const m of messages) {
      if (m.conversation !== current || shown.has(m.number)) continue;
      shown.add(m.number);
      const li = line(m);
      const after = [...log.children].find((x) => Number(x.dataset.number) > m.number);
      log.insertBefore(li, after || null);
    }
    log.scrollTop = log.scrollHeight;
  }

  function drawList() {
    list.textContent = '';
    for (const c of conversations.values()) {
      const li = document.createElement('li');
      const b = document.createElement('button');
      b.type = 'button';
      const label = c.kind === 'group' ? c.name + ' (group)'
        : c.kind === 'room' ? c.name + ' (room)' : other(c);
      b.textContent = label + (c.unread > 0 ? ' (' + c.unread + ')' : '');
      if (c.unread > 0) b.className = 'unread';
      b.addEventListener('click', () => select(c.id));
      li.appendChild(b);
      list.appendChild(li);
    }
  }

  function leaveRoom() {
    if (room) send({ op: 'exit', room });
    room = null;
    people.hidden = true;
    peopleTitle.hidden = true;
  }

  function drawRooms(items) {
    roomList.textContent = '';
    for (const r of items) {
      const li = document.createElement('li');
      const b = document.createElement('button');
      b.type = 'button';
      b.textContent = r.name + ' (' + r.people + ')';
      b.addEventListener('click', () => { leaveRoom(); send({ op: 'enter', room: r.id }); });
      li.appendChild(b);
      if (r.topic) {
        const topic = document.createElement('span');
        topic.className = 'chat-topic';
        topic.textContent = r.topic;
        li.appendChild(topic);
      }
      roomList.appendChild(li);
    }
  }

  function drawPeople(items) {
    people.textContent = '';
    for (const p of items) {
      const li = document.createElement('li');
      li.textContent = p === me ? p + ' (you)' : p;
      people.appendChild(li);
    }
    people.hidden = false;
    peopleTitle.hidden = false;
  }

  function select(id) {
    if (room && room !== id) leaveRoom();
    current = id;
    more = null;
    shown.clear();
    log.textContent = '';
    sendForm.hidden = false;
    const c = conversations.get(id);
    inviteForm.hidden = !(c && c.kind === 'group');
    send({ op: 'history', conversation: id });
  }

  function markRead(id, number) {
    const c = conversations.get(id);
    if (c && number > (c.read || 0)) send({ op: 'read', conversation: id, number });
  }

  const handlers = {
    conversations(f) {
      me = f.me || me;
      $('chat-me').textContent = me;
      // The first page starts the list again; later ones add to it.
      if (f.after === null) { conversations.clear(); pages = 0; }
      for (const c of f.items || []) conversations.set(c.id, c);
      drawList();
      pages += 1;
      if (typeof f.more === 'string' && pages < MAX_PAGES) send({ op: 'conversations', after: f.more });
    },
    conversation(f) {
      if (!conversations.has(f.id)) conversations.set(f.id, { id: f.id, members: f.members, unread: 0, read: 0, last: 0 });
      drawList();
      select(f.id);
      say('');
    },
    sent(f) {
      pending.delete(f.nonce);
      say('');
    },
    history(f) {
      if (f.conversation !== current) return;
      show(f.messages || []);
      more = f.more;
      older.hidden = more === null;
      const last = (f.messages || []).reduce((n, m) => Math.max(n, m.number), 0);
      if (last) markRead(current, last);
    },
    message(f) {
      const m = f.message;
      const c = conversations.get(m.conversation) || { id: m.conversation, members: [m.author, me], unread: 0, read: 0 };
      c.last = m.number;
      if (m.conversation === current) {
        show([m]);
        markRead(current, m.number);
      } else if (m.author !== me) {
        c.unread = (c.unread || 0) + 1;
      }
      conversations.set(c.id, c);
      drawList();
    },
    read(f) {
      const c = conversations.get(f.conversation);
      if (c && f.member === me) {
        c.read = f.number;
        c.unread = Math.max(0, (c.last || 0) - f.number);
        drawList();
      }
    },
    group(f) {
      const c = conversations.get(f.id) || { id: f.id, unread: 0, read: 0, last: 0 };
      c.kind = 'group';
      c.name = f.name;
      c.count = f.count;
      const fresh = !conversations.has(f.id);
      conversations.set(f.id, c);
      drawList();
      if (fresh) { select(f.id); send({ op: 'invites' }); }
    },
    invites(f) { drawInvites(f.items || []); },
    invited() { send({ op: 'invites' }); },
    removed(f) {
      conversations.delete(f.conversation);
      if (current === f.conversation) { current = null; log.textContent = ''; sendForm.hidden = true; inviteForm.hidden = true; }
      drawList();
      say('You were taken out of a group.');
    },
    left(f) { handlers.removed(f); say('You left the group.'); },
    invite() { say('Invited.'); },
    member(f) {
      const c = conversations.get(f.conversation);
      if (!c || f.account === me) return;
      const what = { joined: 'joined', left: 'left', kicked: 'was taken out of', role: 'has a new role in', owner: 'now owns' }[f.event];
      if (what) say(f.account + ' ' + what + ' ' + (c.name || 'the group') + '.');
    },
    rooms(f) { drawRooms(f.items || []); },
    room(f) {
      if (room === f.id || current === f.id) return;
      room = f.id;
      conversations.set(f.id, { id: f.id, kind: 'room', name: f.name, unread: 0, read: 0, last: 0 });
      drawList();
      select(f.id);
      inviteForm.hidden = true;
      say('In ' + f.name + '.');
      send({ op: 'who', room: f.id });
      send({ op: 'rooms' });
    },
    entered(f) { if (f.room === room) send({ op: 'who', room }); },
    exited(f) { if (f.room === room && f.account !== me) send({ op: 'who', room }); },
    who(f) { if (f.room === room) drawPeople(f.items || []); },
    kicked(f) { outOfRoom(f.room, 'You were put out of the room.'); },
    banned(f) { outOfRoom(f.room, 'You may not come back to that room for now.'); },
    room_closed(f) { outOfRoom(f.room, 'The room was closed.'); },
    room_left(f) { outOfRoom(f.room, 'You may no longer be in that room.'); },
    muted() { say('You may not write in this room for now.'); },
    error(f) {
      say(f.message || 'Something went wrong.');
      // A refused message: its text goes back in the box, so nothing typed
      // is lost.
      const text = f.nonce && pending.get(f.nonce);
      if (text) {
        pending.delete(f.nonce);
        const box = sendForm.elements.text;
        if (!box.value) box.value = text;
      }
    },
  };

  function connect() {
    ws = new WebSocket(url);
    ws.addEventListener('open', () => { say('Connected.'); room = null; send({ op: 'invites' }); send({ op: 'rooms' }); });
    ws.addEventListener('message', (e) => {
      let f;
      try { f = JSON.parse(e.data); } catch (_) { return; }
      const h = handlers[f.op];
      if (h) h(f);
    });
    ws.addEventListener('close', () => {
      say('Disconnected. Trying again…');
      setTimeout(connect, 3000);
    });
  }

  function outOfRoom(id, why) {
    if (room !== id) return;
    room = null;
    conversations.delete(id);
    if (current === id) { current = null; log.textContent = ''; sendForm.hidden = true; }
    people.hidden = true;
    peopleTitle.hidden = true;
    drawList();
    say(why);
    send({ op: 'rooms' });
  }

  function drawInvites(items) {
    invites.textContent = '';
    for (const i of items) {
      const li = document.createElement('li');
      li.appendChild(document.createTextNode('Invited to ' + i.name + ' '));
      const join = document.createElement('button');
      join.type = 'button';
      join.textContent = 'Join';
      join.addEventListener('click', () => send({ op: 'join', conversation: i.conversation }));
      const no = document.createElement('button');
      no.type = 'button';
      no.textContent = 'Decline';
      no.addEventListener('click', () => { send({ op: 'decline', conversation: i.conversation }); li.remove(); });
      li.append(join, ' ', no);
      invites.appendChild(li);
    }
  }

  $('chat-create').addEventListener('submit', (e) => {
    e.preventDefault();
    send({ op: 'create', name: e.target.elements.name.value });
    e.target.reset();
  });
  inviteForm.addEventListener('submit', (e) => {
    e.preventDefault();
    if (current) send({ op: 'invite', conversation: current, account: e.target.elements.account.value.trim().toLowerCase() });
    e.target.reset();
  });
  $('chat-open').addEventListener('submit', (e) => {
    e.preventDefault();
    send({ op: 'open', with: e.target.elements.with.value.trim().toLowerCase() });
    e.target.reset();
  });
  sendForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const box = e.target.elements.text;
    const text = box.value;
    if (!current || !text.trim()) return;
    nonce += 1;
    pending.set(String(nonce), text);
    if (pending.size > 50) pending.delete(pending.keys().next().value);
    send({ op: 'send', conversation: current, nonce: String(nonce), body: [{ text }] });
    box.value = '';
  });
  older.addEventListener('click', () => {
    if (current && more !== null) send({ op: 'history', conversation: current, before: more });
  });

  connect();
}());
