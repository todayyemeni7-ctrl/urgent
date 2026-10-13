/* Runtime adapter for the Urgent app: Supabase Auth + private Realtime + durable items. */
(function (w) {
  'use strict';
  var cfg = w.URGENT_CONFIG && w.URGENT_CONFIG.supabase || {};
  var client = null, sdkPromise = null, memberCache = null;
  var roomId = String(cfg.roomId || '');
  var topic = 'urgent-room:' + roomId;
  var validRoles = ['admin', 'editor', 'operator', 'reader'];
  function isReceptionPage() {
    var file = String(w.location.pathname || '').split('/').pop().toLowerCase();
    return !file || file === 'index' || file === 'index.html';
  }
  function authStorageKey() {
    if (isReceptionPage()) return 'urgent-display-auth-' + roomId;
    try { return 'sb-' + new URL(cfg.url).hostname.split('.')[0] + '-auth-token'; }
    catch (e) { return 'urgent-auth-' + roomId; }
  }

  function enabled() { return !!(cfg.enabled && cfg.url && cfg.publishableKey && roomId); }
  function hasStoredSession() {
    try {
      return !!localStorage.getItem(authStorageKey());
    } catch (e) { return false; }
  }
  function loadSdk() {
    if (w.URGENT_SUPABASE_SDK && w.URGENT_SUPABASE_SDK.createClient) return Promise.resolve(w.URGENT_SUPABASE_SDK);
    if (sdkPromise) return sdkPromise;
    sdkPromise = new Promise(function (resolve, reject) {
      var script = document.createElement('script');
      script.src = new URL('vendor/supabase.min.js', document.baseURI).href;
      script.async = true;
      script.onload = function () {
        if (w.URGENT_SUPABASE_SDK && w.URGENT_SUPABASE_SDK.createClient) resolve(w.URGENT_SUPABASE_SDK);
        else { sdkPromise = null; reject(new Error('تعذّر تحميل مكتبة Supabase')); }
      };
      script.onerror = function () { sdkPromise = null; reject(new Error('تعذّر تحميل الاتصال الآمن؛ تحقق من الشبكة ثم أعد المحاولة.')); };
      document.head.appendChild(script);
    });
    return sdkPromise;
  }
  function getClient() {
    if (!enabled()) return Promise.reject(new Error('إعداد Supabase غير مكتمل'));
    if (client) return Promise.resolve(client);
    return loadSdk().then(function (sdk) {
      if (!client) client = sdk.createClient(cfg.url, cfg.publishableKey, {
        auth: { storageKey: authStorageKey(), persistSession: true, autoRefreshToken: true, detectSessionInUrl: false },
        realtime: { params: { eventsPerSecond: 10 } }
      });
      return client;
    });
  }
  function membershipFor(user) {
    if (!user || !user.id) return Promise.reject(new Error('انتهت الجلسة؛ سجّل الدخول من جديد.'));
    return getClient().then(function (c) {
      return c.from('room_members').select('role,display_name,username,can_view_bar')
        .eq('room_id', roomId).eq('user_id', user.id).maybeSingle();
    }).then(function (r) {
      if (r.error) throw r.error;
      var row = r.data;
      if (!row || validRoles.indexOf(row.role) < 0) throw new Error('الحساب صحيح لكنه غير مضاف إلى غرفة الأخبار. اطلب من المسؤول إسناد دور لك.');
      memberCache = {
        user: user,
        role: row.role,
        name: row.display_name || row.username || (user.user_metadata && user.user_metadata.username) || 'مستخدم',
        username: row.username || '',
        canViewBar: row.can_view_bar === true
      };
      return memberCache;
    });
  }
  function currentMember() {
    if (!hasStoredSession()) return Promise.resolve(null);
    return getClient().then(function (c) { return c.auth.getSession(); }).then(function (r) {
      if (r.error) throw r.error;
      return r.data.session ? membershipFor(r.data.session.user) : null;
    });
  }
  function usernameAlias(username) {
    var value = String(username || '').trim().toLowerCase();
    if (Array.from(value).length < 3 || Array.from(value).length > 32 || !/^[\p{L}\p{N}._-]+$/u.test(value)) {
      return Promise.reject(new Error('اكتب اسم مستخدم صحيحاً أو بريد الحساب الحالي.'));
    }
    if (!w.crypto || !w.crypto.subtle) return Promise.reject(new Error('يلزم اتصال HTTPS لتسجيل الدخول باسم مستخدم.'));
    return w.crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)).then(function (digest) {
      var bytes = new Uint8Array(digest), hex = '';
      for (var i = 0; i < 20; i++) hex += bytes[i].toString(16).padStart(2, '0');
      return 'ua-' + hex + '@login.urgent.invalid';
    });
  }
  function signIn(identifier, password) {
    var login = String(identifier || '').trim();
    var emailPromise = login.indexOf('@') >= 0 ? Promise.resolve(login) : usernameAlias(login);
    return emailPromise.then(function (email) {
      return getClient().then(function (c) {
        return c.auth.signInWithPassword({ email: email, password: String(password || '') });
      });
    }).then(function (r) {
      if (r.error) throw new Error(r.error.message === 'Invalid login credentials' ? 'اسم المستخدم/البريد أو كلمة المرور غير صحيحة.' : r.error.message);
      return membershipFor(r.data.user);
    }).catch(function (err) {
      if (client && err && /غير مضاف/.test(err.message || '')) return client.auth.signOut().then(function () { throw err; });
      throw err;
    });
  }
  function signOut() {
    memberCache = null;
    return getClient().then(function (c) { return c.auth.signOut(); }).then(function (r) { if (r.error) throw r.error; });
  }

  function requirePage(options) {
    options = options || {};
    var allowed = options.roles || validRoles;
    var root = document.createElement('div');
    root.id = 'urgentAuthGate';
    root.setAttribute('role', 'status');
    root.setAttribute('aria-live', 'polite');
    root.setAttribute('aria-label', 'جارٍ استعادة جلسة غرفة الأخبار');
    root.style.cssText = 'position:fixed;inset:0;z-index:999999;display:grid;place-items:center;padding:20px;background:rgba(7,12,22,.97);direction:rtl;color:#eef2f7;font-family:inherit';
    root.innerHTML = '<div style="display:grid;place-items:center;width:100%;height:100%"><img src="/assets/logo-320.png" alt="شعار اليمن اليوم" style="display:block;width:min(68vw,220px);height:auto;max-height:55vh;object-fit:contain;padding:10px;border-radius:22px;background:#fff;box-shadow:0 18px 52px rgba(224,36,36,.22)"></div>';
    document.body.appendChild(root);
    var formHtml = '<form style="width:min(100%,420px);padding:26px;border:1px solid rgba(148,163,184,.25);border-radius:22px;background:#101827;box-shadow:0 20px 70px rgba(0,0,0,.45)">' +
      '<div style="font-size:22px;font-weight:800;margin-bottom:8px">' + (isReceptionPage() ? 'فتح شاشة الاستقبال' : 'تسجيل الدخول الآمن') + '</div>' +
      '<p style="color:#aab7c8;margin:0 0 20px;line-height:1.8">' + (isReceptionPage() ? 'أدخل اسم مستخدم وكلمة مرور حساب الشاشة. يمكنك أيضاً استخدام بريد حساب المالك الحالي. تبقى الجلسة محفوظة على هذا الجهاز حتى تسجيل الخروج.' : 'يلزم حساب معتمد لعرض أخبار غرفة التنفيذ. الحسابات الجديدة تدخل باسم مستخدم، وبريد حساب المالك الحالي ما زال صالحاً.') + '</p>' +
      '<label style="display:block;margin:0 0 14px">اسم المستخدم أو البريد<input name="identifier" type="text" autocomplete="username" autocapitalize="none" required style="box-sizing:border-box;display:block;width:100%;margin-top:7px;padding:13px;border-radius:12px;border:1px solid #3a4658;background:#0a111c;color:#fff;font:inherit;direction:auto" placeholder="اسم المستخدم أو البريد الإلكتروني"></label>' +
      '<label style="display:block;margin:0 0 18px">كلمة المرور<input name="password" type="password" autocomplete="current-password" required style="box-sizing:border-box;display:block;width:100%;margin-top:7px;padding:13px;border-radius:12px;border:1px solid #3a4658;background:#0a111c;color:#fff;font:inherit"></label>' +
      '<div data-error style="min-height:24px;color:#fca5a5;font-size:14px;margin-bottom:10px"></div>' +
      '<button type="submit" style="width:100%;padding:13px;border:0;border-radius:12px;background:#ef4444;color:#fff;font:inherit;font-weight:800;cursor:pointer">دخول</button>' +
      '<button type="button" data-signout style="display:none;margin:12px auto 0;border:0;background:none;color:#cbd5e1;text-decoration:underline;font:inherit;cursor:pointer">تسجيل الخروج وتبديل الحساب</button>' +
      '</form>';
    function showLogin(message, canSignOut) {
      root.setAttribute('role', 'dialog');
      root.setAttribute('aria-modal', 'true');
      root.removeAttribute('aria-live');
      root.setAttribute('aria-label', isReceptionPage() ? 'تسجيل الدخول إلى شاشة التنفيذ' : 'تسجيل الدخول الآمن');
      root.innerHTML = formHtml;
      var form = root.querySelector('form'), errBox = root.querySelector('[data-error]'), signout = root.querySelector('[data-signout]');
      function showError(text, allowSignOut) { errBox.textContent = text || ''; signout.style.display = allowSignOut ? 'block' : 'none'; }
      signout.addEventListener('click', function () {
        signOut().then(function () { showError('', false); form.reset(); });
      });
      form.addEventListener('submit', function (e) {
        e.preventDefault();
        var button = form.querySelector('button[type=submit]');
        button.disabled = true; button.textContent = 'جارٍ التحقق…'; showError('', false);
        signIn(form.elements.identifier.value, form.elements.password.value).then(function (m) {
          if (!finish(m)) return;
          form.reset();
        }).catch(function (err) { showError(err.message || 'تعذّر تسجيل الدخول. تحقق من الشبكة والبيانات.'); })
          .then(function () { button.disabled = false; button.textContent = 'دخول'; });
      });
      if (message) showError(message, canSignOut);
    }
    function finish(member) {
      if (allowed.indexOf(member.role) < 0) {
        showLogin('الدور الحالي (' + member.role + ') لا يملك صلاحية فتح هذه الصفحة.', true);
        return false;
      }
      root.remove();
      if (typeof options.onReady === 'function') options.onReady(member);
      return member;
    }
    if (!hasStoredSession()) {
      showLogin();
      return root;
    }
    getClient().then(function (c) { return c.auth.getSession(); }).then(function (r) {
      if (r.error) throw r.error;
      if (r.data && r.data.session) {
        return membershipFor(r.data.session.user).then(function (m) { finish(m); }).catch(function (err) { showLogin(err.message, true); });
      }
      showLogin();
    }).catch(function (err) { showLogin(err.message || 'تعذّر تهيئة الاتصال الآمن.'); });
    return root;
  }

  function createBus(opts) {
    opts = opts || {};
    var state = 'new', channel = null, barChannel = null, timer = null, retryTimer = null, membershipTimer = null, retryMs = 2000, generation = 0;
    var queue = [], active = false, stopped = false, selfMeta = null, previousPresence = {};
    var memberSnapshot = null, presencePagehideBound = false;
    var syncTimer = null, syncBusy = false, syncCursor = '', syncVersions = Object.create(null), syncErrorReported = false, syncVisibilityHandler = null;
    function setState(next, info) { state = next; if (typeof opts.onState === 'function') { try { opts.onState(next, info || {}); } catch (e) {} } }
    function callback(rel, data, empty, initial) { if (typeof opts.onMessage === 'function') { try { opts.onMessage(rel, data, !!empty, !!initial); } catch (e) { console.error(e); } } }
    function checkMembership(member) {
      var next = { user: member.user.id, role: member.role, canViewBar: member.canViewBar === true };
      if (memberSnapshot && (memberSnapshot.user !== next.user || memberSnapshot.role !== next.role || memberSnapshot.canViewBar !== next.canViewBar)) {
        w.location.reload();
        return true;
      }
      memberSnapshot = next;
      return false;
    }
    function watchMembership() {
      if (membershipTimer) return;
      membershipTimer = setInterval(function () {
        getClient().then(function (c) { return c.auth.getSession(); }).then(function (r) {
          if (r.error) throw r.error;
          if (!r.data.session) { w.location.reload(); return null; }
          return membershipFor(r.data.session.user);
        }).then(function (member) {
          if (member && checkMembership(member)) return;
        }).catch(function (err) {
          if (/غير مضاف إلى غرفة الأخبار|انتهت الجلسة/.test(err && err.message || '')) w.location.reload();
        });
      }, 30000);
    }
    function rowTopic(row) { return (row.kind === 'note' ? 'note/' : row.kind === 'bar' ? 'bar/' : 'news/') + row.item_key; }
    function rowData(row) { return { id: row.item_key, t: row.content, a: row.author || '', ts: Number(row.created_ms) || Date.now(), e: row.edited_ms == null ? undefined : Number(row.edited_ms), n: row.kind === 'note' ? 1 : undefined, bar: row.kind === 'bar' ? 1 : undefined }; }
    function stampAfter(a, b) {
      var at = Date.parse(a), bt = Date.parse(b);
      if (isFinite(at) && isFinite(bt) && at !== bt) return at > bt;
      return String(a) > String(b);
    }
    function rememberVersion(row) {
      if (!row || !row.item_key || !row.updated_at) return;
      var id = String(row.item_key), version = String(row.updated_at), previous = syncVersions[id];
      if (!previous || stampAfter(version, previous)) syncVersions[id] = version;
      if (!syncCursor || stampAfter(version, syncCursor)) syncCursor = version;
    }
    function emitRow(row, initial) {
      if (!row || !row.item_key) return;
      rememberVersion(row);
      var rel = rowTopic(row), removed = !!row.deleted_at;
      if (removed) { callback(rel, null, true, initial); return; }
      callback(rel, rowData(row), false, initial);
      callback('ack/' + row.item_key, row.ack || null, !row.ack, initial);
      callback('pin/' + row.item_key, row.pin || null, !row.pin, initial);
    }
    function handleChange(msg, isDelete, isBarChannel) {
      // بث realtime.broadcast_changes يغلّف السجل داخل msg.payload؛ تغييرات Postgres Changes تمرّره مباشرة
      var src = (msg && msg.payload && typeof msg.payload === 'object') ? msg.payload : (msg || {});
      var row = isDelete ? (src.old || src.old_record || src.record) : (src.new || src.new_record || src.record);
      if (!row) return;
      if ((row.kind === 'bar') !== !!isBarChannel) return;
      if (isDelete) row.deleted_at = new Date().toISOString();
      emitRow(row, false);
    }
    function handlePostgresChange(msg, member) {
      var eventType = String(msg && (msg.eventType || msg.event || '')).toUpperCase();
      if (eventType !== 'INSERT' && eventType !== 'UPDATE') return;
      var row = msg && (msg.new || msg.new_record || msg.record);
      if (!row || !row.item_key || !row.kind || String(row.room_id || '').toLowerCase() !== roomId.toLowerCase()) return;
      if (['news', 'note', 'bar'].indexOf(row.kind) < 0) return;
      var isBar = row.kind === 'bar';
      if (isBar && !member.canViewBar) return;
      handleChange(msg, false, isBar);
    }
    function syncIncremental() {
      if (stopped || syncBusy || (w.document && w.document.visibilityState === 'hidden')) return;
      syncBusy = true;
      getClient().then(function (db) {
        var query = db.from('urgent_items').select('room_id,item_key,kind,content,author,created_ms,edited_ms,ack,pin,deleted_at,updated_at').eq('room_id', roomId);
        if (syncCursor) query = query.gte('updated_at', syncCursor);
        return query.order('updated_at', { ascending: true }).limit(1000);
      }).then(function (r) {
        if (r.error) throw r.error;
        (r.data || []).forEach(function (row) {
          var version = String(row.updated_at || ''), previous = syncVersions[String(row.item_key)];
          if (String(row.room_id || '').toLowerCase() !== roomId.toLowerCase()) return;
          if (row.kind === 'bar' && (!memberCache || !memberCache.canViewBar)) return;
          if (version && previous === version) return;
          emitRow(row, false);
        });
        syncErrorReported = false;
      }).catch(function (err) {
        if (!syncErrorReported) { syncErrorReported = true; console.warn('[urgent-supabase-sync]', err); }
      }).then(function () { syncBusy = false; });
    }
    function startSyncWatchdog() {
      if (!syncTimer) syncTimer = setInterval(syncIncremental, 5000);
      if (!syncVisibilityHandler && w.document) {
        syncVisibilityHandler = function () { if (w.document.visibilityState === 'visible') syncIncremental(); };
        w.document.addEventListener('visibilitychange', syncVisibilityHandler);
      }
    }
    function flush() {
      if (!channel || state !== 'connected' || !queue.length) return;
      var task = queue.shift();
      perform(task.rel, task.data, task.options).then(task.resolve, function (err) { task.reject(err); reportError(err); }).then(flush);
    }
    function reportError(err) {
      console.error('[urgent-supabase]', err);
      if (typeof opts.onError === 'function') { try { opts.onError(err); } catch (e) {} }
      if (err && (err.code === '42501' || /not authorized|permission denied/i.test(err.message || '')) && w.URGENT && w.URGENT.toast) {
        w.URGENT.toast('ليس لديك صلاحية لتنفيذ هذا الإجراء.', 'warn', 6000);
      }
    }
    function perform(rel, data, options) {
      return getClient().then(function (c) {
        var kind = rel.indexOf('news/') === 0 ? 'news' : rel.indexOf('note/') === 0 ? 'note' : rel.indexOf('bar/') === 0 ? 'bar' : '';
        if (kind) {
          if (!data || !data.t) return;
          if (kind === 'bar' && (!memberCache || !memberCache.canViewBar || (memberCache.role !== 'admin' && memberCache.role !== 'editor'))) {
            return Promise.reject(new Error('لا تملك صلاحية إرسال الشريط الإخباري.'));
          }
          var key = rel.slice(kind === 'news' ? 5 : kind === 'note' ? 5 : 4);
          return c.rpc('urgent_save_item', {
            p_room: roomId,
            p_item_key: key,
            p_kind: kind,
            p_content: String(data.t),
            p_author: String(data.a || ''),
            p_created_ms: Number(data.ts) || Date.now(),
            p_edited_ms: Number(data.e) || null
          }).then(function (r) { if (r.error) throw r.error; });
        }
        if (rel.indexOf('ack/') === 0) {
          var ackKey = rel.slice(4);
          return c.rpc('urgent_ack_item', { p_room: roomId, p_item_key: ackKey, p_ack: data || null }).then(function (r) { if (r.error) throw r.error; });
        }
        if (rel.indexOf('pin/') === 0) {
          var pinKey = rel.slice(4);
          return c.rpc('urgent_pin_item', { p_room: roomId, p_item_key: pinKey, p_pin: data || null }).then(function (r) { if (r.error) throw r.error; });
        }
        if (rel === 'ctrl' && data && data.action === 'delete' && data.id) {
          return c.from('urgent_items').delete().eq('room_id', roomId).eq('item_key', String(data.id)).then(function (r) { if (r.error) throw r.error; });
        }
        if (rel === 'cfg/admins') return Promise.reject(new Error('إدارة المستخدمين انتقلت إلى Supabase Auth؛ لا تُبثّ كلمات المرور أو التجزئات.'));
        if (rel.indexOf('presence/') === 0) {
          if (data && data.off) return channel.untrack();
          return channel.track(data || selfMeta || {});
        }
        if (!channel) return Promise.reject(new Error('قناة Realtime غير متصلة'));
        return channel.send({ type: 'broadcast', event: 'message', payload: { rel: rel, data: data || null, isEmpty: !data } }).then(function (status) {
          if (status !== 'ok') throw new Error('فشل إرسال الحدث إلى Realtime (' + status + ')');
        });
      });
    }
    function publish(rel, data, options) {
      if (stopped) return false;
      return new Promise(function (resolve, reject) {
        if (queue.length >= 100) { reject(new Error('امتلأ طابور الاتصال؛ أعد المحاولة بعد استقرار الشبكة.')); return; }
        queue.push({ rel: String(rel || ''), data: data, options: options || {}, resolve: resolve, reject: reject });
        flush();
      }).catch(function (err) { reportError(err); return false; });
    }
    function onPresenceSync() {
      if (!channel) return;
      var live = {}, all = channel.presenceState() || {};
      Object.keys(all).forEach(function (key) { (all[key] || []).forEach(function (meta) { if (meta && meta.who) live[meta.who] = meta; }); });
      Object.keys(previousPresence).forEach(function (who) { if (!live[who]) callback('presence/' + who, null, true, false); });
      Object.keys(live).forEach(function (who) { callback('presence/' + who, live[who], false, false); });
      previousPresence = live;
    }
    function startPresence() {
      if (timer) { clearInterval(timer); timer = null; }
      selfMeta = { who: opts.who || 'user', role: opts.role || 'reader', name: typeof opts.name === 'function' ? opts.name() : (opts.name || ''), ts: Date.now() };
      // تسجّل العضوية عند الاشتراك مرة واحدة؛ اتصال WebSocket يحدّث الحياة بنفسه.
      // تكرار track كل 15 ثانية كان يسبب مهلات Presence تقطع قناة الأخبار والإقرارات.
      if (channel && state === 'connected') { selfMeta.ts = Date.now(); channel.track(selfMeta).catch(function () {}); }
      if (!presencePagehideBound) {
        w.addEventListener('pagehide', function () { if (channel) channel.untrack().catch(function () {}); });
        presencePagehideBound = true;
      }
      return true;
    }
    function fetchArchivePage(offset, limit) {
      offset = Math.max(0, Number(offset) || 0);
      limit = Math.min(1000, Math.max(1, Number(limit) || 500));
      return getClient().then(function (c) {
        return c.from('urgent_items').select('item_key,kind,content,author,created_ms,edited_ms,ack,pin,deleted_at')
          .eq('room_id', roomId).is('deleted_at', null)
          .order('created_ms', { ascending: false }).range(offset, offset + limit - 1);
      }).then(function (r) {
        if (r.error) throw r.error;
        var rows = r.data || [];
        rows.slice().reverse().forEach(function (row) { emitRow(row, true); });
        return { count: rows.length, nextOffset: offset + rows.length, done: rows.length < limit };
      });
    }
    function getArchiveCount() {
      return getClient().then(function (c) {
        return c.from('urgent_items').select('item_key', { count: 'exact', head: true })
          .eq('room_id', roomId).is('deleted_at', null);
      }).then(function (r) { if (r.error) throw r.error; return Number(r.count) || 0; });
    }
    function disposeChannel() {
      var old = channel, oldBars = barChannel; channel = null; barChannel = null; active = false;
      if (!old && !oldBars) return Promise.resolve();
      return getClient().then(function (c) {
        return Promise.all([old ? c.removeChannel(old) : Promise.resolve(), oldBars ? c.removeChannel(oldBars) : Promise.resolve()]);
      }).catch(function () {});
    }
    function scheduleReconnect() {
      if (stopped || retryTimer) return;
      retryTimer = setTimeout(function () {
        retryTimer = null;
        disposeChannel().then(connect);
      }, retryMs);
      retryMs = Math.min(30000, retryMs * 2);
    }
    function connect() {
      if (active || stopped) return;
      active = true;
      var myGeneration = ++generation;
      setState('connecting', { transport: 'Supabase Realtime' });
      getClient().then(function (c) {
        return c.auth.getSession().then(function (r) {
          if (!r.data.session) throw new Error('يلزم تسجيل الدخول إلى Supabase أولاً.');
          return membershipFor(r.data.session.user).then(function (member) { return { client: c, member: member }; });
        });
      }).then(function (context) {
          var c = context.client, member = context.member, snapshotStarted = false;
          if (checkMembership(member)) return;
          watchMembership();
          function connectionError(status, err) {
            if (myGeneration !== generation) return;
            active = false; setState('offline', { reason: status, message: err && err.message });
            scheduleReconnect();
          }
          function loadSnapshot() {
            if (snapshotStarted || myGeneration !== generation) return;
            snapshotStarted = true; active = false; retryMs = 2000;
            if (selfMeta) { selfMeta.ts = Date.now(); channel.track(selfMeta).catch(function () {}); }
            var snapshotLimit = Math.min(1000, Math.max(50, Number(opts.snapshotLimit) || 1000));
            getClient().then(function (db) {
              var pingAt = Date.now();
              var ping = db.from('rooms').select('id').eq('id', roomId).limit(1).then(function (r) { if (r.error) throw r.error; return Date.now() - pingAt; });
              var rows = db.from('urgent_items').select('item_key,kind,content,author,created_ms,edited_ms,ack,pin,deleted_at,updated_at').eq('room_id', roomId).is('deleted_at', null).order('created_ms', { ascending: false }).limit(snapshotLimit);
              var watermark = db.from('urgent_items').select('updated_at').eq('room_id', roomId).order('updated_at', { ascending: false }).limit(1);
              return Promise.all([rows, ping, watermark]);
            }).then(function (result) {
              var r = result[0];
              if (r.error) throw r.error;
              if (result[2].error) throw result[2].error;
              if (!syncCursor && result[2].data && result[2].data[0]) syncCursor = String(result[2].data[0].updated_at || '');
              (r.data || []).slice().reverse().forEach(function (row) { emitRow(row, true); });
              setState('connected', { transport: 'Supabase Realtime', latencyMs: result[1] });
              startSyncWatchdog();
              flush();
              if (typeof opts.onReady === 'function') { try { opts.onReady({ snapshotCount: (r.data || []).length }); } catch (e) {} }
            }).catch(function (e) { reportError(e); setState('offline', { reason: 'snapshot', message: e.message }); scheduleReconnect(); });
          }
          channel = c.channel(topic, { config: { private: true, presence: { key: opts.who || 'user' } } });
          var subscribedChannel = channel;
          channel.on('broadcast', { event: 'INSERT' }, function (m) { if (channel === subscribedChannel) handleChange(m, false, false); });
          channel.on('broadcast', { event: 'UPDATE' }, function (m) { if (channel === subscribedChannel) handleChange(m, false, false); });
          channel.on('broadcast', { event: 'DELETE' }, function (m) { if (channel === subscribedChannel) handleChange(m, true, false); });
          // DELETE is deliberately excluded: Supabase does not apply table RLS to DELETE events.
          // Deletes continue through private Broadcast topics (bars remain on the protected :bars topic).
          var postgresChangeFilter = { schema: 'public', table: 'urgent_items', filter: 'room_id=eq.' + roomId, select: ['room_id', 'item_key', 'kind', 'content', 'author', 'created_ms', 'edited_ms', 'ack', 'pin', 'deleted_at', 'updated_at'] };
          channel.on('postgres_changes', Object.assign({ event: 'INSERT' }, postgresChangeFilter), function (m) {
            if (channel === subscribedChannel) handlePostgresChange(m, member);
          });
          channel.on('postgres_changes', Object.assign({ event: 'UPDATE' }, postgresChangeFilter), function (m) {
            if (channel === subscribedChannel) handlePostgresChange(m, member);
          });
          channel.on('broadcast', { event: 'message' }, function (m) {
            if (channel !== subscribedChannel) return;
            var p = m && m.payload || {};
            if (String(p.rel || '').indexOf('bar/') === 0) return;
            callback(p.rel || '', p.data, !!p.isEmpty, false);
          });
          channel.on('presence', { event: 'sync' }, function () { if (channel === subscribedChannel) onPresenceSync(); });
          channel.subscribe(function (status, err) {
            if (myGeneration !== generation || channel !== subscribedChannel) return;
            if (status === 'SUBSCRIBED') {
              if (selfMeta) { selfMeta.ts = Date.now(); channel.track(selfMeta).catch(function () {}); }
              if (!member.canViewBar) { loadSnapshot(); return; }
              if (!barChannel) {
                barChannel = c.channel(topic + ':bars', { config: { private: true } });
                var subscribedBarChannel = barChannel;
                barChannel.on('broadcast', { event: 'INSERT' }, function (m) { if (barChannel === subscribedBarChannel) handleChange(m, false, true); });
                barChannel.on('broadcast', { event: 'UPDATE' }, function (m) { if (barChannel === subscribedBarChannel) handleChange(m, false, true); });
                barChannel.on('broadcast', { event: 'DELETE' }, function (m) { if (barChannel === subscribedBarChannel) handleChange(m, true, true); });
                barChannel.subscribe(function (barStatus, barErr) {
                  if (myGeneration !== generation || barChannel !== subscribedBarChannel) return;
                  if (barStatus === 'SUBSCRIBED') loadSnapshot();
                  else if (barStatus === 'CHANNEL_ERROR' || barStatus === 'TIMED_OUT' || barStatus === 'CLOSED') connectionError(barStatus, barErr);
                });
              }
            } else if (status === 'CHANNEL_ERROR' || status === 'TIMED_OUT' || status === 'CLOSED') {
              connectionError(status, err);
            }
          });
        }).catch(function (err) {
          if (myGeneration !== generation) return;
          active = false; reportError(err); setState('failed', { reason: 'auth-or-init', message: err.message });
          scheduleReconnect();
        });
    }
    function end() {
      stopped = true; active = false;
      generation++;
      if (timer) clearInterval(timer); if (retryTimer) clearTimeout(retryTimer); if (membershipTimer) clearInterval(membershipTimer);
      if (syncTimer) clearInterval(syncTimer); syncTimer = null;
      if (syncVisibilityHandler && w.document) w.document.removeEventListener('visibilitychange', syncVisibilityHandler);
      syncVisibilityHandler = null;
      var main = channel, bars = barChannel; channel = null; barChannel = null;
      if (main || bars) getClient().then(function (db) { return Promise.all([main ? db.removeChannel(main) : Promise.resolve(), bars ? db.removeChannel(bars) : Promise.resolve()]); }).catch(function () {});
      setState('offline', { reason: 'closed' });
    }
    function reconnectNow() {
      if (stopped || active || state === 'connected') return;
      if (retryTimer) clearTimeout(retryTimer); retryTimer = null;
      generation++;
      disposeChannel().then(connect);
    }
    return { connect: connect, startPresence: startPresence, publish: publish, fetchArchivePage: fetchArchivePage, getArchiveCount: getArchiveCount, state: function () { return state; }, isAlive: function () { return state === 'connected'; }, reconnectNow: reconnectNow, end: end };
  }

  w.URGENT_SUPABASE = {
    enabled: enabled,
    roomId: roomId,
    topic: topic,
    getClient: getClient,
    currentMember: currentMember,
    membershipFor: membershipFor,
    signIn: signIn,
    signOut: signOut,
    requirePage: requirePage,
    createBus: createBus
  };
})(window);
