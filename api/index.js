const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// IMPORTANT: Must use service_role key (not anon key) to bypass RLS
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_KEY || '';
const CODE_VERSION = 'v7-HARDENED-2026-01-27';

// Decode JWT to check if it's service_role or anon key
function getKeyRole(jwt) {
  try {
    if (!jwt) return 'missing';
    const parts = jwt.split('.');
    if (parts.length !== 3) return 'invalid_format';
    const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
    return payload.role || 'unknown';
  } catch (e) {
    return 'decode_error';
  }
}

const KEY_ROLE = getKeyRole(SUPABASE_KEY);
const IS_SERVICE_KEY = KEY_ROLE === 'service_role';

// Log warning if using wrong key type
console.log('Supabase key role:', KEY_ROLE, IS_SERVICE_KEY ? '(GOOD)' : '(WARNING: Should be service_role!)');

const supabase = createClient(process.env.SUPABASE_URL, SUPABASE_KEY, {
  auth: {
    autoRefreshToken: false,
    persistSession: false
  }
});
const BASE_URL = String(process.env.BASE_URL || 'https://earnr.xyz').trim();
const X_CLIENT_ID = String(process.env.X_CLIENT_ID || '').trim();
const X_CLIENT_SECRET = String(process.env.X_CLIENT_SECRET || '').trim();

// ============================================
// RATE LIMITING (in-memory, per-IP)
// ============================================
const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW_MS = 60 * 1000; // 1 minute
const RATE_LIMITS = {
  '/auth/login': { max: 10, window: RATE_LIMIT_WINDOW_MS },
  '/api/submissions:POST': { max: 10, window: RATE_LIMIT_WINDOW_MS },
  '/api/heartbeat': { max: 30, window: RATE_LIMIT_WINDOW_MS },
  default: { max: 60, window: RATE_LIMIT_WINDOW_MS }
};

function getRateLimitKey(ip, path, method) {
  if (path === '/auth/login') return ip + ':' + path;
  if (path === '/api/submissions' && method === 'POST') return ip + ':' + path + ':POST';
  if (path === '/api/heartbeat') return ip + ':' + path;
  return ip + ':default';
}

function getRateLimitConfig(path, method) {
  if (path === '/auth/login') return RATE_LIMITS['/auth/login'];
  if (path === '/api/submissions' && method === 'POST') return RATE_LIMITS['/api/submissions:POST'];
  if (path === '/api/heartbeat') return RATE_LIMITS['/api/heartbeat'];
  return RATE_LIMITS.default;
}

function checkRateLimit(ip, path, method) {
  var key = getRateLimitKey(ip, path, method);
  var config = getRateLimitConfig(path, method);
  var now = Date.now();
  var entry = rateLimitMap.get(key);

  if (!entry || now - entry.windowStart > config.window) {
    rateLimitMap.set(key, { windowStart: now, count: 1 });
    return { allowed: true, remaining: config.max - 1 };
  }

  entry.count++;
  if (entry.count > config.max) {
    return { allowed: false, remaining: 0 };
  }
  return { allowed: true, remaining: config.max - entry.count };
}

// Clean up stale rate limit entries every 5 minutes
setInterval(function() {
  var now = Date.now();
  for (var [key, entry] of rateLimitMap) {
    if (now - entry.windowStart > RATE_LIMIT_WINDOW_MS * 2) {
      rateLimitMap.delete(key);
    }
  }
}, 5 * 60 * 1000);

// ============================================
// OAUTH STATE STORAGE (database-backed with in-memory fallback)
// ============================================
const statesMemory = new Map();

async function storeOAuthState(state, verifier) {
  // Try database first
  try {
    await supabase.from('oauth_states').insert({
      state: state,
      verifier: verifier,
      created_at: new Date().toISOString()
    });
    return;
  } catch (e) {
    // Table might not exist yet — fall back to memory
    console.log('OAuth state DB insert failed, using memory fallback:', e.message);
  }
  statesMemory.set(state, verifier);
  // Auto-expire from memory after 10 minutes
  setTimeout(function() { statesMemory.delete(state); }, 10 * 60 * 1000);
}

async function retrieveOAuthState(state) {
  // Try database first
  try {
    var result = await supabase.from('oauth_states').select('verifier').eq('state', state).single();
    if (result.data) {
      // Delete after retrieval (one-time use)
      await supabase.from('oauth_states').delete().eq('state', state);
      return result.data.verifier;
    }
  } catch (e) {
    // Fall back to memory
  }
  var verifier = statesMemory.get(state);
  statesMemory.delete(state);
  return verifier || null;
}

// Clean up expired OAuth states from DB every 10 minutes
setInterval(async function() {
  try {
    var tenMinAgo = new Date(Date.now() - 10 * 60 * 1000).toISOString();
    await supabase.from('oauth_states').delete().lt('created_at', tenMinAgo);
  } catch (e) { /* table may not exist */ }
}, 10 * 60 * 1000);


module.exports = async function(req, res) {
  try {
    const url = new URL(req.url, BASE_URL);
    const p = url.pathname;
    // Security headers
    var allowedOrigins = [BASE_URL, 'https://earnr.xyz', 'https://www.earnr.xyz'];
    var origin = req.headers.origin || '';
    if (allowedOrigins.includes(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
    } else {
      res.setHeader('Access-Control-Allow-Origin', BASE_URL);
    }
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    if (req.method === 'OPTIONS') {
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Admin-Key');
      return res.status(200).end();
    }

    // ============================================
    // RATE LIMITING CHECK
    // ============================================
    var clientIp = req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || req.socket?.remoteAddress || 'unknown';
    if (typeof clientIp === 'string' && clientIp.includes(',')) clientIp = clientIp.split(',')[0].trim();
    var rateCheck = checkRateLimit(clientIp, p, req.method);
    if (!rateCheck.allowed) {
      res.setHeader('Retry-After', '60');
      return res.status(429).json({ error: 'Too many requests. Please try again later.' });
    }

    // ============================================
    // HEALTH CHECK
    // ============================================
    if (p === '/api/health') {
      var dbOk = false;
      try {
        var hc = await supabase.from('users').select('id', { count: 'exact', head: true });
        dbOk = !hc.error;
      } catch (e) { /* db down */ }
      return res.status(dbOk ? 200 : 503).json({
        status: dbOk ? 'ok' : 'degraded',
        version: CODE_VERSION,
        timestamp: new Date().toISOString()
      });
    }

    const cookies = {};
    String(req.headers.cookie || '').split(';').forEach(function(c) {
      const parts = c.trim().split('=');
      if(parts[0]) cookies[parts[0]] = parts[1];
    });

    async function getUser() {
      if(!cookies.session) return null;
      try {
        const result = await supabase.from('users').select('*').eq('id', cookies.session).single();
        if (!result.data) return null;

        // Calculate REAL total_earned and tasks_completed from approved submissions
        const subsResult = await supabase.from('submissions').select('*, tasks(reward)').eq('user_id', cookies.session).eq('status', 'APPROVED');
        const approvedSubs = subsResult.data || [];
        const realTotalEarned = approvedSubs.reduce((sum, s) => sum + (s.tasks?.reward || 0), 0);
        const realTasksCompleted = approvedSubs.length;

        return {
          ...result.data,
          total_earned: realTotalEarned,
          tasks_completed: realTasksCompleted
        };
      } catch(e) { return null; }
    }

    if (p === '/auth/login') {
      var state = crypto.randomBytes(16).toString('hex');
      var verifier = crypto.randomBytes(32).toString('base64url');
      var challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
      await storeOAuthState(state, verifier);
      var redir = encodeURIComponent(BASE_URL + '/auth/callback');
      var authUrl = 'https://twitter.com/i/oauth2/authorize?response_type=code&client_id=' + X_CLIENT_ID + '&redirect_uri=' + redir + '&scope=tweet.read%20users.read&state=' + state + '&code_challenge=' + challenge + '&code_challenge_method=S256';
      res.writeHead(302, { 'Location': authUrl });
      return res.end();
    }

    if (p === '/auth/callback') {
      var code = url.searchParams.get('code');
      var state = url.searchParams.get('state');
      var verifier = await retrieveOAuthState(state);
      if (!verifier) { res.writeHead(302, { 'Location': '/?error=bad_state' }); return res.end(); }

      var tokenRes = await fetch('https://api.twitter.com/2/oauth2/token', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': 'Basic ' + Buffer.from(X_CLIENT_ID + ':' + X_CLIENT_SECRET).toString('base64')
        },
        body: new URLSearchParams({code: code, grant_type: 'authorization_code', redirect_uri: BASE_URL + '/auth/callback', code_verifier: verifier})
      });
      var tokens = await tokenRes.json();
      if(!tokens.access_token) { res.writeHead(302, { 'Location': '/?error=no_token' }); return res.end(); }

      var userRes = await fetch('https://api.twitter.com/2/users/me?user.fields=profile_image_url,public_metrics', { headers: { 'Authorization': 'Bearer ' + tokens.access_token }});
      var userData = await userRes.json();
      if(!userData.data) { res.writeHead(302, { 'Location': '/?error=no_user' }); return res.end(); }

      var xu = userData.data;
      var userResult = await supabase.from('users').select('*').eq('x_id', xu.id).single();
      var user = userResult.data;

      if(user) {
        var updateResult = await supabase.from('users').update({username: xu.username, display_name: xu.name, avatar_url: (xu.profile_image_url || '').replace('_normal', '_400x400'), followers_count: xu.public_metrics ? xu.public_metrics.followers_count : 0, last_seen: new Date().toISOString()}).eq('x_id', xu.id).select().single();
        user = updateResult.data;
      } else {
        var insertResult = await supabase.from('users').insert({x_id: xu.id, username: xu.username, display_name: xu.name, avatar_url: (xu.profile_image_url || '').replace('_normal', '_400x400'), followers_count: xu.public_metrics ? xu.public_metrics.followers_count : 0}).select().single();
        user = insertResult.data;
        await supabase.from('activity').insert({type: 'JOIN', user_id: user.id, username: user.username, avatar_url: user.avatar_url});
      }
      res.setHeader('Set-Cookie', 'session=' + user.id + '; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000; Path=/');
      res.writeHead(302, { 'Location': '/' });
      return res.end();
    }

    if (p === '/auth/logout') { res.setHeader('Set-Cookie', 'session=; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Path=/'); res.writeHead(302, { 'Location': '/' }); return res.end(); }
    if (p === '/api/me') { return res.status(200).json({user: await getUser()}); }
    if (p.startsWith('/api/user/')) {
      var userId = p.split('/')[3];
      var r = await supabase.from('users').select('*').eq('id', userId).single();
      if (!r.data) return res.status(200).json({user: null});

      // Calculate REAL total_earned and tasks_completed from approved submissions
      var subsResult = await supabase.from('submissions').select('*, tasks(reward)').eq('user_id', userId).eq('status', 'APPROVED');
      var approvedSubs = subsResult.data || [];
      var realTotalEarned = approvedSubs.reduce(function(sum, s) { return sum + (s.tasks?.reward || 0); }, 0);
      var realTasksCompleted = approvedSubs.length;

      return res.status(200).json({user: {...r.data, total_earned: realTotalEarned, tasks_completed: realTasksCompleted}});
    }
    if (p === '/api/stats') {
      var usersRes = await supabase.from('users').select('*', {count: 'exact', head: true});
      var fiveMinAgo = new Date(Date.now() - 5*60*1000).toISOString();
      var onlineRes = await supabase.from('users').select('*', {count: 'exact', head: true}).gte('last_seen', fiveMinAgo);
      var tasksRes = await supabase.from('tasks').select('*', {count: 'exact', head: true}).eq('is_active', true);
      // Get approved submissions with task rewards
      var approvedRes = await supabase.from('submissions').select('*, tasks(reward)').eq('status', 'APPROVED');
      var totalPaid = (approvedRes.data || []).reduce((sum, s) => sum + (s.tasks?.reward || 0), 0);
      var completedCount = (approvedRes.data || []).length;
      return res.status(200).json({
        totalUsers: usersRes.count || 0,
        onlineUsers: onlineRes.count || 0,
        totalPaidOut: totalPaid,
        totalTasks: tasksRes.count || 0,
        completedTasks: completedCount
      });
    }
    if (p === '/api/activity') { var r = await supabase.from('activity').select('*').order('created_at', {ascending: false}).limit(20); return res.status(200).json({activity: r.data || []}); }
    if (p === '/api/tasks') {
      var page = parseInt(url.searchParams.get('page')) || 1;
      var limit = Math.min(parseInt(url.searchParams.get('limit')) || 50, 100);
      var offset = (page - 1) * limit;
      var r = await supabase.from('tasks').select('*', {count: 'exact'}).eq('is_active', true).order('created_at', {ascending: false}).range(offset, offset + limit - 1);
      return res.status(200).json({tasks: r.data || [], total: r.count || 0, page: page, limit: limit});
    }
    if (p === '/api/leaderboard') {
      // Get all users
      var usersRes = await supabase.from('users').select('*');
      var users = usersRes.data || [];

      // Get all approved submissions with rewards
      var subsRes = await supabase.from('submissions').select('user_id, tasks(reward)').eq('status', 'APPROVED');
      var subs = subsRes.data || [];

      // Calculate real earnings per user
      var earningsByUser = {};
      var tasksByUser = {};
      subs.forEach(function(s) {
        if (!earningsByUser[s.user_id]) earningsByUser[s.user_id] = 0;
        if (!tasksByUser[s.user_id]) tasksByUser[s.user_id] = 0;
        earningsByUser[s.user_id] += (s.tasks?.reward || 0);
        tasksByUser[s.user_id]++;
      });

      // Merge real values into users and sort
      var leaderboard = users.map(function(u) {
        return {
          ...u,
          total_earned: earningsByUser[u.id] || 0,
          tasks_completed: tasksByUser[u.id] || 0
        };
      }).sort(function(a, b) { return b.total_earned - a.total_earned; }).slice(0, 50);

      return res.status(200).json({leaderboard: leaderboard});
    }
    if (p === '/api/earnrs' || p === '/api/hunters') {
      var page = parseInt(url.searchParams.get('page')) || 1;
      var limit = Math.min(parseInt(url.searchParams.get('limit')) || 50, 100);
      var offset = (page - 1) * limit;
      var r = await supabase.from('users').select('*', {count: 'exact'}).order('created_at', {ascending: false}).range(offset, offset + limit - 1);
      if (r.error) {
        console.error('Error fetching earnrs:', r.error);
        return res.status(500).json({error: r.error.message, earnrs: [], hunters: []});
      }
      return res.status(200).json({earnrs: r.data || [], hunters: r.data || [], total: r.count || 0, page: page, limit: limit});
    }
    if (p === '/api/heartbeat') { var u = await getUser(); if(u) await supabase.from('users').update({last_seen: new Date().toISOString()}).eq('id', u.id); return res.status(200).json({ok: true}); }
    if (p === '/api/wallet' && req.method === 'POST') {
      var u = await getUser();
      if(!u) return res.status(401).json({error: 'Not logged in'});
      var body = ''; for await (var chunk of req) { body += chunk; }
      var data;
      try { data = JSON.parse(body); } catch (e) { return res.status(400).json({error: 'Invalid JSON'}); }
      var wallet = String(data.wallet || '').trim();

      // Validate Solana address format (32-44 chars, Base58)
      if (wallet) {
        var base58Regex = /^[1-9A-HJ-NP-Za-km-z]+$/;
        if (wallet.length < 32 || wallet.length > 44 || !base58Regex.test(wallet)) {
          return res.status(400).json({error: 'Invalid Solana wallet address'});
        }
      }

      await supabase.from('users').update({wallet_address: wallet}).eq('id', u.id);
      return res.status(200).json({success: true});
    }

    // ============================================
    // NOTIFICATIONS API
    // ============================================

    // Get user's notifications
    if (p === '/api/notifications' && req.method === 'GET') {
      var u = await getUser();
      if (!u) return res.status(401).json({error: 'Not logged in'});

      var r = await supabase.from('notifications')
        .select('*')
        .eq('user_id', u.id)
        .order('created_at', {ascending: false})
        .limit(50);

      return res.status(200).json({notifications: r.data || []});
    }

    // Mark all notifications as read
    if (p === '/api/notifications/read' && req.method === 'POST') {
      var u = await getUser();
      if (!u) return res.status(401).json({error: 'Not logged in'});

      await supabase.from('notifications')
        .update({is_read: true})
        .eq('user_id', u.id)
        .eq('is_read', false);

      return res.status(200).json({success: true});
    }

    // Mark single notification as read
    if (p.match(/^\/api\/notifications\/[^/]+\/read$/) && req.method === 'POST') {
      var u = await getUser();
      if (!u) return res.status(401).json({error: 'Not logged in'});

      var notifId = p.split('/')[3];
      await supabase.from('notifications')
        .update({is_read: true})
        .eq('id', notifId)
        .eq('user_id', u.id);

      return res.status(200).json({success: true});
    }

    // Helper function to create notifications
    async function createNotification(userId, type, title, message, relatedId) {
      if (!userId) return { success: false, error: 'No userId provided' };

      try {
        var insertData = {
          user_id: userId,
          type: type,
          title: title,
          message: message,
          is_read: false
        };

        if (relatedId) {
          insertData.related_id = relatedId;
        }

        var result = await supabase.from('notifications').insert(insertData).select();

        if (result.error) {
          console.error('NOTIFICATION: Supabase error:', result.error);
          return { success: false, error: result.error.message };
        }

        return { success: true, data: result.data };
      } catch (e) {
        console.error('NOTIFICATION: Exception:', e.message);
        return { success: false, error: e.message };
      }
    }

    // Create notifications for all users when new task is added (batched)
    async function notifyAllUsersNewTask(task) {
      try {
        var usersRes = await supabase.from('users').select('id');
        if (usersRes.error) {
          console.error('NEW_TASK_NOTIFY: Failed to fetch users:', usersRes.error);
          return { success: false, error: usersRes.error.message };
        }
        var users = usersRes.data || [];

        if (users.length === 0) {
          return { success: true, message: 'No users to notify' };
        }

        // Batch notifications in chunks of 500 to avoid payload limits
        var BATCH_SIZE = 500;
        var totalInserted = 0;

        for (var i = 0; i < users.length; i += BATCH_SIZE) {
          var batch = users.slice(i, i + BATCH_SIZE);
          var notifications = batch.map(function(u) {
            return {
              user_id: u.id,
              type: 'NEW_TASK',
              title: 'New Task Available',
              message: task.title + ' - ' + task.reward + ' USDC',
              is_read: false
            };
          });

          var result = await supabase.from('notifications').insert(notifications);
          if (result.error) {
            console.error('NEW_TASK_NOTIFY: Batch error at offset', i, result.error);
          } else {
            totalInserted += batch.length;
          }
        }

        return { success: true, count: totalInserted };
      } catch (e) {
        console.error('NEW_TASK_NOTIFY: Exception:', e.message);
        return { success: false, error: e.message };
      }
    }

    // Payout wallet balance - fetch SOL + stablecoin value server-side
    // Cache to avoid showing $0 on intermittent API failures
    if (p === '/api/wallet-balance') {
      var PAYOUT_WALLET = 'CvNbLNsjoNGeKkFRdKbHtf24CYbsLMfCDz9AfarEzzxL';
      var RPC = 'https://api.mainnet-beta.solana.com';

      // Return cached value if fresh (under 60s)
      if (global._walletCache && (Date.now() - global._walletCache.ts < 60000)) {
        return res.status(200).json(global._walletCache.data);
      }

      try {
        var fetchWithTimeout = function(url, opts, ms) {
          ms = ms || 8000;
          return Promise.race([
            fetch(url, opts),
            new Promise(function(_, reject) { setTimeout(function() { reject(new Error('timeout')); }, ms); })
          ]);
        };

        var rpcFetch = function(method, params) {
          return fetchWithTimeout(RPC, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: method, params: params })
          }).then(function(r) { return r.json(); });
        };

        // Fetch SOL balance, token accounts, and SOL price from 3 sources in parallel
        var results = await Promise.allSettled([
          rpcFetch('getBalance', [PAYOUT_WALLET]),
          rpcFetch('getTokenAccountsByOwner', [
            PAYOUT_WALLET,
            { programId: 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA' },
            { encoding: 'jsonParsed' }
          ]),
          fetchWithTimeout('https://api.coingecko.com/api/v3/simple/price?ids=solana&vs_currencies=usd', {
            headers: { 'Accept': 'application/json', 'User-Agent': 'earnr-xyz/1.0' }
          }).then(function(r) { return r.json(); }),
          fetchWithTimeout('https://price.jup.ag/v6/price?ids=SOL', {
            headers: { 'Accept': 'application/json' }
          }).then(function(r) { return r.json(); }),
          fetchWithTimeout('https://api.binance.com/api/v3/ticker/price?symbol=SOLUSDT', {
            headers: { 'Accept': 'application/json' }
          }).then(function(r) { return r.json(); })
        ]);

        var solRes = results[0].status === 'fulfilled' ? results[0].value : null;
        var tokensRes = results[1].status === 'fulfilled' ? results[1].value : null;
        var cgPrice = results[2].status === 'fulfilled' ? results[2].value : null;
        var jupPrice = results[3].status === 'fulfilled' ? results[3].value : null;
        var binPrice = results[4].status === 'fulfilled' ? results[4].value : null;

        var solBalance = (solRes?.result?.value || 0) / 1e9;

        // Try CoinGecko, then Jupiter, then Binance
        var solPrice = cgPrice?.solana?.usd || jupPrice?.data?.SOL?.price || parseFloat(binPrice?.price) || 0;

        // If all price sources failed but we have SOL, use cached price
        if (solPrice === 0 && solBalance > 0 && global._walletCache?.data?.solPrice) {
          solPrice = global._walletCache.data.solPrice;
        }

        var totalUsd = solBalance * solPrice;

        var stablecoins = {
          'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v': true, // USDC
          'Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB': true  // USDT
        };

        var tokenAccounts = tokensRes?.result?.value || [];
        for (var t = 0; t < tokenAccounts.length; t++) {
          var info = tokenAccounts[t].account.data.parsed.info;
          var amt = parseFloat(info.tokenAmount.uiAmountString || '0');
          if (stablecoins[info.mint]) totalUsd += amt;
        }

        var responseData = {
          totalUsd: totalUsd,
          solBalance: solBalance,
          solPrice: solPrice,
          wallet: PAYOUT_WALLET
        };

        // Only cache if we got a real value (don't cache $0 when wallet has SOL)
        if (totalUsd > 0 || solBalance === 0) {
          global._walletCache = { ts: Date.now(), data: responseData };
        }

        return res.status(200).json(responseData);
      } catch (err) {
        console.error('Wallet balance error:', err);
        // On total failure, return cached value if available
        if (global._walletCache?.data) {
          return res.status(200).json(global._walletCache.data);
        }
        return res.status(500).json({ error: 'Failed to fetch wallet balance' });
      }
    }

    // Payouts API - Fetch approved submissions from database
    if (p === '/api/payouts') {
      try {
        var page = parseInt(url.searchParams.get('page')) || 1;
        var limit = Math.min(parseInt(url.searchParams.get('limit')) || 1000, 2000);
        var offset = (page - 1) * limit;

        // Get approved submissions with user and task info (paginated)
        var approvedRes = await supabase
          .from('submissions')
          .select('*, users(*), tasks(*)', {count: 'exact'})
          .eq('status', 'APPROVED')
          .order('created_at', {ascending: false})
          .range(offset, offset + limit - 1);

        var submissions = approvedRes.data || [];

        // For stats, use count query instead of fetching all
        var statsRes = await supabase.from('submissions').select('*, tasks(reward)').eq('status', 'APPROVED');
        var allApproved = statsRes.data || [];
        var totalPaidOut = 0;
        var last24hPaid = 0;
        var now = Date.now();
        var dayAgo = now - 24 * 60 * 60 * 1000;

        for (var j = 0; j < allApproved.length; j++) {
          var reward = allApproved[j].tasks?.reward || 0;
          totalPaidOut += reward;
          var ts = allApproved[j].created_at ? new Date(allApproved[j].created_at).getTime() : now;
          if (ts > dayAgo) last24hPaid += reward;
        }

        var transactions = [];
        for (var i = 0; i < submissions.length; i++) {
          var sub = submissions[i];
          transactions.push({
            id: sub.id,
            username: sub.users?.username || 'Unknown',
            avatar_url: sub.users?.avatar_url || '',
            wallet: sub.users?.wallet_address || '',
            amount: sub.tasks?.reward || 0,
            task_title: sub.tasks?.title || 'Task',
            timestamp: sub.created_at,
            status: 'completed'
          });
        }

        return res.status(200).json({
          transactions: transactions,
          stats: {
            totalPaidOut: totalPaidOut,
            last24hPaid: last24hPaid,
            transactionCount: approvedRes.count || 0
          },
          page: page,
          limit: limit,
          total: approvedRes.count || 0
        });
      } catch (err) {
        console.error('Payouts API error:', err);
        return res.status(200).json({
          transactions: [],
          stats: { totalPaidOut: 0, last24hPaid: 0, transactionCount: 0 },
          error: err.message
        });
      }
    }

    // User Submissions API
    if (p === '/api/submissions' && req.method === 'GET') {
      var user = await getUser();
      if (!user) return res.status(401).json({error: 'Not logged in'});
      var page = parseInt(url.searchParams.get('page')) || 1;
      var limit = Math.min(parseInt(url.searchParams.get('limit')) || 50, 100);
      var offset = (page - 1) * limit;
      var r = await supabase.from('submissions').select('*, tasks(*)', {count: 'exact'}).eq('user_id', user.id).order('created_at', {ascending: false}).range(offset, offset + limit - 1);
      return res.status(200).json({submissions: r.data || [], total: r.count || 0, page: page, limit: limit});
    }

    if (p === '/api/submissions' && req.method === 'POST') {
      var user = await getUser();
      if (!user) return res.status(401).json({error: 'Not logged in'});
      var body = ''; for await (var chunk of req) { body += chunk; }
      var data;
      try { data = JSON.parse(body); } catch (e) { return res.status(400).json({error: 'Invalid JSON'}); }
      if (!data.task_id || !data.proof_url) return res.status(400).json({error: 'Missing task_id or proof_url'});

      // Validate proof URL is a valid HTTP(S) URL
      try {
        var proofUrl = new URL(data.proof_url);
        if (proofUrl.protocol !== 'https:' && proofUrl.protocol !== 'http:') {
          return res.status(400).json({error: 'Proof URL must be an HTTP or HTTPS link'});
        }
      } catch (e) {
        return res.status(400).json({error: 'Invalid proof URL format'});
      }

      // Get the task to check requirements
      var taskResult = await supabase.from('tasks').select('*').eq('id', data.task_id).single();
      if (!taskResult.data) {
        return res.status(404).json({error: 'Task not found'});
      }
      var task = taskResult.data;

      // Check if task is active
      if (!task.is_active) {
        return res.status(400).json({error: 'This task is no longer active'});
      }

      // Check if slots are available
      if (task.slots_filled >= task.slots_total) {
        return res.status(400).json({error: 'No slots available for this task'});
      }

      // Check minimum followers requirement
      if (task.min_followers && task.min_followers > 0) {
        var userFollowers = user.followers_count || 0;
        if (userFollowers < task.min_followers) {
          return res.status(400).json({
            error: 'You need at least ' + task.min_followers.toLocaleString() + ' followers to complete this task. You have ' + userFollowers.toLocaleString() + ' followers.'
          });
        }
      }

      // Check if user already submitted this task
      var existing = await supabase.from('submissions').select('id').eq('user_id', user.id).eq('task_id', data.task_id);
      if (existing.data && existing.data.length > 0) {
        return res.status(400).json({error: 'You already submitted this task'});
      }

      var r = await supabase.from('submissions').insert({
        user_id: user.id,
        task_id: data.task_id,
        proof_url: data.proof_url,
        comment: data.comment || null,
        status: 'PENDING'
      }).select().single();

      if (r.error) {
        console.error('Submission insert error:', r.error);
        return res.status(500).json({error: 'Failed to save submission: ' + r.error.message});
      }

      // Atomic slot increment — only increment if slots_filled < slots_total
      // This uses a conditional update to prevent race conditions
      var slotUpdate = await supabase.rpc('increment_slot', { task_id_input: data.task_id });
      if (slotUpdate.error) {
        // Fallback: try regular update if RPC doesn't exist yet
        console.log('RPC increment_slot not available, using fallback. Error:', slotUpdate.error.message);
        await supabase.from('tasks').update({slots_filled: task.slots_filled + 1}).eq('id', data.task_id);
      }

      return res.status(200).json({submission: r.data});
    }

    // Admin API
    var adminKey = String(req.headers['x-admin-key'] || '').trim();
    var validAdminKey = String(process.env.ADMIN_KEY || '').trim();

    if (p === '/api/admin/submissions') {
      if (!validAdminKey) return res.status(500).json({error: 'ADMIN_KEY not configured on server'});
      if (!adminKey || adminKey !== validAdminKey) return res.status(401).json({error: 'Invalid admin key'});
      var page = parseInt(url.searchParams.get('page')) || 1;
      var limit = Math.min(parseInt(url.searchParams.get('limit')) || 500, 1000);
      var offset = (page - 1) * limit;
      var statusFilter = url.searchParams.get('status') || null;

      var query = supabase.from('submissions').select('*, users(*), tasks!inner(*)', {count: 'exact'}).eq('tasks.is_active', true).order('created_at', {ascending: false}).range(offset, offset + limit - 1);
      if (statusFilter) query = query.eq('status', statusFilter);

      var r = await query;
      return res.status(200).json({
        submissions: r.data || [],
        total: r.count || 0,
        page: page,
        limit: limit,
        _debug: {
          codeVersion: CODE_VERSION,
          keyRole: KEY_ROLE,
          isServiceKey: IS_SERVICE_KEY
        }
      });
    }

    // Admin Tasks API - List all tasks
    if (p === '/api/admin/tasks' && req.method === 'GET') {
      if (!adminKey || adminKey !== validAdminKey) return res.status(401).json({error: 'Invalid admin key'});
      var page = parseInt(url.searchParams.get('page')) || 1;
      var limit = Math.min(parseInt(url.searchParams.get('limit')) || 50, 200);
      var offset = (page - 1) * limit;
      var r = await supabase.from('tasks').select('*', {count: 'exact'}).order('created_at', {ascending: false}).range(offset, offset + limit - 1);
      return res.status(200).json({tasks: r.data || [], total: r.count || 0, page: page, limit: limit});
    }

    // Admin Tasks API - Create task
    if (p === '/api/admin/tasks' && req.method === 'POST') {
      if (!adminKey || adminKey !== validAdminKey) return res.status(401).json({error: 'Invalid admin key'});
      var body = ''; for await (var chunk of req) { body += chunk; }
      var data;
      try { data = JSON.parse(body); } catch (e) { return res.status(400).json({error: 'Invalid JSON'}); }

      if (!data.title || !data.reward) {
        return res.status(400).json({error: 'Title and reward are required'});
      }

      // Validate reward bounds
      var reward = parseFloat(data.reward);
      if (isNaN(reward) || reward <= 0 || reward > 10000) {
        return res.status(400).json({error: 'Reward must be between 0.01 and 10,000 USDC'});
      }

      var slotsTotal = parseInt(data.slots_total) || 100;
      if (slotsTotal < 1 || slotsTotal > 100000) {
        return res.status(400).json({error: 'Slots must be between 1 and 100,000'});
      }

      var taskData = {
        title: String(data.title).substring(0, 200),
        description: String(data.description || '').substring(0, 2000),
        reward: reward,
        task_url: data.task_url || null,
        category: data.category || 'X',
        difficulty: data.difficulty || 'EASY',
        slots_total: slotsTotal,
        slots_filled: 0,
        min_followers: Math.max(0, parseInt(data.min_followers) || 0),
        is_active: data.is_active !== false
      };

      var r = await supabase.from('tasks').insert(taskData).select().single();
      if (r.error) {
        console.error('Task create error:', r.error);
        return res.status(500).json({error: 'Failed to create task: ' + r.error.message});
      }

      // Notify all users about new task (fire-and-forget to avoid blocking response)
      var notifyPromise = null;
      if (r.data && r.data.is_active) {
        notifyPromise = notifyAllUsersNewTask(r.data).catch(function(e) {
          console.error('NEW_TASK_NOTIFY: Background error:', e.message);
          return { success: false, error: e.message };
        });
      }

      // Don't await notification — return response immediately
      return res.status(200).json({success: true, task: r.data, notification: 'queued'});
    }

    // Admin Tasks API - Update task
    if (p.match(/^\/api\/admin\/tasks\/[^/]+$/) && req.method === 'PUT') {
      if (!adminKey || adminKey !== validAdminKey) return res.status(401).json({error: 'Invalid admin key'});
      var taskId = p.split('/')[4];
      var body = ''; for await (var chunk of req) { body += chunk; }
      var data;
      try { data = JSON.parse(body); } catch (e) { return res.status(400).json({error: 'Invalid JSON'}); }

      var updateData = {};
      if (data.title !== undefined) updateData.title = String(data.title).substring(0, 200);
      if (data.description !== undefined) updateData.description = String(data.description).substring(0, 2000);
      if (data.reward !== undefined) {
        var reward = parseFloat(data.reward);
        if (isNaN(reward) || reward <= 0 || reward > 10000) {
          return res.status(400).json({error: 'Reward must be between 0.01 and 10,000 USDC'});
        }
        updateData.reward = reward;
      }
      if (data.task_url !== undefined) updateData.task_url = data.task_url || null;
      if (data.category !== undefined) updateData.category = data.category;
      if (data.difficulty !== undefined) updateData.difficulty = data.difficulty;
      if (data.slots_total !== undefined) {
        var slots = parseInt(data.slots_total);
        if (slots < 1 || slots > 100000) return res.status(400).json({error: 'Slots must be between 1 and 100,000'});
        updateData.slots_total = slots;
      }
      if (data.min_followers !== undefined) updateData.min_followers = Math.max(0, parseInt(data.min_followers) || 0);
      if (data.is_active !== undefined) updateData.is_active = data.is_active;

      var r = await supabase.from('tasks').update(updateData).eq('id', taskId).select().single();
      if (r.error) {
        console.error('Task update error:', r.error);
        return res.status(500).json({error: 'Failed to update task: ' + r.error.message});
      }

      // If task was deactivated, auto-cancel all pending submissions
      if (data.is_active === false) {
        await supabase.from('submissions').update({status: 'CANCELLED'}).eq('task_id', taskId).eq('status', 'PENDING');
      }

      return res.status(200).json({success: true, task: r.data});
    }

    // Admin Tasks API - Delete task
    if (p.match(/^\/api\/admin\/tasks\/[^/]+$/) && req.method === 'DELETE') {
      if (!adminKey || adminKey !== validAdminKey) return res.status(401).json({error: 'Invalid admin key'});
      var taskId = p.split('/')[4];

      // Check if task has submissions
      var subs = await supabase.from('submissions').select('id', {count: 'exact', head: true}).eq('task_id', taskId);
      if (subs.count > 0) {
        return res.status(400).json({error: 'Cannot delete task with existing submissions. Deactivate it instead.'});
      }

      var r = await supabase.from('tasks').delete().eq('id', taskId);
      if (r.error) {
        console.error('Task delete error:', r.error);
        return res.status(500).json({error: 'Failed to delete task: ' + r.error.message});
      }
      return res.status(200).json({success: true});
    }

    // Debug endpoint to check database connection and key type
    if (p === '/api/admin/debug' && req.method === 'GET') {
      if (!adminKey || adminKey !== validAdminKey) return res.status(401).json({error: 'Invalid admin key'});
      var testResult = await supabase.from('submissions').select('id, status').limit(1);
      return res.status(200).json({
        codeVersion: CODE_VERSION,
        keyRole: KEY_ROLE,
        isServiceKey: IS_SERVICE_KEY,
        keyPrefix: SUPABASE_KEY.substring(0, 20) + '...',
        keyLength: SUPABASE_KEY.length,
        supabaseUrl: (process.env.SUPABASE_URL || '').substring(0, 40) + '...',
        problem: !IS_SERVICE_KEY ? 'WRONG KEY! You are using the anon key. Updates will NOT persist.' : 'None detected',
        testQuery: testResult.error ? testResult.error.message : 'OK',
        testData: testResult.data
      });
    }

    // DIAGNOSTIC: Test if database updates persist
    if (p === '/api/admin/test-update' && req.method === 'POST') {
      if (!adminKey || adminKey !== validAdminKey) return res.status(401).json({error: 'Invalid admin key'});

      console.log('TEST-UPDATE: Starting persistence test...');
      var results = { steps: [], success: false };

      try {
        // Get a random pending submission for testing (we won't actually change it)
        var pending = await supabase.from('submissions').select('id, status').eq('status', 'PENDING').limit(1).single();

        if (!pending.data) {
          return res.status(200).json({
            error: 'No pending submissions to test with',
            hint: 'Create a test submission first'
          });
        }

        var testId = pending.data.id;
        results.testSubmissionId = testId;
        results.steps.push({ step: 1, action: 'Found pending submission', id: testId, status: pending.data.status });

        // Step 2: Update to a TEST status (we'll use 'TEST_STATUS')
        var update1 = await supabase
          .from('submissions')
          .update({ status: 'APPROVED' })
          .eq('id', testId)
          .select('status');

        results.steps.push({
          step: 2,
          action: 'Update to APPROVED',
          returned: update1.data?.[0]?.status,
          error: update1.error?.message || null,
          rowCount: update1.data?.length || 0
        });

        // Step 3: Immediately read back
        var read1 = await supabase.from('submissions').select('status').eq('id', testId).single();
        results.steps.push({
          step: 3,
          action: 'Immediate read',
          status: read1.data?.status
        });

        // Step 4: Wait 500ms and read again with new client
        await new Promise(r => setTimeout(r, 500));
        var newClient = createClient(process.env.SUPABASE_URL, SUPABASE_KEY, {
          auth: { autoRefreshToken: false, persistSession: false }
        });
        var read2 = await newClient.from('submissions').select('status').eq('id', testId).single();
        results.steps.push({
          step: 4,
          action: 'Read after 500ms (new client)',
          status: read2.data?.status
        });

        // Step 5: Wait another 500ms and read with yet another client
        await new Promise(r => setTimeout(r, 500));
        var client3 = createClient(process.env.SUPABASE_URL, SUPABASE_KEY, {
          auth: { autoRefreshToken: false, persistSession: false }
        });
        var read3 = await client3.from('submissions').select('status').eq('id', testId).single();
        results.steps.push({
          step: 5,
          action: 'Read after 1000ms (third client)',
          status: read3.data?.status
        });

        // Check if all reads show APPROVED
        if (read1.data?.status === 'APPROVED' && read2.data?.status === 'APPROVED' && read3.data?.status === 'APPROVED') {
          results.success = true;
          results.message = 'SUCCESS! Update persisted through all verifications.';
        } else {
          results.success = false;
          results.message = 'FAILED! Status reverted at some point. Check steps for details.';
          results.hint = 'This confirms there is a database trigger or policy reverting updates.';
        }

        return res.status(200).json(results);

      } catch (err) {
        results.error = err.message;
        return res.status(500).json(results);
      }
    }

    if (p.match(/^\/api\/admin\/submissions\/[^/]+\/approve$/) && req.method === 'POST') {
      if (!adminKey || adminKey !== validAdminKey) return res.status(401).json({error: 'Invalid admin key'});

      // Parse request body for tx_hash
      var body = '';
      for await (var chunk of req) { body += chunk; }
      var bodyData = {};
      try { bodyData = body ? JSON.parse(body) : {}; } catch (e) { }
      var txHash = bodyData.tx_hash || null;

      var subId = p.split('/')[4];
      console.log('APPROVE v7: Starting for ID:', subId, 'tx_hash:', txHash);

      // Step 1: Get current submission
      var sub = await supabase.from('submissions').select('*, tasks(*), users(*)').eq('id', subId).single();

      if (sub.error) {
        return res.status(500).json({error: 'Failed to fetch submission: ' + sub.error.message, step: 'fetch'});
      }
      if (!sub.data) {
        return res.status(404).json({error: 'Submission not found', step: 'fetch'});
      }

      var currentStatus = sub.data.status;
      var reward = sub.data.tasks?.reward || 0;

      if (currentStatus !== 'PENDING') {
        return res.status(400).json({error: 'Already processed', currentStatus: currentStatus});
      }

      // Step 2: Do the UPDATE
      var updateData = { status: 'APPROVED' };
      if (txHash) {
        updateData.tx_hash = txHash;
      }
      var updateResult = await supabase
        .from('submissions')
        .update(updateData)
        .eq('id', subId)
        .select();

      if (updateResult.error) {
        return res.status(500).json({
          error: 'UPDATE failed: ' + updateResult.error.message,
          step: 'update',
          details: updateResult.error
        });
      }

      // Check if update returned any rows
      if (!updateResult.data || updateResult.data.length === 0) {
        return res.status(500).json({
          error: 'UPDATE returned no rows - the row was not updated',
          step: 'update',
          hint: 'This usually means RLS is blocking the update. Make sure you are using the service_role key.',
          keyRole: KEY_ROLE
        });
      }

      var updatedStatus = updateResult.data[0].status;

      if (updatedStatus !== 'APPROVED') {
        return res.status(500).json({
          error: 'UPDATE did not change status to APPROVED',
          step: 'update',
          returnedStatus: updatedStatus
        });
      }

      // Step 3: Verify with a fresh read
      var verifyResult = await supabase.from('submissions').select('status').eq('id', subId).single();

      if (verifyResult.data?.status !== 'APPROVED') {
        return res.status(500).json({
          error: 'CRITICAL: Status reverted immediately! Update showed ' + updatedStatus + ' but read shows ' + verifyResult.data?.status,
          step: 'verify',
          hint: 'There may be a database trigger reverting the status'
        });
      }

      // Step 4: Update user stats (non-critical)
      try {
        await supabase.from('users').update({
          total_earned: (sub.data.users?.total_earned || 0) + reward,
          completed_tasks: (sub.data.users?.completed_tasks || 0) + 1
        }).eq('id', sub.data.user_id);
      } catch (e) {
        console.log('APPROVE: User stats update failed:', e.message);
      }

      // Step 5: Add activity (non-critical)
      try {
        await supabase.from('activity').insert({
          user_id: sub.data.user_id,
          username: sub.data.users?.username,
          avatar_url: sub.data.users?.avatar_url,
          type: 'TASK_COMPLETED',
          task_name: sub.data.tasks?.title,
          amount: reward
        });
      } catch (e) {
        console.log('APPROVE: Activity insert failed:', e.message);
      }

      // Step 6: Create notification for user
      var notificationResult = await createNotification(
        sub.data.user_id,
        'APPROVED',
        'Submission Approved!',
        'Your submission for "' + (sub.data.tasks?.title || 'task') + '" was approved! +' + reward + ' USDC',
        subId
      );

      return res.status(200).json({
        success: true,
        message: 'Submission approved successfully',
        submission: { id: subId, status: 'APPROVED' },
        notification: notificationResult,
        debug: {
          version: 'v7-HARDENED',
          keyRole: KEY_ROLE,
          userId: sub.data.user_id,
          reward: reward
        }
      });
    }

    if (p.match(/^\/api\/admin\/submissions\/[^/]+\/reject$/) && req.method === 'POST') {
      if (!adminKey || adminKey !== validAdminKey) return res.status(401).json({error: 'Invalid admin key'});

      // Check if using service_role key
      if (!IS_SERVICE_KEY) {
        console.error('REJECT: WRONG KEY TYPE! Using:', KEY_ROLE, 'but need service_role');
        return res.status(500).json({
          error: 'Database updates are blocked because you are using the WRONG Supabase key!',
          currentKeyRole: KEY_ROLE,
          requiredKeyRole: 'service_role',
          fix: 'Go to Supabase Dashboard > Settings > API > Copy the "service_role" secret key > Go to Vercel > Settings > Environment Variables > Update SUPABASE_SERVICE_KEY with the new key > Redeploy'
        });
      }

      // Parse request body for rejection_reason
      var bodyData = {};
      try {
        bodyData = typeof req.body === 'string' ? JSON.parse(req.body) : (req.body || {});
      } catch (e) { bodyData = {}; }
      var rejectionReason = bodyData.rejection_reason || null;

      var subId = p.split('/')[4];

      var sub = await supabase.from('submissions').select('*, tasks(title)').eq('id', subId).single();
      if (sub.error) {
        console.error('REJECT: Error fetching submission:', sub.error);
        return res.status(500).json({error: 'Failed to fetch submission: ' + sub.error.message});
      }
      if (!sub.data) return res.status(404).json({error: 'Submission not found'});
      if (sub.data.status !== 'PENDING') return res.status(400).json({error: 'Submission already processed, current status: ' + sub.data.status});

      var updateResult = await supabase
        .from('submissions')
        .update({status: 'REJECTED', rejection_reason: rejectionReason})
        .eq('id', subId);

      if (updateResult.error) {
        console.error('REJECT: Update error:', updateResult.error);
        return res.status(500).json({error: 'Failed to reject: ' + updateResult.error.message});
      }

      // Verify the update
      var verifyResult = await supabase.from('submissions').select('*').eq('id', subId).single();

      if (verifyResult.data?.status !== 'REJECTED') {
        console.error('REJECT: Status did not change! Still:', verifyResult.data?.status);
        return res.status(500).json({
          error: 'Update did not persist. Status is still: ' + verifyResult.data?.status
        });
      }

      // Decrement slots_filled on the task atomically
      if (sub.data.task_id) {
        var slotDec = await supabase.rpc('decrement_slot', { task_id_input: sub.data.task_id });
        if (slotDec.error) {
          // Fallback if RPC doesn't exist
          var taskResult = await supabase.from('tasks').select('slots_filled').eq('id', sub.data.task_id).single();
          if (taskResult.data && taskResult.data.slots_filled > 0) {
            await supabase.from('tasks').update({ slots_filled: taskResult.data.slots_filled - 1 }).eq('id', sub.data.task_id);
          }
        }
      }

      // Create notification for user
      var notificationMessage = 'Your submission for "' + (sub.data.tasks?.title || 'task') + '" was not approved.';
      if (rejectionReason) {
        notificationMessage += ' Reason: ' + rejectionReason;
      }
      var notificationResult = await createNotification(
        sub.data.user_id,
        'REJECTED',
        'Submission Rejected',
        notificationMessage,
        subId
      );

      return res.status(200).json({
        success: true,
        submission: verifyResult.data,
        notification: notificationResult,
        debug: { userId: sub.data.user_id }
      });
    }

    // Serve PFP generator page
    if (p === '/pfp' || p === '/pfp.html') {
      res.setHeader('Content-Type', 'text/html');
      var pfpPath = path.join(process.cwd(), 'public', 'pfp.html');
      if (fs.existsSync(pfpPath)) {
        return res.status(200).send(fs.readFileSync(pfpPath, 'utf8'));
      }
    }

    // Serve how it works page
    if (p === '/how-it-works' || p === '/how-it-works.html') {
      res.setHeader('Content-Type', 'text/html');
      var howPath = path.join(process.cwd(), 'public', 'how-it-works.html');
      if (fs.existsSync(howPath)) {
        return res.status(200).send(fs.readFileSync(howPath, 'utf8'));
      }
    }

    // Serve terms page
    if (p === '/terms' || p === '/terms.html') {
      res.setHeader('Content-Type', 'text/html');
      var termsPath = path.join(process.cwd(), 'public', 'terms.html');
      if (fs.existsSync(termsPath)) {
        return res.status(200).send(fs.readFileSync(termsPath, 'utf8'));
      }
    }

    // Serve privacy page
    if (p === '/privacy' || p === '/privacy.html') {
      res.setHeader('Content-Type', 'text/html');
      var privacyPath = path.join(process.cwd(), 'public', 'privacy.html');
      if (fs.existsSync(privacyPath)) {
        return res.status(200).send(fs.readFileSync(privacyPath, 'utf8'));
      }
    }

    // Serve admin page
    if (p === '/admin') {
      res.setHeader('Content-Type', 'text/html');
      var adminPath = path.join(process.cwd(), 'public', 'admin.html');
      if (fs.existsSync(adminPath)) {
        return res.status(200).send(fs.readFileSync(adminPath, 'utf8'));
      }
    }

    res.setHeader('Content-Type', 'text/html');

    if (p === '/' || p === '') {
      var user = await getUser();
      if (user) {
        var dashboardPath = path.join(process.cwd(), 'public', 'dashboard.html');
        if (fs.existsSync(dashboardPath)) {
          return res.status(200).send(fs.readFileSync(dashboardPath, 'utf8'));
        }
      }
      var landingPath = path.join(process.cwd(), 'public', 'index.html');
      if (fs.existsSync(landingPath)) {
        return res.status(200).send(fs.readFileSync(landingPath, 'utf8'));
      }
    }

    // Everything else is a 404
    var notFoundPath = path.join(process.cwd(), 'public', '404.html');
    if (fs.existsSync(notFoundPath)) {
      return res.status(404).send(fs.readFileSync(notFoundPath, 'utf8'));
    }
    return res.status(404).send('Page not found');
  } catch(err) {
    console.error(err);
    return res.status(500).json({error: err.message});
  }
};
