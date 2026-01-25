const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);
const BASE_URL = (process.env.BASE_URL || 'https://earnr.xyz').trim();
const oauthStates = new Map();

module.exports = async (req, res) => {
  const url = new URL(req.url, BASE_URL);
  const path = url.pathname;

  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();

  // Parse cookies
  const cookies = {};
  (req.headers.cookie || '').split(';').forEach(c => {
    const [k, v] = c.trim().split('=');
    if (k) cookies[k] = v;
  });

  // Get user helper
  const getUser = async () => {
    if (!cookies.session) return null;
    const { data } = await supabase.from('users').select('*').eq('id', cookies.session).single();
    return data;
  };

  // AUTH LOGIN
  if (path === '/auth/login') {
    const state = crypto.randomBytes(16).toString('hex');
    const verifier = crypto.randomBytes(32).toString('base64url');
    const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
    oauthStates.set(state, { verifier, createdAt: Date.now() });
    
    const authUrl = `https://twitter.com/i/oauth2/authorize?response_type=code&client_id=${process.env.X_CLIENT_ID}&redirect_uri=${encodeURIComponent(BASE_URL + '/auth/callback')}&scope=tweet.read%20users.read&state=${state}&code_challenge=${challenge}&code_challenge_method=S256`;
    return res.writeHead(302, { Location: authUrl }).end();
  }

  // AUTH CALLBACK
  if (path === '/auth/callback') {
    const code = url.searchParams.get('code');
    const state = url.searchParams.get('state');
    const stored = oauthStates.get(state);
    if (!stored) return res.writeHead(302, { Location: '/?error=invalid_state' }).end();
    
    oauthStates.delete(state);
    try {
      const tokenRes = await fetch('https://api.twitter.com/2/oauth2/token', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': 'Basic ' + Buffer.from(process.env.X_CLIENT_ID + ':' + process.env.X_CLIENT_SECRET).toString('base64')
        },
        body: new URLSearchParams({ code, grant_type: 'authorization_code', redirect_uri: BASE_URL + '/auth/callback', code_verifier: stored.verifier })
      });
      const tokens = await tokenRes.json();
      if (!tokens.access_token) return res.writeHead(302, { Location: '/?error=token_failed' }).end();

      const userRes = await fetch('https://api.twitter.com/2/users/me?user.fields=profile_image_url,public_metrics', {
        headers: { 'Authorization': 'Bearer ' + tokens.access_token }
      });
      const { data: xUser } = await userRes.json();
      if (!xUser) return res.writeHead(302, { Location: '/?error=user_failed' }).end();

      let { data: user } = await supabase.from('users').select('*').eq('x_id', xUser.id).single();
      if (user) {
        const { data } = await supabase.from('users').update({ username: xUser.username, display_name: xUser.name, avatar_url: xUser.profile_image_url?.replace('_normal', '_400x400'), followers_count: xUser.public_metrics?.followers_count || 0, last_seen: new Date().toISOString() }).eq('x_id', xUser.id).select().single();
        user = data;
      } else {
        const { data } = await supabase.from('users').insert({ x_id: xUser.id, username: xUser.username, display_name: xUser.name, avatar_url: xUser.profile_image_url?.replace('_normal', '_400x400'), followers_count: xUser.public_metrics?.followers_count || 0 }).select().single();
        user = data;
        await supabase.from('activity').insert({ type: 'JOIN', user_id: user.id, username: user.username, avatar_url: user.avatar_url });
      }
      res.setHeader('Set-Cookie', `session=${user.id}; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000; Path=/`);
      return res.writeHead(302, { Location: '/' }).end();
    } catch (e) { console.error(e); return res.writeHead(302, { Location: '/?error=auth_error' }).end(); }
  }

  // AUTH LOGOUT
  if (path === '/auth/logout') {
    res.setHeader('Set-Cookie', 'session=; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Path=/');
    return res.writeHead(302, { Location: '/' }).end();
  }

  // API ME
  if (path === '/api/me') return res.status(200).json({ user: await getUser() });

  // API STATS
  if (path === '/api/stats') {
    const { count: totalUsers } = await supabase.from('users').select('*', { count: 'exact', head: true });
    const { count: onlineUsers } = await supabase.from('users').select('*', { count: 'exact', head: true }).gte('last_seen', new Date(Date.now() - 300000).toISOString());
    const { data: tasks } = await supabase.from('tasks').select('reward, slots_filled').eq('is_active', true);
    return res.status(200).json({ totalUsers: totalUsers || 0, onlineUsers: onlineUsers || 0, totalPaidOut: tasks?.reduce((s, t) => s + t.reward * t.slots_filled, 0) || 0, totalTasks: tasks?.length || 0 });
  }

  // API ACTIVITY
  if (path === '/api/activity') {
    const { data } = await supabase.from('activity').select('*').order('created_at', { ascending: false }).limit(20);
    return res.status(200).json({ activity: data || [] });
  }

  // API TASKS
  if (path === '/api/tasks') {
    const { data } = await supabase.from('tasks').select('*').eq('is_active', true).order('created_at', { ascending: false });
    return res.status(200).json({ tasks: data || [] });
  }

  // API LEADERBOARD
  if (path === '/api/leaderboard') {
    const { data } = await supabase.from('users').select('id, username, display_name, avatar_url, total_earned, tasks_completed, rank').order('total_earned', { ascending: false }).limit(20);
    return res.status(200).json({ leaderboard: data || [] });
  }

  // API HUNTERS
  if (path === '/api/hunters') {
    const { data } = await supabase.from('users').select('id, username, display_name, avatar_url, total_earned, tasks_completed, created_at').order('created_at', { ascending: false });
    return res.status(200).json({ hunters: data || [] });
  }

  // API HEARTBEAT
  if (path === '/api/heartbeat') {
    const user = await getUser();
    if (user) await supabase.from('users').update({ last_seen: new Date().toISOString() }).eq('id', user.id);
    return res.status(200).json({ ok: true });
  }

  // SERVE FRONTEND
  const fs = require('fs');
  const filePath = require('path').join(process.cwd(), 'public', 'index.html');
  if (fs.existsSync(filePath)) {
    res.setHeader('Content-Type', 'text/html');
    return res.status(200).send(fs.readFileSync(filePath, 'utf8'));
  }
  return res.status(200).send('EARNR API Running');
};
