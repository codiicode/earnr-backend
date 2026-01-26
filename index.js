const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);
const BASE_URL = String(process.env.BASE_URL || 'https://earnr.xyz').trim();
const X_CLIENT_ID = String(process.env.X_CLIENT_ID || '').trim();
const X_CLIENT_SECRET = String(process.env.X_CLIENT_SECRET || '').trim();
const states = new Map();

module.exports = async function(req, res) {
  try {
    const url = new URL(req.url, BASE_URL);
    const p = url.pathname;
    res.setHeader('Access-Control-Allow-Origin', '*');
    if (req.method === 'OPTIONS') return res.status(200).end();

    const cookies = {};
    String(req.headers.cookie || '').split(';').forEach(function(c) { 
      const parts = c.trim().split('='); 
      if(parts[0]) cookies[parts[0]] = parts[1]; 
    });
    
    async function getUser() { 
      if(!cookies.session) return null; 
      try { 
        const result = await supabase.from('users').select('*').eq('id', cookies.session).single(); 
        return result.data; 
      } catch(e) { return null; } 
    }

    if (p === '/auth/login') {
      var state = crypto.randomBytes(16).toString('hex');
      var verifier = crypto.randomBytes(32).toString('base64url');
      var challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
      states.set(state, verifier);
      var redir = encodeURIComponent(BASE_URL + '/auth/callback');
      var authUrl = 'https://twitter.com/i/oauth2/authorize?response_type=code&client_id=' + X_CLIENT_ID + '&redirect_uri=' + redir + '&scope=tweet.read%20users.read&state=' + state + '&code_challenge=' + challenge + '&code_challenge_method=S256';
      res.writeHead(302, { 'Location': authUrl });
      return res.end();
    }

    if (p === '/auth/callback') {
      var code = url.searchParams.get('code');
      var state = url.searchParams.get('state');
      var verifier = states.get(state);
      states.delete(state);
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

    if (p === '/auth/logout') { res.setHeader('Set-Cookie', 'session=; Max-Age=0; Path=/'); res.writeHead(302, { 'Location': '/' }); return res.end(); }
    if (p === '/api/me') { return res.status(200).json({user: await getUser()}); }
    if (p === '/api/stats') { var r = await supabase.from('users').select('*', {count: 'exact', head: true}); return res.status(200).json({totalUsers: r.count || 0, onlineUsers: 0, totalPaidOut: 0, totalTasks: 0}); }
    if (p === '/api/activity') { var r = await supabase.from('activity').select('*').order('created_at', {ascending: false}).limit(20); return res.status(200).json({activity: r.data || []}); }
    if (p === '/api/tasks') { var r = await supabase.from('tasks').select('*').eq('is_active', true); return res.status(200).json({tasks: r.data || []}); }
    if (p === '/api/leaderboard') { var r = await supabase.from('users').select('*').order('total_earned', {ascending: false}).limit(20); return res.status(200).json({leaderboard: r.data || []}); }
    if (p === '/api/earnrs' || p === '/api/hunters') { var r = await supabase.from('users').select('*').order('created_at', {ascending: false}); return res.status(200).json({earnrs: r.data || [], hunters: r.data || []}); }
    if (p === '/api/heartbeat') { var u = await getUser(); if(u) await supabase.from('users').update({last_seen: new Date().toISOString()}).eq('id', u.id); return res.status(200).json({ok: true}); }

    var user = await getUser();
    res.setHeader('Content-Type', 'text/html');
    
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
    
    return res.status(200).send('EARNR API');
  } catch(err) { 
    console.error(err); 
    return res.status(500).json({error: err.message}); 
  }
};
