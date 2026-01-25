const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

let supabase;
try {
  supabase = createClient(process.env.SUPABASE_URL || '', process.env.SUPABASE_SERVICE_KEY || '');
} catch (e) { console.error(e); }

const BASE_URL = (process.env.BASE_URL || 'https://earnr.xyz').trim();
const states = new Map();

module.exports = async (req, res) => {
  try {
    const url = new URL(req.url, BASE_URL);
    const p = url.pathname;
    res.setHeader('Access-Control-Allow-Origin', '*');
    if (req.method === 'OPTIONS') return res.status(200).end();

    const cookies = {};
    (req.headers.cookie || '').split(';').forEach(c => { const [k,v] = c.trim().split('='); if(k) cookies[k]=v; });
    const getUser = async () => { if(!cookies.session) return null; try { const {data} = await supabase.from('users').select('*').eq('id',cookies.session).single(); return data; } catch(e) { return null; } };

    if (p === '/auth/login') {
      const state = crypto.randomBytes(16).toString('hex');
      const verifier = crypto.randomBytes(32).toString('base64url');
      const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
      states.set(state, verifier);
      return res.writeHead(302, { Location: `https://twitter.com/i/oauth2/authorize?response_type=code&client_id=${process.env.X_CLIENT_ID}&redirect_uri=${encodeURIComponent(BASE_URL+'/auth/callback')}&scope=tweet.read%20users.read&state=${state}&code_challenge=${challenge}&code_challenge_method=S256` }).end();
    }

    if (p === '/auth/callback') {
      const code = url.searchParams.get('code'), state = url.searchParams.get('state');
      const verifier = states.get(state); states.delete(state);
      if (!verifier) return res.writeHead(302, { Location: '/?error=bad_state' }).end();
      const tr = await fetch('https://api.twitter.com/2/oauth2/token', { method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded','Authorization':'Basic '+Buffer.from(process.env.X_CLIENT_ID+':'+process.env.X_CLIENT_SECRET).toString('base64')}, body: new URLSearchParams({code,grant_type:'authorization_code',redirect_uri:BASE_URL+'/auth/callback',code_verifier:verifier}) });
      const tk = await tr.json(); if(!tk.access_token) return res.writeHead(302,{Location:'/?error=no_token'}).end();
      const ur = await fetch('https://api.twitter.com/2/users/me?user.fields=profile_image_url,public_metrics',{headers:{'Authorization':'Bearer '+tk.access_token}});
      const {data:xu} = await ur.json(); if(!xu) return res.writeHead(302,{Location:'/?error=no_user'}).end();
      let {data:user} = await supabase.from('users').select('*').eq('x_id',xu.id).single();
      if(user) { const {data}=await supabase.from('users').update({username:xu.username,display_name:xu.name,avatar_url:(xu.profile_image_url||'').replace('_normal','_400x400'),followers_count:xu.public_metrics?.followers_count||0,last_seen:new Date().toISOString()}).eq('x_id',xu.id).select().single(); user=data; }
      else { const {data}=await supabase.from('users').insert({x_id:xu.id,username:xu.username,display_name:xu.name,avatar_url:(xu.profile_image_url||'').replace('_normal','_400x400'),followers_count:xu.public_metrics?.followers_count||0}).select().single(); user=data; await supabase.from('activity').insert({type:'JOIN',user_id:user.id,username:user.username,avatar_url:user.avatar_url}); }
      res.setHeader('Set-Cookie',`session=${user.id}; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000; Path=/`);
      return res.writeHead(302,{Location:'/'}).end();
    }

    if (p === '/auth/logout') { res.setHeader('Set-Cookie','session=; Max-Age=0; Path=/'); return res.writeHead(302,{Location:'/'}).end(); }
    if (p === '/api/me') return res.status(200).json({user:await getUser()});
    if (p === '/api/stats') { const {count:t}=await supabase.from('users').select('*',{count:'exact',head:true}); return res.status(200).json({totalUsers:t||0,onlineUsers:0,totalPaidOut:0,totalTasks:0}); }
    if (p === '/api/activity') { const {data}=await supabase.from('activity').select('*').order('created_at',{ascending:false}).limit(20); return res.status(200).json({activity:data||[]}); }
    if (p === '/api/tasks') { const {data}=await supabase.from('tasks').select('*').eq('is_active',true); return res.status(200).json({tasks:data||[]}); }
    if (p === '/api/leaderboard') { const {data}=await supabase.from('users').select('*').order('total_earned',{ascending:false}).limit(20); return res.status(200).json({leaderboard:data||[]}); }
    if (p === '/api/hunters') { const {data}=await supabase.from('users').select('*').order('created_at',{ascending:false}); return res.status(200).json({hunters:data||[]}); }
    if (p === '/api/heartbeat') { const u=await getUser(); if(u) await supabase.from('users').update({last_seen:new Date().toISOString()}).eq('id',u.id); return res.status(200).json({ok:true}); }

    const hp = path.join(process.cwd(),'public','index.html');
    if (fs.existsSync(hp)) { res.setHeader('Content-Type','text/html'); return res.status(200).send(fs.readFileSync(hp,'utf8')); }
    return res.status(200).send('EARNR');
  } catch(e) { console.error(e); return res.status(500).json({error:e.message}); }
};
