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
    if (p.startsWith('/api/user/')) { var userId = p.split('/')[3]; var r = await supabase.from('users').select('*').eq('id', userId).single(); return res.status(200).json({user: r.data || null}); }
    if (p === '/api/stats') {
      var usersRes = await supabase.from('users').select('*', {count: 'exact', head: true});
      var fiveMinAgo = new Date(Date.now() - 5*60*1000).toISOString();
      var onlineRes = await supabase.from('users').select('*', {count: 'exact', head: true}).gte('last_seen', fiveMinAgo);
      var tasksRes = await supabase.from('tasks').select('*', {count: 'exact', head: true}).eq('is_active', true);
      var approvedRes = await supabase.from('submissions').select('reward').eq('status', 'APPROVED');
      var totalPaid = (approvedRes.data || []).reduce((sum, s) => sum + (s.reward || 0), 0);
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
    if (p === '/api/tasks') { var r = await supabase.from('tasks').select('*').eq('is_active', true); return res.status(200).json({tasks: r.data || []}); }
    if (p === '/api/leaderboard') { var r = await supabase.from('users').select('*').order('total_earned', {ascending: false}).limit(20); return res.status(200).json({leaderboard: r.data || []}); }
    if (p === '/api/earnrs' || p === '/api/hunters') {
      var r = await supabase.from('users').select('*').order('created_at', {ascending: false});
      if (r.error) {
        console.error('Error fetching earnrs:', r.error);
        return res.status(500).json({error: r.error.message, earnrs: [], hunters: []});
      }
      return res.status(200).json({earnrs: r.data || [], hunters: r.data || []});
    }
    if (p === '/api/heartbeat') { var u = await getUser(); if(u) await supabase.from('users').update({last_seen: new Date().toISOString()}).eq('id', u.id); return res.status(200).json({ok: true}); }
    if (p === '/api/wallet' && req.method === 'POST') { var u = await getUser(); if(!u) return res.status(401).json({error: 'Not logged in'}); var body = ''; for await (var chunk of req) { body += chunk; } var data = JSON.parse(body); await supabase.from('users').update({wallet_address: String(data.wallet || '').trim()}).eq('id', u.id); return res.status(200).json({success: true}); }

    // Payouts API - Fetch approved submissions from database
    if (p === '/api/payouts') {
      try {
        // Get all approved submissions with user and task info
        var approvedRes = await supabase
          .from('submissions')
          .select('*, users(*), tasks(*)')
          .eq('status', 'APPROVED')
          .order('approved_at', {ascending: false});

        var submissions = approvedRes.data || [];

        // Calculate totals
        var totalPaidOut = 0;
        var last24hPaid = 0;
        var now = Date.now();
        var dayAgo = now - 24 * 60 * 60 * 1000;

        var transactions = [];
        for (var i = 0; i < submissions.length; i++) {
          var sub = submissions[i];
          var reward = sub.tasks?.reward || 0;
          var approvedAt = sub.approved_at ? new Date(sub.approved_at).getTime() : now;

          totalPaidOut += reward;
          if (approvedAt > dayAgo) {
            last24hPaid += reward;
          }

          transactions.push({
            id: sub.id,
            username: sub.users?.username || 'Unknown',
            avatar_url: sub.users?.avatar_url || '',
            wallet: sub.users?.wallet_address || '',
            amount: reward,
            task_title: sub.tasks?.title || 'Task',
            timestamp: sub.approved_at || sub.created_at,
            status: 'completed'
          });
        }

        return res.status(200).json({
          transactions: transactions,
          stats: {
            totalPaidOut: totalPaidOut,
            last24hPaid: last24hPaid,
            transactionCount: transactions.length
          }
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
      var r = await supabase.from('submissions').select('*, tasks(*)').eq('user_id', user.id).order('created_at', {ascending: false});
      return res.status(200).json({submissions: r.data || []});
    }

    if (p === '/api/submissions' && req.method === 'POST') {
      var user = await getUser();
      if (!user) return res.status(401).json({error: 'Not logged in'});
      var body = ''; for await (var chunk of req) { body += chunk; }
      var data = JSON.parse(body);
      if (!data.task_id || !data.proof_url) return res.status(400).json({error: 'Missing task_id or proof_url'});

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

      return res.status(200).json({submission: r.data});
    }

    // Admin API
    var adminKey = String(req.headers['x-admin-key'] || '').trim();
    var validAdminKey = String(process.env.ADMIN_KEY || '').trim();

    if (p === '/api/admin/submissions') {
      if (!validAdminKey) return res.status(500).json({error: 'ADMIN_KEY not configured on server'});
      if (!adminKey || adminKey !== validAdminKey) return res.status(401).json({error: 'Invalid admin key'});
      var r = await supabase.from('submissions').select('*, users(*), tasks(*)').order('created_at', {ascending: false});
      return res.status(200).json({submissions: r.data || []});
    }

    if (p.match(/^\/api\/admin\/submissions\/[^/]+\/approve$/) && req.method === 'POST') {
      if (!adminKey || adminKey !== validAdminKey) return res.status(401).json({error: 'Invalid admin key'});
      var subId = p.split('/')[4];

      // Get submission with task info
      var sub = await supabase.from('submissions').select('*, tasks(*)').eq('id', subId).single();
      if (sub.error) {
        console.error('Error fetching submission:', sub.error);
        return res.status(500).json({error: 'Failed to fetch submission: ' + sub.error.message});
      }
      if (!sub.data) return res.status(404).json({error: 'Submission not found'});
      if (sub.data.status !== 'PENDING') return res.status(400).json({error: 'Submission already processed'});

      // Update submission status with error checking
      var updateResult = await supabase
        .from('submissions')
        .update({status: 'APPROVED', approved_at: new Date().toISOString()})
        .eq('id', subId)
        .select()
        .single();

      if (updateResult.error) {
        console.error('Error updating submission:', updateResult.error);
        return res.status(500).json({error: 'Failed to update submission: ' + updateResult.error.message});
      }

      if (!updateResult.data || updateResult.data.status !== 'APPROVED') {
        console.error('Update did not apply. Result:', updateResult);
        return res.status(500).json({error: 'Update failed to apply'});
      }

      // Update user stats (ignore errors, non-critical)
      var reward = sub.data.tasks?.reward || 0;
      try {
        await supabase.rpc('increment_user_stats', {user_id: sub.data.user_id, earned: reward, tasks: 1});
      } catch (e) {
        console.error('Error updating user stats:', e);
        // Continue anyway - the approval is the critical part
      }

      // Add activity (ignore errors, non-critical)
      try {
        var userInfo = await supabase.from('users').select('username, avatar_url').eq('id', sub.data.user_id).single();
        await supabase.from('activity').insert({
          user_id: sub.data.user_id,
          username: userInfo.data?.username,
          avatar_url: userInfo.data?.avatar_url,
          type: 'TASK_COMPLETED',
          task_name: sub.data.tasks?.title,
          amount: reward
        });
      } catch (e) {
        console.error('Error adding activity:', e);
        // Continue anyway
      }

      return res.status(200).json({success: true, submission: updateResult.data});
    }

    if (p.match(/^\/api\/admin\/submissions\/[^/]+\/reject$/) && req.method === 'POST') {
      if (!adminKey || adminKey !== validAdminKey) return res.status(401).json({error: 'Invalid admin key'});
      var subId = p.split('/')[4];

      var sub = await supabase.from('submissions').select('*').eq('id', subId).single();
      if (sub.error) {
        console.error('Error fetching submission:', sub.error);
        return res.status(500).json({error: 'Failed to fetch submission: ' + sub.error.message});
      }
      if (!sub.data) return res.status(404).json({error: 'Submission not found'});
      if (sub.data.status !== 'PENDING') return res.status(400).json({error: 'Submission already processed'});

      var updateResult = await supabase
        .from('submissions')
        .update({status: 'REJECTED', rejected_at: new Date().toISOString()})
        .eq('id', subId)
        .select()
        .single();

      if (updateResult.error) {
        console.error('Error rejecting submission:', updateResult.error);
        return res.status(500).json({error: 'Failed to reject submission: ' + updateResult.error.message});
      }

      return res.status(200).json({success: true, submission: updateResult.data});
    }

    // Serve admin page
    if (p === '/admin') {
      res.setHeader('Content-Type', 'text/html');
      var adminPath = path.join(process.cwd(), 'public', 'admin.html');
      if (fs.existsSync(adminPath)) {
        return res.status(200).send(fs.readFileSync(adminPath, 'utf8'));
      }
    }

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
