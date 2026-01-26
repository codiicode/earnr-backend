const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// IMPORTANT: Must use service_role key (not anon key) to bypass RLS
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_KEY || '';
const CODE_VERSION = 'v6-DIRECT-2026-01-26';

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
    if (p === '/api/tasks') { var r = await supabase.from('tasks').select('*').eq('is_active', true).order('created_at', {ascending: false}); return res.status(200).json({tasks: r.data || []}); }
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
      }).sort(function(a, b) { return b.total_earned - a.total_earned; }).slice(0, 20);

      return res.status(200).json({leaderboard: leaderboard});
    }
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
          .order('created_at', {ascending: false});

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
          var approvedAt = sub.created_at ? new Date(sub.created_at).getTime() : now;

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
            timestamp: sub.created_at,
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

      // Increment slots_filled
      await supabase.from('tasks').update({slots_filled: task.slots_filled + 1}).eq('id', data.task_id);

      return res.status(200).json({submission: r.data});
    }

    // Admin API
    var adminKey = String(req.headers['x-admin-key'] || '').trim();
    var validAdminKey = String(process.env.ADMIN_KEY || '').trim();

    if (p === '/api/admin/submissions') {
      if (!validAdminKey) return res.status(500).json({error: 'ADMIN_KEY not configured on server'});
      if (!adminKey || adminKey !== validAdminKey) return res.status(401).json({error: 'Invalid admin key'});
      var r = await supabase.from('submissions').select('*, users(*), tasks(*)').order('created_at', {ascending: false});
      return res.status(200).json({
        submissions: r.data || [],
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
      var r = await supabase.from('tasks').select('*').order('created_at', {ascending: false});
      return res.status(200).json({tasks: r.data || []});
    }

    // Admin Tasks API - Create task
    if (p === '/api/admin/tasks' && req.method === 'POST') {
      if (!adminKey || adminKey !== validAdminKey) return res.status(401).json({error: 'Invalid admin key'});
      var body = ''; for await (var chunk of req) { body += chunk; }
      var data = JSON.parse(body);

      if (!data.title || !data.reward) {
        return res.status(400).json({error: 'Title and reward are required'});
      }

      var taskData = {
        title: data.title,
        description: data.description || '',
        reward: parseFloat(data.reward) || 0,
        task_url: data.task_url || null,
        category: data.category || 'SOCIAL',
        difficulty: data.difficulty || 'EASY',
        slots_total: parseInt(data.slots_total) || 100,
        slots_filled: 0,
        min_followers: parseInt(data.min_followers) || 0,
        is_active: data.is_active !== false
      };

      var r = await supabase.from('tasks').insert(taskData).select().single();
      if (r.error) {
        console.error('Task create error:', r.error);
        return res.status(500).json({error: 'Failed to create task: ' + r.error.message});
      }
      return res.status(200).json({success: true, task: r.data});
    }

    // Admin Tasks API - Update task
    if (p.match(/^\/api\/admin\/tasks\/[^/]+$/) && req.method === 'PUT') {
      if (!adminKey || adminKey !== validAdminKey) return res.status(401).json({error: 'Invalid admin key'});
      var taskId = p.split('/')[4];
      var body = ''; for await (var chunk of req) { body += chunk; }
      var data = JSON.parse(body);

      var updateData = {};
      if (data.title !== undefined) updateData.title = data.title;
      if (data.description !== undefined) updateData.description = data.description;
      if (data.reward !== undefined) updateData.reward = parseFloat(data.reward) || 0;
      if (data.task_url !== undefined) updateData.task_url = data.task_url || null;
      if (data.category !== undefined) updateData.category = data.category;
      if (data.difficulty !== undefined) updateData.difficulty = data.difficulty;
      if (data.slots_total !== undefined) updateData.slots_total = parseInt(data.slots_total) || 100;
      if (data.min_followers !== undefined) updateData.min_followers = parseInt(data.min_followers) || 0;
      if (data.is_active !== undefined) updateData.is_active = data.is_active;

      var r = await supabase.from('tasks').update(updateData).eq('id', taskId).select().single();
      if (r.error) {
        console.error('Task update error:', r.error);
        return res.status(500).json({error: 'Failed to update task: ' + r.error.message});
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

      var subId = p.split('/')[4];
      console.log('APPROVE v6: Starting for ID:', subId);
      console.log('APPROVE v6: Key role:', KEY_ROLE);

      // Step 1: Get current submission
      var sub = await supabase.from('submissions').select('*, tasks(*), users(*)').eq('id', subId).single();
      console.log('APPROVE v6: Fetch result:', JSON.stringify({data: sub.data?.status, error: sub.error}));

      if (sub.error) {
        return res.status(500).json({error: 'Failed to fetch submission: ' + sub.error.message, step: 'fetch'});
      }
      if (!sub.data) {
        return res.status(404).json({error: 'Submission not found', step: 'fetch'});
      }

      var currentStatus = sub.data.status;
      var reward = sub.data.tasks?.reward || 0;
      console.log('APPROVE v6: Current status:', currentStatus, 'Reward:', reward);

      if (currentStatus !== 'PENDING') {
        return res.status(400).json({error: 'Already processed', currentStatus: currentStatus});
      }

      // Step 2: Do the UPDATE - simple and direct
      console.log('APPROVE v6: Executing UPDATE...');
      var updateResult = await supabase
        .from('submissions')
        .update({ status: 'APPROVED' })
        .eq('id', subId)
        .select();

      console.log('APPROVE v6: Update result:', JSON.stringify(updateResult));

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
      console.log('APPROVE v6: Update returned status:', updatedStatus);

      if (updatedStatus !== 'APPROVED') {
        return res.status(500).json({
          error: 'UPDATE did not change status to APPROVED',
          step: 'update',
          returnedStatus: updatedStatus
        });
      }

      // Step 3: Verify with a fresh read
      console.log('APPROVE v6: Verifying with fresh read...');
      var verifyResult = await supabase.from('submissions').select('status').eq('id', subId).single();
      console.log('APPROVE v6: Verify result:', JSON.stringify(verifyResult));

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
        console.log('APPROVE v6: User stats update failed:', e.message);
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
        console.log('APPROVE v6: Activity insert failed:', e.message);
      }

      console.log('APPROVE v6: SUCCESS!');
      return res.status(200).json({
        success: true,
        message: 'Submission approved successfully',
        submission: { id: subId, status: 'APPROVED' },
        debug: {
          version: 'v6-DIRECT',
          keyRole: KEY_ROLE,
          updateReturnedStatus: updatedStatus,
          verifyStatus: verifyResult.data?.status,
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

      var subId = p.split('/')[4];
      console.log('REJECT: Starting rejection for submission ID:', subId);

      var sub = await supabase.from('submissions').select('*').eq('id', subId).single();
      if (sub.error) {
        console.error('REJECT: Error fetching submission:', sub.error);
        return res.status(500).json({error: 'Failed to fetch submission: ' + sub.error.message});
      }
      if (!sub.data) return res.status(404).json({error: 'Submission not found'});
      console.log('REJECT: Current status:', sub.data.status);
      if (sub.data.status !== 'PENDING') return res.status(400).json({error: 'Submission already processed, current status: ' + sub.data.status});

      var updateResult = await supabase
        .from('submissions')
        .update({status: 'REJECTED'})
        .eq('id', subId);

      console.log('REJECT: Update result:', JSON.stringify(updateResult));

      if (updateResult.error) {
        console.error('REJECT: Update error:', updateResult.error);
        return res.status(500).json({error: 'Failed to reject: ' + updateResult.error.message});
      }

      // Verify the update
      var verifyResult = await supabase.from('submissions').select('*').eq('id', subId).single();
      console.log('REJECT: Verification result:', JSON.stringify(verifyResult));

      if (verifyResult.data?.status !== 'REJECTED') {
        console.error('REJECT: Status did not change! Still:', verifyResult.data?.status);
        return res.status(500).json({
          error: 'Update did not persist. Status is still: ' + verifyResult.data?.status
        });
      }

      console.log('REJECT: SUCCESS - Status verified as REJECTED');
      return res.status(200).json({success: true, submission: verifyResult.data});
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
