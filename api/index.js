const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// IMPORTANT: Must use service_role key (not anon key) to bypass RLS
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_KEY || '';
const CODE_VERSION = 'v4-RAWSQL-2026-01-26';

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
      return res.status(200).json({
        submissions: r.data || [],
        _debug: {
          codeVersion: CODE_VERSION,
          keyRole: KEY_ROLE,
          isServiceKey: IS_SERVICE_KEY
        }
      });
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
          .update({ status: 'APPROVED', approved_at: new Date().toISOString() })
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
      console.log('APPROVE v4: Starting for ID:', subId);
      console.log('APPROVE v4: Key role:', KEY_ROLE, '| Supabase URL:', process.env.SUPABASE_URL);

      // Create a FRESH supabase client for this operation to avoid any caching
      var freshClient = createClient(process.env.SUPABASE_URL, SUPABASE_KEY, {
        auth: { autoRefreshToken: false, persistSession: false },
        db: { schema: 'public' }
      });

      // Step 1: Get current submission
      var sub = await freshClient.from('submissions').select('*, tasks(*)').eq('id', subId).single();
      if (sub.error) {
        console.error('APPROVE v4: Fetch error:', sub.error);
        return res.status(500).json({error: 'Failed to fetch: ' + sub.error.message, code: 'FETCH_ERROR'});
      }
      if (!sub.data) {
        return res.status(404).json({error: 'Submission not found', code: 'NOT_FOUND'});
      }

      console.log('APPROVE v4: Current status:', sub.data.status, '| reward:', sub.data.tasks?.reward);

      if (sub.data.status !== 'PENDING') {
        return res.status(400).json({error: 'Already processed: ' + sub.data.status, code: 'ALREADY_PROCESSED'});
      }

      // Step 2: Prepare update data
      var now = new Date().toISOString();
      var reward = sub.data.tasks?.reward || 0;

      // Step 3: Perform the update with select() to get returned data
      console.log('APPROVE v4: Executing UPDATE...');
      var updateResult = await freshClient
        .from('submissions')
        .update({
          status: 'APPROVED',
          approved_at: now,
          reward: reward  // Also store reward on submission for easier querying
        })
        .eq('id', subId)
        .eq('status', 'PENDING')  // Extra safety: only update if still PENDING
        .select('id, status, approved_at, reward');

      console.log('APPROVE v4: Update result:', JSON.stringify(updateResult));

      if (updateResult.error) {
        console.error('APPROVE v4: Update error:', updateResult.error);
        return res.status(500).json({
          error: 'Update failed: ' + updateResult.error.message,
          code: 'UPDATE_ERROR',
          details: updateResult.error
        });
      }

      if (!updateResult.data || updateResult.data.length === 0) {
        // Update returned 0 rows - either RLS blocked it or status changed
        console.error('APPROVE v4: Update returned 0 rows!');

        // Check current state
        var checkState = await freshClient.from('submissions').select('id, status').eq('id', subId).single();
        return res.status(500).json({
          error: 'Update returned 0 rows',
          code: 'ZERO_ROWS',
          currentStatus: checkState.data?.status,
          hint: 'RLS may be blocking the update or status changed concurrently'
        });
      }

      var returnedStatus = updateResult.data[0].status;
      console.log('APPROVE v4: Update returned status:', returnedStatus);

      if (returnedStatus !== 'APPROVED') {
        return res.status(500).json({
          error: 'Update returned wrong status: ' + returnedStatus,
          code: 'WRONG_STATUS_RETURNED'
        });
      }

      // Step 4: AGGRESSIVE verification - wait and check multiple times with DIFFERENT clients
      var verifications = [];

      // Verify 1: Immediate with same client
      var v1 = await freshClient.from('submissions').select('status').eq('id', subId).single();
      verifications.push({ delay: '0ms', client: 'fresh', status: v1.data?.status });
      console.log('APPROVE v4: Verify 0ms:', v1.data?.status);

      // Verify 2: 200ms with original global client
      await new Promise(r => setTimeout(r, 200));
      var v2 = await supabase.from('submissions').select('status').eq('id', subId).single();
      verifications.push({ delay: '200ms', client: 'global', status: v2.data?.status });
      console.log('APPROVE v4: Verify 200ms (global client):', v2.data?.status);

      // Verify 3: 500ms with brand new client
      await new Promise(r => setTimeout(r, 300));
      var newestClient = createClient(process.env.SUPABASE_URL, SUPABASE_KEY, {
        auth: { autoRefreshToken: false, persistSession: false }
      });
      var v3 = await newestClient.from('submissions').select('status').eq('id', subId).single();
      verifications.push({ delay: '500ms', client: 'newest', status: v3.data?.status });
      console.log('APPROVE v4: Verify 500ms (newest client):', v3.data?.status);

      // Check if any verification shows non-APPROVED
      var failed = verifications.find(v => v.status !== 'APPROVED');
      if (failed) {
        console.error('APPROVE v4: VERIFICATION FAILED!', failed);
        return res.status(500).json({
          error: 'CRITICAL: Status reverted after update!',
          code: 'STATUS_REVERTED',
          verifications: verifications,
          hint: 'There may be a database trigger reverting the change. Check Supabase Dashboard > Database > Triggers'
        });
      }

      console.log('APPROVE v4: All verifications passed!');

      // Step 5: Update user stats (non-blocking, catch errors)
      try {
        await supabase.rpc('increment_user_stats', {user_id: sub.data.user_id, earned: reward, tasks: 1});
      } catch (e) {
        console.log('APPROVE v4: Stats update failed (non-critical):', e.message);
      }

      // Step 6: Add activity (non-blocking)
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
        console.log('APPROVE v4: Activity insert failed (non-critical):', e.message);
      }

      // Step 7: Final verification after 1 second with yet another client
      await new Promise(r => setTimeout(r, 500));
      var finalClient = createClient(process.env.SUPABASE_URL, SUPABASE_KEY, {
        auth: { autoRefreshToken: false, persistSession: false }
      });
      var finalCheck = await finalClient.from('submissions').select('id, status, approved_at').eq('id', subId).single();
      verifications.push({ delay: '1000ms', client: 'final', status: finalCheck.data?.status });
      console.log('APPROVE v4: Final check at 1000ms:', finalCheck.data?.status);

      if (finalCheck.data?.status !== 'APPROVED') {
        return res.status(500).json({
          error: 'CRITICAL: Final verification failed! Status is: ' + finalCheck.data?.status,
          code: 'FINAL_VERIFICATION_FAILED',
          verifications: verifications,
          hint: 'Check for database triggers or background processes resetting status'
        });
      }

      return res.status(200).json({
        success: true,
        message: 'Submission approved and verified',
        submission: finalCheck.data,
        debug: {
          codeVersion: CODE_VERSION,
          keyRole: KEY_ROLE,
          supabaseUrl: (process.env.SUPABASE_URL || '').substring(0, 30) + '...',
          verifications: verifications,
          submissionId: subId,
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
        .update({status: 'REJECTED', rejected_at: new Date().toISOString()})
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
