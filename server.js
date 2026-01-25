const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');
const path = require('path');

const app = express();

// Environment variables (set these in Vercel)
const CONFIG = {
  X_CLIENT_ID: process.env.X_CLIENT_ID,
  X_CLIENT_SECRET: process.env.X_CLIENT_SECRET,
  SUPABASE_URL: process.env.SUPABASE_URL,
  SUPABASE_ANON_KEY: process.env.SUPABASE_ANON_KEY,
  SUPABASE_SERVICE_KEY: process.env.SUPABASE_SERVICE_KEY,
  BASE_URL: process.env.BASE_URL || 'https://earnr.xyz',
  SESSION_SECRET: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex')
};

// Initialize Supabase
const supabase = createClient(CONFIG.SUPABASE_URL, CONFIG.SUPABASE_SERVICE_KEY);
const supabasePublic = createClient(CONFIG.SUPABASE_URL, CONFIG.SUPABASE_ANON_KEY);

// Middleware
app.use(cors({ origin: CONFIG.BASE_URL, credentials: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static('public'));

// Store for OAuth states and code verifiers (in production, use Redis)
const oauthStates = new Map();

// Helper: Generate PKCE code verifier and challenge
function generatePKCE() {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}

// Helper: Get user from session cookie
async function getUser(req) {
  const sessionId = req.cookies.session;
  if (!sessionId) return null;
  
  const { data } = await supabase
    .from('users')
    .select('*')
    .eq('id', sessionId)
    .single();
  
  return data;
}

// ============================================
// AUTH ROUTES
// ============================================

// Start X OAuth flow
app.get('/auth/login', (req, res) => {
  const state = crypto.randomBytes(16).toString('hex');
  const { verifier, challenge } = generatePKCE();
  
  // Store state and verifier temporarily
  oauthStates.set(state, { verifier, createdAt: Date.now() });
  
  // Clean up old states (older than 10 minutes)
  for (const [key, value] of oauthStates) {
    if (Date.now() - value.createdAt > 600000) {
      oauthStates.delete(key);
    }
  }
  
  const authUrl = new URL('https://twitter.com/i/oauth2/authorize');
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('client_id', CONFIG.X_CLIENT_ID);
  authUrl.searchParams.set('redirect_uri', `${CONFIG.BASE_URL}/auth/callback`);
  authUrl.searchParams.set('scope', 'tweet.read users.read');
  authUrl.searchParams.set('state', state);
  authUrl.searchParams.set('code_challenge', challenge);
  authUrl.searchParams.set('code_challenge_method', 'S256');
  
  res.redirect(authUrl.toString());
});

// X OAuth callback
app.get('/auth/callback', async (req, res) => {
  const { code, state, error } = req.query;
  
  if (error) {
    console.error('OAuth error:', error);
    return res.redirect('/?error=auth_failed');
  }
  
  // Verify state
  const storedState = oauthStates.get(state);
  if (!storedState) {
    return res.redirect('/?error=invalid_state');
  }
  
  const { verifier } = storedState;
  oauthStates.delete(state);
  
  try {
    // Exchange code for access token
    const tokenResponse = await fetch('https://api.twitter.com/2/oauth2/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': 'Basic ' + Buffer.from(`${CONFIG.X_CLIENT_ID}:${CONFIG.X_CLIENT_SECRET}`).toString('base64')
      },
      body: new URLSearchParams({
        code,
        grant_type: 'authorization_code',
        redirect_uri: `${CONFIG.BASE_URL}/auth/callback`,
        code_verifier: verifier
      })
    });
    
    const tokenData = await tokenResponse.json();
    
    if (!tokenData.access_token) {
      console.error('Token error:', tokenData);
      return res.redirect('/?error=token_failed');
    }
    
    // Get user info from X
    const userResponse = await fetch('https://api.twitter.com/2/users/me?user.fields=profile_image_url,public_metrics', {
      headers: {
        'Authorization': `Bearer ${tokenData.access_token}`
      }
    });
    
    const userData = await userResponse.json();
    
    if (!userData.data) {
      console.error('User data error:', userData);
      return res.redirect('/?error=user_failed');
    }
    
    const xUser = userData.data;
    
    // Check if user exists in database
    let { data: existingUser } = await supabase
      .from('users')
      .select('*')
      .eq('x_id', xUser.id)
      .single();
    
    let user;
    
    if (existingUser) {
      // Update existing user
      const { data: updatedUser } = await supabase
        .from('users')
        .update({
          username: xUser.username,
          display_name: xUser.name,
          avatar_url: xUser.profile_image_url?.replace('_normal', '_400x400'),
          followers_count: xUser.public_metrics?.followers_count || 0,
          last_seen: new Date().toISOString()
        })
        .eq('x_id', xUser.id)
        .select()
        .single();
      
      user = updatedUser;
    } else {
      // Create new user
      const { data: newUser } = await supabase
        .from('users')
        .insert({
          x_id: xUser.id,
          username: xUser.username,
          display_name: xUser.name,
          avatar_url: xUser.profile_image_url?.replace('_normal', '_400x400'),
          followers_count: xUser.public_metrics?.followers_count || 0
        })
        .select()
        .single();
      
      user = newUser;
      
      // Add to activity feed
      await supabase.from('activity').insert({
        type: 'JOIN',
        user_id: user.id,
        username: user.username,
        avatar_url: user.avatar_url
      });
    }
    
    // Set session cookie
    res.cookie('session', user.id, {
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days
    });
    
    res.redirect('/');
    
  } catch (err) {
    console.error('Auth error:', err);
    res.redirect('/?error=auth_error');
  }
});

// Logout
app.get('/auth/logout', (req, res) => {
  res.clearCookie('session');
  res.redirect('/');
});

// Get current user
app.get('/api/me', async (req, res) => {
  const user = await getUser(req);
  res.json({ user });
});

// ============================================
// STATS ROUTES
// ============================================

// Get platform stats
app.get('/api/stats', async (req, res) => {
  try {
    const { count: totalUsers } = await supabase
      .from('users')
      .select('*', { count: 'exact', head: true });
    
    // Users active in last 5 minutes
    const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000).toISOString();
    const { count: onlineUsers } = await supabase
      .from('users')
      .select('*', { count: 'exact', head: true })
      .gte('last_seen', fiveMinutesAgo);
    
    const { data: tasks } = await supabase
      .from('tasks')
      .select('reward, slots_filled')
      .eq('is_active', true);
    
    const totalPaidOut = tasks?.reduce((sum, t) => sum + (t.reward * t.slots_filled), 0) || 0;
    const totalTasks = tasks?.length || 0;
    
    res.json({
      totalUsers: totalUsers || 0,
      onlineUsers: onlineUsers || 0,
      totalPaidOut,
      totalTasks
    });
  } catch (err) {
    console.error('Stats error:', err);
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});

// ============================================
// ACTIVITY ROUTES
// ============================================

// Get recent activity
app.get('/api/activity', async (req, res) => {
  try {
    const { data } = await supabase
      .from('activity')
      .select('*')
      .order('created_at', { ascending: false })
      .limit(20);
    
    res.json({ activity: data || [] });
  } catch (err) {
    console.error('Activity error:', err);
    res.status(500).json({ error: 'Failed to fetch activity' });
  }
});

// ============================================
// TASKS ROUTES
// ============================================

// Get all active tasks
app.get('/api/tasks', async (req, res) => {
  try {
    const { data } = await supabase
      .from('tasks')
      .select('*')
      .eq('is_active', true)
      .order('created_at', { ascending: false });
    
    res.json({ tasks: data || [] });
  } catch (err) {
    console.error('Tasks error:', err);
    res.status(500).json({ error: 'Failed to fetch tasks' });
  }
});

// Get single task
app.get('/api/tasks/:id', async (req, res) => {
  try {
    const { data } = await supabase
      .from('tasks')
      .select('*')
      .eq('id', req.params.id)
      .single();
    
    res.json({ task: data });
  } catch (err) {
    res.status(404).json({ error: 'Task not found' });
  }
});

// ============================================
// SUBMISSIONS ROUTES
// ============================================

// Submit proof for a task
app.post('/api/submissions', async (req, res) => {
  const user = await getUser(req);
  if (!user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  
  const { task_id, proof_url } = req.body;
  
  if (!task_id || !proof_url) {
    return res.status(400).json({ error: 'Missing task_id or proof_url' });
  }
  
  try {
    // Check task exists and has slots
    const { data: task } = await supabase
      .from('tasks')
      .select('*')
      .eq('id', task_id)
      .single();
    
    if (!task) {
      return res.status(404).json({ error: 'Task not found' });
    }
    
    if (task.slots_filled >= task.slots_total) {
      return res.status(400).json({ error: 'No slots available' });
    }
    
    // Check if user already submitted
    const { data: existing } = await supabase
      .from('submissions')
      .select('id')
      .eq('user_id', user.id)
      .eq('task_id', task_id)
      .single();
    
    if (existing) {
      return res.status(400).json({ error: 'Already submitted' });
    }
    
    // Create submission
    const { data: submission } = await supabase
      .from('submissions')
      .insert({
        user_id: user.id,
        task_id,
        proof_url
      })
      .select()
      .single();
    
    res.json({ submission });
  } catch (err) {
    console.error('Submission error:', err);
    res.status(500).json({ error: 'Failed to create submission' });
  }
});

// Get user's submissions
app.get('/api/submissions', async (req, res) => {
  const user = await getUser(req);
  if (!user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  
  try {
    const { data } = await supabase
      .from('submissions')
      .select('*, tasks(*)')
      .eq('user_id', user.id)
      .order('created_at', { ascending: false });
    
    res.json({ submissions: data || [] });
  } catch (err) {
    console.error('Submissions error:', err);
    res.status(500).json({ error: 'Failed to fetch submissions' });
  }
});

// ============================================
// USERS/HUNTERS ROUTES
// ============================================

// Get leaderboard
app.get('/api/leaderboard', async (req, res) => {
  try {
    const { data } = await supabase
      .from('users')
      .select('id, username, display_name, avatar_url, total_earned, tasks_completed, rank')
      .order('total_earned', { ascending: false })
      .limit(20);
    
    res.json({ leaderboard: data || [] });
  } catch (err) {
    console.error('Leaderboard error:', err);
    res.status(500).json({ error: 'Failed to fetch leaderboard' });
  }
});

// Get all hunters
app.get('/api/hunters', async (req, res) => {
  try {
    const { data } = await supabase
      .from('users')
      .select('id, username, display_name, avatar_url, total_earned, tasks_completed, created_at')
      .order('created_at', { ascending: false });
    
    res.json({ hunters: data || [] });
  } catch (err) {
    console.error('Hunters error:', err);
    res.status(500).json({ error: 'Failed to fetch hunters' });
  }
});

// ============================================
// PROFILE ROUTES
// ============================================

// Update wallet address
app.post('/api/profile/wallet', async (req, res) => {
  const user = await getUser(req);
  if (!user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  
  const { wallet_address } = req.body;
  
  try {
    const { data } = await supabase
      .from('users')
      .update({ wallet_address })
      .eq('id', user.id)
      .select()
      .single();
    
    res.json({ user: data });
  } catch (err) {
    console.error('Wallet update error:', err);
    res.status(500).json({ error: 'Failed to update wallet' });
  }
});

// ============================================
// ADMIN ROUTES (for you to manage tasks)
// ============================================

// Create task (simple auth with secret key)
app.post('/api/admin/tasks', async (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  if (adminKey !== process.env.ADMIN_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  const { title, description, reward, category, difficulty, slots_total, expires_at } = req.body;
  
  try {
    const { data } = await supabase
      .from('tasks')
      .insert({
        title,
        description,
        reward,
        category: category || 'SOCIAL',
        difficulty: difficulty || 'EASY',
        slots_total: slots_total || 10,
        expires_at
      })
      .select()
      .single();
    
    res.json({ task: data });
  } catch (err) {
    console.error('Create task error:', err);
    res.status(500).json({ error: 'Failed to create task' });
  }
});

// Approve submission (marks as approved, updates user stats)
app.post('/api/admin/submissions/:id/approve', async (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  if (adminKey !== process.env.ADMIN_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  try {
    // Get submission
    const { data: submission } = await supabase
      .from('submissions')
      .select('*, tasks(*), users(*)')
      .eq('id', req.params.id)
      .single();
    
    if (!submission) {
      return res.status(404).json({ error: 'Submission not found' });
    }
    
    // Update submission status
    await supabase
      .from('submissions')
      .update({ 
        status: 'APPROVED',
        reviewed_at: new Date().toISOString()
      })
      .eq('id', req.params.id);
    
    // Update user stats
    await supabase
      .from('users')
      .update({
        total_earned: submission.users.total_earned + submission.tasks.reward,
        tasks_completed: submission.users.tasks_completed + 1,
        xp: submission.users.xp + 100
      })
      .eq('id', submission.user_id);
    
    // Update task slots
    await supabase
      .from('tasks')
      .update({
        slots_filled: submission.tasks.slots_filled + 1
      })
      .eq('id', submission.task_id);
    
    // Add to activity
    await supabase.from('activity').insert({
      type: 'EARN',
      user_id: submission.user_id,
      username: submission.users.username,
      avatar_url: submission.users.avatar_url,
      amount: submission.tasks.reward,
      task_name: submission.tasks.title
    });
    
    res.json({ success: true });
  } catch (err) {
    console.error('Approve error:', err);
    res.status(500).json({ error: 'Failed to approve submission' });
  }
});

// Reject submission
app.post('/api/admin/submissions/:id/reject', async (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  if (adminKey !== process.env.ADMIN_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  try {
    await supabase
      .from('submissions')
      .update({ 
        status: 'REJECTED',
        reviewed_at: new Date().toISOString()
      })
      .eq('id', req.params.id);
    
    res.json({ success: true });
  } catch (err) {
    console.error('Reject error:', err);
    res.status(500).json({ error: 'Failed to reject submission' });
  }
});

// Get all pending submissions
app.get('/api/admin/submissions/pending', async (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  if (adminKey !== process.env.ADMIN_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  try {
    const { data } = await supabase
      .from('submissions')
      .select('*, tasks(*), users(*)')
      .eq('status', 'PENDING')
      .order('created_at', { ascending: true });
    
    res.json({ submissions: data || [] });
  } catch (err) {
    console.error('Pending submissions error:', err);
    res.status(500).json({ error: 'Failed to fetch submissions' });
  }
});

// ============================================
// HEARTBEAT (keep user online status updated)
// ============================================

app.post('/api/heartbeat', async (req, res) => {
  const user = await getUser(req);
  if (user) {
    await supabase
      .from('users')
      .update({ last_seen: new Date().toISOString() })
      .eq('id', user.id);
  }
  res.json({ ok: true });
});

// ============================================
// SERVE FRONTEND
// ============================================

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`EARNR server running on port ${PORT}`);
});

module.exports = app;
