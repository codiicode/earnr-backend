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
    if (p === '/api/stats') { var r = await supabase.from('users').select('*', {count: 'exact', head: true}); var fiveMinAgo = new Date(Date.now() - 5*60*1000).toISOString(); var online = await supabase.from('users').select('*', {count: 'exact', head: true}).gte('last_seen', fiveMinAgo); return res.status(200).json({totalUsers: r.count || 0, onlineUsers: online.count || 0, totalPaidOut: 0, totalTasks: 0}); }
    if (p === '/api/activity') { var r = await supabase.from('activity').select('*').order('created_at', {ascending: false}).limit(20); return res.status(200).json({activity: r.data || []}); }
    if (p === '/api/tasks') { var r = await supabase.from('tasks').select('*').eq('is_active', true); return res.status(200).json({tasks: r.data || []}); }
    if (p === '/api/leaderboard') { var r = await supabase.from('users').select('*').order('total_earned', {ascending: false}).limit(20); return res.status(200).json({leaderboard: r.data || []}); }
    if (p === '/api/earnrs' || p === '/api/hunters') { var r = await supabase.from('users').select('*').order('created_at', {ascending: false}); return res.status(200).json({earnrs: r.data || [], hunters: r.data || []}); }
    if (p === '/api/heartbeat') { var u = await getUser(); if(u) await supabase.from('users').update({last_seen: new Date().toISOString()}).eq('id', u.id); return res.status(200).json({ok: true}); }
    if (p === '/api/wallet' && req.method === 'POST') { var u = await getUser(); if(!u) return res.status(401).json({error: 'Not logged in'}); var body = ''; for await (var chunk of req) { body += chunk; } var data = JSON.parse(body); await supabase.from('users').update({wallet_address: String(data.wallet || '').trim()}).eq('id', u.id); return res.status(200).json({success: true}); }

    // Payouts API - Fetch live Solana transactions from payout wallet
    if (p === '/api/payouts') {
      var PAYOUT_WALLET = String(process.env.PAYOUT_WALLET_ADDRESS || '').trim();
      if (!PAYOUT_WALLET) {
        return res.status(200).json({
          transactions: [],
          stats: { balance: 0, totalPaidOut: 0, transactionCount: 0 },
          error: 'Payout wallet not configured'
        });
      }

      try {
        // Fetch recent transactions using Solana public RPC
        var txResponse = await fetch('https://api.mainnet-beta.solana.com', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id: 1,
            method: 'getSignaturesForAddress',
            params: [PAYOUT_WALLET, { limit: 50 }]
          })
        });
        var txData = await txResponse.json();
        var signatures = txData.result || [];

        // Fetch USDC token account balance
        var USDC_MINT = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';
        var balanceResponse = await fetch('https://api.mainnet-beta.solana.com', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id: 1,
            method: 'getTokenAccountsByOwner',
            params: [PAYOUT_WALLET, { mint: USDC_MINT }, { encoding: 'jsonParsed' }]
          })
        });
        var balanceData = await balanceResponse.json();
        var usdcBalance = 0;
        if (balanceData.result && balanceData.result.value && balanceData.result.value.length > 0) {
          var tokenInfo = balanceData.result.value[0].account.data.parsed.info;
          usdcBalance = tokenInfo.tokenAmount.uiAmount || 0;
        }

        // Get transaction details for each signature (limited to last 20 for performance)
        var transactions = [];
        var totalPaidOut = 0;

        for (var i = 0; i < Math.min(signatures.length, 20); i++) {
          var sig = signatures[i];
          try {
            var txDetailRes = await fetch('https://api.mainnet-beta.solana.com', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                jsonrpc: '2.0',
                id: 1,
                method: 'getTransaction',
                params: [sig.signature, { encoding: 'jsonParsed', maxSupportedTransactionVersion: 0 }]
              })
            });
            var txDetail = await txDetailRes.json();

            if (txDetail.result) {
              var meta = txDetail.result.meta;
              var blockTime = txDetail.result.blockTime;
              var instructions = txDetail.result.transaction.message.instructions || [];

              // Look for token transfers (USDC payouts)
              var preBalances = meta.preTokenBalances || [];
              var postBalances = meta.postTokenBalances || [];

              for (var j = 0; j < postBalances.length; j++) {
                var post = postBalances[j];
                if (post.mint === USDC_MINT && post.owner !== PAYOUT_WALLET) {
                  var pre = preBalances.find(function(p) { return p.accountIndex === post.accountIndex; });
                  var preAmount = pre ? pre.uiTokenAmount.uiAmount : 0;
                  var postAmount = post.uiTokenAmount.uiAmount || 0;
                  var diff = postAmount - preAmount;

                  if (diff > 0) {
                    transactions.push({
                      signature: sig.signature,
                      recipient: post.owner,
                      amount: diff,
                      timestamp: blockTime * 1000,
                      slot: sig.slot
                    });
                    totalPaidOut += diff;
                  }
                }
              }
            }
          } catch (txErr) {
            // Skip failed transaction fetches
          }
        }

        return res.status(200).json({
          transactions: transactions,
          stats: {
            balance: usdcBalance,
            totalPaidOut: totalPaidOut,
            transactionCount: transactions.length,
            walletAddress: PAYOUT_WALLET
          }
        });
      } catch (err) {
        console.error('Payouts API error:', err);
        return res.status(200).json({
          transactions: [],
          stats: { balance: 0, totalPaidOut: 0, transactionCount: 0 },
          error: err.message
        });
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
