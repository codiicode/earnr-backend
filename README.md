# EARNR Backend

Crypto bounty platform backend with X OAuth authentication.

## Quick Deploy to Vercel

### 1. Push to GitHub

Create a new GitHub repo and push this code:

```bash
git init
git add .
git commit -m "Initial commit"
git remote add origin https://github.com/YOUR_USERNAME/earnr-backend.git
git push -u origin main
```

### 2. Deploy to Vercel

1. Go to [vercel.com](https://vercel.com)
2. Click "Add New" → "Project"
3. Import your GitHub repo
4. Add Environment Variables (Settings → Environment Variables):

| Name | Value |
|------|-------|
| X_CLIENT_ID | QWFUUVgzbEVjWUdWZUk3N1JqMmY6MTpjaQ |
| X_CLIENT_SECRET | qGKyhdiPMK5PnnDwjVs40IEXvpAUcho-FASEaGVBnUYtrex8Va |
| SUPABASE_URL | https://zzscefkggaqumiblnkdw.supabase.co |
| SUPABASE_ANON_KEY | (your anon key) |
| SUPABASE_SERVICE_KEY | (your service key) |
| BASE_URL | https://earnr.xyz |
| ADMIN_KEY | (make up a secret key for admin access) |

5. Click "Deploy"

### 3. Connect Your Domain

1. In Vercel, go to Project → Settings → Domains
2. Add `earnr.xyz`
3. Update your domain DNS to point to Vercel

### 4. Update X Developer Settings

Make sure your X app callback URL matches:
- Callback URL: `https://earnr.xyz/auth/callback`
- Website URL: `https://earnr.xyz`

## API Endpoints

### Public
- `GET /api/stats` - Platform statistics
- `GET /api/activity` - Recent activity feed
- `GET /api/tasks` - All active tasks
- `GET /api/leaderboard` - Top hunters
- `GET /api/hunters` - All hunters

### Authenticated (requires login)
- `GET /api/me` - Current user
- `POST /api/submissions` - Submit task proof
- `GET /api/submissions` - User's submissions
- `POST /api/profile/wallet` - Update wallet address

### Admin (requires X-Admin-Key header)
- `POST /api/admin/tasks` - Create new task
- `GET /api/admin/submissions/pending` - View pending submissions
- `POST /api/admin/submissions/:id/approve` - Approve submission
- `POST /api/admin/submissions/:id/reject` - Reject submission

## Creating Tasks (Admin)

```bash
curl -X POST https://earnr.xyz/api/admin/tasks \
  -H "Content-Type: application/json" \
  -H "X-Admin-Key: your-admin-key" \
  -d '{
    "title": "Quote Tweet Launch Post",
    "description": "Add commentary to our pinned tweet. Min 100 followers required.",
    "reward": 5000,
    "category": "SOCIAL",
    "difficulty": "EASY",
    "slots_total": 10
  }'
```

## Approving Submissions (Admin)

```bash
curl -X POST https://earnr.xyz/api/admin/submissions/SUBMISSION_ID/approve \
  -H "X-Admin-Key: your-admin-key"
```
