# Vercel Deployment Guide for Secure File Manager

## Prerequisites
- GitHub account with your code pushed
- Vercel account (vercel.com)
- PostgreSQL database (Vercel Postgres, Railway, ElephantSQL, or similar)

## Step-by-Step Deployment

### 1. Create a PostgreSQL Database
Choose one option:
- **Vercel Postgres** (easiest if using Vercel): https://vercel.com/docs/postgres
- **Railway**: https://railway.app
- **ElephantSQL**: https://www.elephantsql.com
- **AWS RDS**: PostgreSQL on AWS

Get your database connection string (looks like: `postgresql://user:password@host:port/dbname`)

### 2. Push Code to GitHub
```bash
git init
git add .
git commit -m "Initial commit"
git push origin main
```

### 3. Connect Vercel to GitHub
1. Go to https://vercel.com/dashboard
2. Click "Add New Project"
3. Select "Import Git Repository"
4. Select your GitHub repository
5. Click "Import"

### 4. Configure Environment Variables in Vercel
In the Vercel dashboard, go to **Settings → Environment Variables** and add:

#### Required Variables:
- `DATABASE_URL` = Your PostgreSQL connection string (from step 1)
- `SECRET_KEY` = Generate a random secret key (e.g., `python -c "import secrets; print(secrets.token_hex(32))"`)

#### Optional Variables (for features):
- `MAIL_USERNAME` = Your Gmail address
- `MAIL_PASSWORD` = Gmail app password (not your regular password)
- `GOOGLE_OAUTH_CLIENT_ID` = From Google Cloud Console
- `GOOGLE_OAUTH_CLIENT_SECRET` = From Google Cloud Console
- `FACEBOOK_OAUTH_CLIENT_ID` = From Facebook Developers
- `FACEBOOK_OAUTH_CLIENT_SECRET` = From Facebook Developers
- `PUBLIC_BASE_URL` = Your deployed domain (e.g., `https://yourdomain.vercel.app`)

### 5. Deploy
1. Click "Deploy" in Vercel dashboard
2. Wait for build to complete
3. Your app should be live at `https://<project-name>.vercel.app`

## Troubleshooting

### 404 Errors
- ✅ Make sure `api/index.py` exists
- ✅ Make sure `vercel.json` is configured correctly
- ✅ Check that all routes are properly registered

### Database Connection Issues
- ✅ Verify `DATABASE_URL` is set correctly in Vercel Environment Variables
- ✅ Make sure PostgreSQL database is running and accessible
- ✅ Check database credentials in the connection string

### Import Errors
- ✅ Run `pip install -r requirements.txt` locally to test
- ✅ Check all dependencies are in `requirements.txt`
- ✅ Make sure Python version 3.9+ is used

### File Upload Issues
- ✅ Vercel uses `/tmp` for temporary storage (files deleted after function ends)
- ✅ Consider using AWS S3 or similar for persistent storage
- ⚠️ Current setup stores files in `/tmp` - they will be deleted!

## Important Notes

1. **Temporary File Storage**: Files uploaded to Vercel are stored in `/tmp` and are deleted after the serverless function ends. For a production app, integrate AWS S3 or similar.

2. **Environment Variables**: Don't commit `.env` file to GitHub! Always use Vercel dashboard to set environment variables.

3. **Database**: SQLite is no longer used. PostgreSQL is required for Vercel deployment.

4. **Debugging**: Check Vercel logs by clicking "View Deployment" → "Logs" in the dashboard.

## Quick Commands

```bash
# Test locally
python run.py

# Install dependencies
pip install -r requirements.txt

# Generate secure secret key
python -c "import secrets; print(secrets.token_hex(32))"
```

## Additional Resources
- Vercel Python Guide: https://vercel.com/docs/concepts/functions/serverless-functions/runtimes/python
- Flask on Vercel: https://vercel.com/docs/frameworks/flask
- PostgreSQL Documentation: https://www.postgresql.org/docs/
