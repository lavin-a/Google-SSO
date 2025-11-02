# Google SSO Integration

Secure OAuth integration between Google and Outseta for the Almeida Racing Academy.

## 🏗️ Architecture

- **Backend**: Vercel serverless function (`api/auth/google.js`)
- **Frontend**: Framer component (`GoogleSSOButton.tsx`)
- **User Management**: Outseta CRM with JWT tokens

## 📋 Setup Instructions

### 1. Get Google OAuth Credentials

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Enable the **Google+ API**
4. Go to **Credentials** → **Create Credentials** → **OAuth client ID**
5. Choose **Web application**
6. Configure:
   - **Name**: "Almeida Racing Academy"
   - **Authorized JavaScript origins**: 
     - `https://almeidaracingacademy.com`
     - `https://your-vercel-app.vercel.app`
   - **Authorized redirect URIs**:
     - `https://your-vercel-app.vercel.app/api/auth/google?action=callback`
7. Save and copy your:
   - `GOOGLE_CLIENT_ID`
   - `GOOGLE_CLIENT_SECRET`

### 2. Deploy Backend to Vercel

```bash
cd "Google SSO"
vercel
```

Set environment variables in Vercel dashboard:
```
GOOGLE_CLIENT_ID=your_client_id
GOOGLE_CLIENT_SECRET=your_client_secret
OUTSETA_DOMAIN=almeidaracingacademy.outseta.com
OUTSETA_API_KEY=your_api_key
OUTSETA_SECRET_KEY=your_secret_key
```

### 3. Add Button to Framer

1. Copy `GoogleSSOButton.tsx` to your Framer project
2. Update the `backendUrl` property to your deployed Vercel URL
3. Add the component to your sign-in page
4. Customize button text and styles as needed

## 🔒 Security Features

✅ Origin validation for postMessage events  
✅ CORS restricted to trusted domains  
✅ XSS protection with input sanitization  
✅ Secure token exchange via backend  
✅ No client-side secrets  
✅ 8-second timeouts on all API calls  
✅ Error messages sanitized before display  
✅ `prompt=none` for seamless re-authentication  

## 🔄 OAuth Flow

1. User clicks "Sign in with Google" button
2. Popup opens to Google authorization page
3. User approves access (first time only)
4. Google redirects to callback with auth code
5. Backend exchanges code for access token
6. Backend fetches user profile from Google
7. Backend creates/updates user in Outseta
8. Backend generates Outseta JWT token
9. Token sent to frontend via postMessage
10. Frontend sets Outseta token and redirects

## 🛠️ Testing

1. Deploy backend to Vercel
2. Set all environment variables
3. Click the button in Framer preview
4. Check browser console for logs
5. Verify user created in Outseta dashboard

## 📝 Notes

- **OAuth Scopes**: `openid email profile` - provides basic user info
- **User Data**: Google provides `email`, `given_name`, `family_name`, `picture`
- **Re-authentication**: With `prompt=none`, returning users sign in instantly
- **Account Creation**: First sign-in automatically creates Outseta account

## 🐛 Troubleshooting

**Popup blocked**: Enable popups for your site  
**401 Unauthorized**: Check Outseta API credentials  
**400 Bad Request**: Verify Google OAuth credentials and redirect URI  
**Token not set**: Check CORS and origin validation  
**"redirect_uri_mismatch"**: Ensure redirect URI in Google Console matches exactly  

## 📚 Related Files

- Discord SSO: `/Discord SSO/`
- iRacing SSO: `/iRacing SSO/`
- Garage61 SSO: `/Garage61 SSO/`
- Framer Components: `/ARA/`


