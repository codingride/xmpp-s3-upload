import express from 'express';
import crypto from 'crypto';
import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';
import 'dotenv/config';

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET = process.env.PROSODY_SECRET;

// Enable CORS matching the PHP implementation rules
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Methods', 'GET, PUT, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type');
  res.header('Access-Control-Max-Age', '7200');
  res.header('Access-Control-Allow-Origin', '*');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

const r2Client = new S3Client({
  region: 'auto',
  endpoint: `https://${process.env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`,
  credentials: {
    accessKeyId: process.env.R2_ACCESS_KEY_ID,
    secretAccessKey: process.env.R2_SECRET_ACCESS_KEY,
  },
});

function validateProsodySignature(uploadFileName, uploadFileSize, receivedToken) {
  if (!receivedToken || !uploadFileSize) return false;

  const signedData = `${uploadFileName} ${uploadFileSize}`;
  const expectedToken = crypto
    .createHmac('sha256', SECRET)
    .update(signedData)
    .digest('hex');

  try {
    return crypto.timingSafeEqual(
      Buffer.from(receivedToken, 'utf-8'), 
      Buffer.from(expectedToken, 'utf-8')
    );
  } catch (error) {
    console.error("Token comparison error:", error);
    return false;
  }
}

/**
 * CATCH-ALL ROUTE
 * Captures anything appended to the domain root using named wildcard syntax
 */
app.all('/*splat', async (req, res) => {
  // Strip out leading slash to get a clean path (e.g., "slot/filename.png")
  const uploadFileName = req.path.replace(/^\/+/, ''); 

  // Skip requests that don't target an actual file slot path (e.g., favicon)
  if (!uploadFileName || uploadFileName === 'favicon.ico') {
    return res.status(404).send('Not Found');
  }

  const requestMethod = req.method;

  // --- HANDLE GET / HEAD (DOWNLOAD) ---
  if (requestMethod === 'GET' || requestMethod === 'HEAD') {
    console.log(`[GET/HEAD] Redirecting download request for: ${uploadFileName}`);
    return res.redirect(`${process.env.R2_PUBLIC_DOMAIN}/${uploadFileName}`);
  }

  // --- HANDLE PUT (UPLOAD) ---
  if (requestMethod === 'PUT') {
    console.log(`[PUT] Incoming upload request for: ${uploadFileName}`);
    
    const contentLength = req.headers['content-length'];
    const uploadToken = req.query.v; // 'v' query param from mod_http_upload_external

    if (!contentLength) {
      return res.status(411).send('Length Required');
    }

    if (!validateProsodySignature(uploadFileName, contentLength, uploadToken)) {
      console.warn(`⚠️ Token mismatch for ${uploadFileName}. Got: ${uploadToken}`);
      return res.status(403).send('Forbidden: Invalid HMAC signature token.');
    }

    try {
      const contentType = req.headers['content-type'] || 'application/octet-stream';

      const uploadParams = {
        Bucket: process.env.R2_BUCKET_NAME,
        Key: uploadFileName,
        Body: req, 
        ContentType: contentType,
        ContentLength: parseInt(contentLength, 10)
      };

      await r2Client.send(new PutObjectCommand(uploadParams));
      console.log(`✅ Successfully uploaded ${uploadFileName} to R2`);

      return res.sendStatus(201);
    } catch (error) {
      console.error('R2 Upload Failure:', error);
      return res.status(500).send('Internal Server Error while pushing to cloud storage.');
    }
  }

  // Fallback for unhandled verbs
  return res.status(400).send('Bad Request');
});

app.listen(PORT, () => {
  console.log(`Prosody R2 Filer backend listening on port ${PORT}`);
});
