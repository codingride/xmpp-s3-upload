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

/**
 * Validates Prosody token using the exact layout from the PHP creator script.
 * Format: HMAC-SHA256("filename filesize", SECRET)
 */
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

// GET Route redirection to R2 public domain
app.get('/upload/:slot/:filename', (req, res) => {
  const { slot, filename } = req.params;
  return res.redirect(`${process.env.R2_PUBLIC_DOMAIN}/${slot}/${filename}`);
});

// PUT Route to handle uploads
app.put('/upload/:slot/:filename', async (req, res) => {
  const { slot, filename } = req.params;
  
  // Prosody provides the original path schema via request properties or matching the slot configuration
  const uploadFileName = `${slot}/${filename}`; 
  const contentLength = req.headers['content-length'];
  const uploadToken = req.query.v; // The token key parameter is 'v', not 'v2'

  if (!contentLength) {
    return res.status(411).send('Length Required');
  }

  // Validate signature exactly like mod_http_upload_external expects
  if (!validateProsodySignature(uploadFileName, contentLength, uploadToken)) {
    console.log(`Token mismatch context: Received token ${uploadToken}`);
    return res.status(403).send('Forbidden: Invalid HMAC signature token.');
  }

  try {
    const contentType = req.headers['content-type'] || 'application/octet-stream';

    const uploadParams = {
      Bucket: process.env.R2_BUCKET_NAME,
      Key: `${slot}/${filename}`,
      Body: req, // Streams the incoming request directly to S3/R2
      ContentType: contentType,
      ContentLength: parseInt(contentLength, 10)
    };

    await r2Client.send(new PutObjectCommand(uploadParams));

    // A HTTP status Code of 201 means that the server is ready to serve the file
    res.status(201).send('File uploaded successfully to R2.');
  } catch (error) {
    console.error('R2 Upload Failure:', error);
    res.status(500).send('Internal Server Error while pushing to cloud storage.');
  }
});

app.listen(PORT, () => {
  console.log(`Prosody R2 Filer backend listening on port ${PORT}`);
});
