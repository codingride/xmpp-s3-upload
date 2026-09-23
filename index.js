import express from 'express';
import crypto from 'crypto';
import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';
import 'dotenv/config';

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET = process.env.PROSODY_SECRET;

const r2Client = new S3Client({
  region: 'auto',
  endpoint: `https://${process.env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`,
  credentials: {
    accessKeyId: process.env.R2_ACCESS_KEY_ID,
    secretAccessKey: process.env.R2_SECRET_ACCESS_KEY,
  },
});

function validateProsodySignature(path, queryString) {
  try {
    const params = new URLSearchParams(queryString);
    const receivedToken = params.get('v2');
    if (!receivedToken) return false;

    params.delete('v2');

    const remainingQuery = params.toString();
    const signedData = remainingQuery ? `${path}?${remainingQuery}` : path;

    const expectedToken = crypto
      .createHmac('sha256', SECRET)
      .update(signedData)
      .digest('hex');

    return crypto.timingSafeEqual(Buffer.from(receivedToken), Buffer.from(expectedToken));
  } catch (error) {
    console.log(error);
  }
}

app.get('/upload/:slot/:filename', (req, res) => {
  const { slot, filename } = req.params;
  return res.redirect(`${process.env.R2_PUBLIC_DOMAIN}/${slot}/${filename}`);
});

app.put('/upload/:slot/:filename', async (req, res) => {
  const { slot, filename } = req.params;
  const rawPath = req.path;
  const queryString = req.url.split('?')[1] || '';

  if (!validateProsodySignature(rawPath, queryString)) {
    return res.status(403).send('Forbidden: Invalid HMAC signature token.');
  }

  try {
    const contentLength = req.headers['content-length'];
    const contentType = req.headers['content-type'] || 'application/octet-stream';

    if (!contentLength) {
      return res.status(411).send('Length Required');
    }

    const uploadParams = {
      Bucket: process.env.R2_BUCKET_NAME,
      Key: `${slot}/${filename}`,
      Body: req,
      ContentType: contentType,
      ContentLength: parseInt(contentLength, 10)
    };

    await r2Client.send(new PutObjectCommand(uploadParams));

    res.status(201).send('File uploaded successfully to R2.');
  } catch (error) {
    console.error('R2 Upload Failure:', error);
    res.status(500).send('Internal Server Error while pushing to cloud storage.');
  }
});

app.listen(PORT, () => {
  console.log(`Prosody R2 Filer backend listening on port ${PORT}`);
});
