import { S3Client } from '@aws-sdk/client-s3';
export const s3 = new S3Client({ credentials: { accessKeyId: '{{AWS_KEY}}', secretAccessKey: process.env.AWS_SECRET! } }); // @hit
