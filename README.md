# sftp-to-s3-importer

Python script that polls an SFTP server for certain files, temporarily downloads the matched results, and uploads them to an AWS S3 bucket.

⚠️ **Disclaimer**: This is/was a personal project. Expect rough edges; behavior and interfaces may change. Use at your own risk.

#### Notes
1. If using in Lambda, Paramiko must be added as a [layer](https://www.c-sharpcorner.com/article/paramiko-python-library-setup-with-aws-lambda-layer/). 
2. Uses AWS Secrets Manager for private key retrieval and AWS KMS for password decryption. 
3. Lambda must have a correctly configured and entitled execution role with access to the appropriate AWS resources (S3, Secrets Manager, KMS, etc.)
The "trigger" was a scheduled trigger, but options for invoking this flow automatically are up to the user. 
4. The auth flow is a bit odd. Target server was an old, finnicky MFT server (IBM Sterling File Gateway) that was forcing 2FA in the form of password and private key. Modify to your needs and/or target SFTP server. 

### Dependencies:
- paramiko (as Lambda Layer)
- boto3

### Environment Variables Required:
- SFTP_PASS: KMS-encrypted SFTP password
- S3_BUCKET: Target S3 bucket name
- SFTP_USER: SFTP username
- SFTP_HOST: SFTP server hostname
- SFTP_PATH: Remote directory path
- S3_PREFIX: S3 key prefix (optional)
- FILTER_PATTERN: Regex pattern for file filtering
- AWS_LAMBDA_FUNCTION_NAME: Lambda function name for KMS context
- SFTP_SECRET_NAME: Secrets Manager secret name
- AWS_REGION: AWS region (optional, defaults to us-east-1)





