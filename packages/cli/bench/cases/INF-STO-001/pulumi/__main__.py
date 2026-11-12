import pulumi_aws as aws
import pulumi_azure_native as azure

aws.s3.BucketAclV2("kyc", bucket=bucket.id, acl="public-read-write")  # @hit
aws.s3.BucketPublicAccessBlock("kyc", bucket=bucket.id, restrict_public_buckets=False)  # @hit
azure.storage.StorageAccount("docs", allow_blob_public_access=True, kind="StorageV2")  # @hit
aws.s3.BucketPublicAccessBlock("ok", bucket=bucket.id, block_public_acls=True)
