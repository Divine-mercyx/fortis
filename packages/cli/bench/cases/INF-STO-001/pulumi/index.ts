import * as aws from "@pulumi/aws";
import * as gcp from "@pulumi/gcp";

const docs = new aws.s3.BucketV2("docs");
new aws.s3.BucketAclV2("docs", { bucket: docs.id, acl: "public-read" }); // @hit
new aws.s3.BucketPublicAccessBlock("docs", {
  bucket: docs.id,
  blockPublicAcls: true,
  blockPublicPolicy: false, // @hit
});
new gcp.storage.BucketIAMMember("public", { bucket: "statements", role: "roles/storage.objectViewer", member: "allUsers" }); // @hit
new aws.s3.BucketAclV2("logs", { bucket: docs.id, acl: "log-delivery-write" });
