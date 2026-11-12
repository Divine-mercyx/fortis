import * as aws from "@pulumi/aws";

export const core = new aws.rds.Instance("core", {
  engine: "postgres",
  instanceClass: "db.t4g.medium",
  publiclyAccessible: true, // @hit
});

export const replica = new aws.rds.Instance("replica", {
  engine: "postgres",
  publiclyAccessible: false,
});
