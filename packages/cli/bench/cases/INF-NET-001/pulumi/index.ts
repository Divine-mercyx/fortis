import * as aws from "@pulumi/aws";
import * as gcp from "@pulumi/gcp";

export const db = new aws.ec2.SecurityGroup("db", {
  ingress: [
    { protocol: "tcp", fromPort: 5432, toPort: 5432, cidrBlocks: ["0.0.0.0/0"] }, // @hit
    { protocol: "tcp", fromPort: 443, toPort: 443, cidrBlocks: ["0.0.0.0/0"] },
    { protocol: "tcp", fromPort: 22, toPort: 22, cidrBlocks: ["10.0.0.0/8"] },
  ],
  egress: [{ protocol: "-1", fromPort: 0, toPort: 0, cidrBlocks: ["0.0.0.0/0"] }],
});

export const ssh = new aws.ec2.SecurityGroupRule("ssh", {
  type: "ingress",
  fromPort: 22,
  toPort: 22,
  protocol: "tcp",
  cidrBlocks: ["0.0.0.0/0"], // @hit
  securityGroupId: db.id,
});

export const fw = new gcp.compute.Firewall("es", {
  network: "default",
  sourceRanges: ["0.0.0.0/0"], // @hit
  allows: [{ protocol: "tcp", ports: ["9200"] }],
});
