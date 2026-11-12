import * as k8s from "@pulumi/kubernetes";

new k8s.core.v1.Service("pg", {
  metadata: { name: "pg" },
  spec: { type: "LoadBalancer", ports: [{ port: 5432 }], selector: { app: "pg" } }, // @hit
});

new k8s.core.v1.Service("web", {
  spec: { type: "LoadBalancer", ports: [{ port: 443, targetPort: 3000 }] },
});
