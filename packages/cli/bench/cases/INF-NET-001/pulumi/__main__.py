import pulumi_aws as aws
import pulumi_gcp as gcp

mongo = aws.ec2.SecurityGroup(
    "mongo",
    ingress=[
        aws.ec2.SecurityGroupIngressArgs(protocol="tcp", from_port=27017, to_port=27017, cidr_blocks=["0.0.0.0/0"]),  # @hit
        aws.ec2.SecurityGroupIngressArgs(protocol="tcp", from_port=443, to_port=443, cidr_blocks=["0.0.0.0/0"]),
    ],
)

admin = gcp.compute.Firewall(
    "admin",
    network="default",
    source_ranges=["0.0.0.0/0"],  # @hit
    allows=[gcp.compute.FirewallAllowArgs(protocol="tcp", ports=["22", "3389"])],
)

web = gcp.compute.Firewall("web", network="default", source_ranges=["0.0.0.0/0"], allows=[gcp.compute.FirewallAllowArgs(protocol="tcp", ports=["443"])])
