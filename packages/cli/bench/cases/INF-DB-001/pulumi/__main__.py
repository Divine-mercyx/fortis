import pulumi_aws as aws

core = aws.rds.Instance("core", engine="postgres", publicly_accessible=True)  # @hit
aurora = aws.rds.ClusterInstance("aurora-1", cluster_identifier=cluster.id, publicly_accessible=True)  # @hit
replica = aws.rds.Instance("replica", engine="postgres", publicly_accessible=False)
