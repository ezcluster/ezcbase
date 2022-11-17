

For a standard cluster:
- domain: <cluster> or <cluster>.<project>.scw01.
- Security groups defined in a cluster definition must be named: <clusterId>.<name>
- Flavor defined in a cluster definition must be named: <project>.<cluster>.<name>

For a 'single node' cluster
- domain: null
- Security groups defined in a cluster definition must be named: <clusterId>.<name>
- Flavor defined in a cluster definition must be named: <project>.<clusterId>.<name>

