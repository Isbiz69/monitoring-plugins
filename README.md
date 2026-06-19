# Monitoring Plugins

Collection of custom monitoring plugins and scripts for infrastructure, network, backup and application checks.

The repository is intended to gather small, reusable monitoring tools compatible with environments such as Icinga and Nagios.

## Repository structure

```text
monitoring-plugins/
├── python/          # Python monitoring plugins
├── powershell/      # PowerShell monitoring scripts
├── perl/            # Perl monitoring plugins
└── docs/            # General documentation and integration examples
```

## Planned content

- Infrastructure and system checks
- Network and SNMP checks
- Backup and storage checks
- Application and database checks
- Performance data for metrics and dashboards

## Plugin conventions

Unless stated otherwise, scripts follow the standard Nagios/Icinga exit codes:

| Code | Status |
|---:|---|
| 0 | OK |
| 1 | WARNING |
| 2 | CRITICAL |
| 3 | UNKNOWN |

Each plugin will include its own requirements, arguments, usage examples and sample output.

## Security

All examples use fictitious hosts, addresses and credentials. No production secrets or environment-specific information should be committed to this repository.
