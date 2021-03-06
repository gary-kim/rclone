---
date: 2019-06-15T12:00:42+01:00
title: "rclone version"
slug: rclone_version
url: /commands/rclone_version/
---
## rclone version

Show the version number.

### Synopsis


Show the version number, the go version and the architecture.

Eg

    $ rclone version
    rclone v1.41
    - os/arch: linux/amd64
    - go version: go1.10

If you supply the --check flag, then it will do an online check to
compare your version with the latest release and the latest beta.

    $ rclone version --check
    yours:  1.42.0.6
    latest: 1.42          (released 2018-06-16)
    beta:   1.42.0.5      (released 2018-06-17)

Or

    $ rclone version --check
    yours:  1.41
    latest: 1.42          (released 2018-06-16)
      upgrade: https://downloads.rclone.org/v1.42
    beta:   1.42.0.5      (released 2018-06-17)
      upgrade: https://beta.rclone.org/v1.42-005-g56e1e820



```
rclone version [flags]
```

### Options

```
      --check   Check for new version.
  -h, --help    help for version
```

### SEE ALSO

* [rclone](/commands/rclone/)	 - Show help for rclone commands, flags and backends.

###### Auto generated by spf13/cobra on 15-Jun-2019
