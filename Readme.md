# Keepass FUSE

FUSE based filesystem to access keepass database on filesystem level.

Currently only readonly access is supported.

## Motivation

I've build this mainly to be able to use keepass as secret store
in combination with [morph](https://github.com/DBCDK/morph).

## Build

In order to build this software `go`, sometimes known as `golang` is needed.

Clone this repository and execute

    go build .

## Dependencies

To execute `keepass-fuse` you need to install fuse.

## Usage

    usage: keepass-fuse [-h|--help] [-p|--password "<value>"] [-e|--password-env
                        "<value>"] [-k|--key-file <file>] -d|--db <file>
                        -m|--mount-point "<value>"

                        Mounts keepass file as filesystem and allows access to
                        stored information as files.

    Arguments:

      -h  --help          Print help information
      -p  --password      Password for keepass database
      -e  --password-env  Name of the environment variable to read keepass database
                          password from.
      -k  --key-file      Key file for keepass database. Default: /dev/null
      -d  --db            Keypass database file
      -m  --mount-point   Path to mountpoint

### Run in the background

Because of Go is not supporting any kind of daemonizing processes at the time,
it's not possible to run `keepass-fuse` in the background "out-of-the-box".

As workaround use the shell `&` syntax to run `keepass-fuse` in background.

    keepass-fuse -m ... -d ... &

## Troubleshooting

### `Error mounting keepass filesystem: fork/exec /Library/Filesystems/osxfusefs.fs/Support/load_osxfusefs: no such file or directory`

This is a known problem with using "old" MacOS versions with the
latest version of macFUSE. Try to use an older macFUSE version, that
also supports your version of MacOS.

## Disclaimer

This software is far beyond stable, so use for yout own risk.
Specially, i've **not** done any security related reviews of any
of the used libraries.

## License

This Code is distributed under the MIT-License.

See `LICENSE` file for full license text.

## Credits

* FUSE implementation based on https://github.com/hanwen/go-fuse
* Keepass parsing based on https://github.com/tobischo/gokeepasslib

