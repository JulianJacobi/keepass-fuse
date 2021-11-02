package main

import (
    "context"
    "fmt"
    "io"
    "os"
    "syscall"
    "time"

    "github.com/akamensky/argparse"
    "github.com/hanwen/go-fuse/v2/fs"
    "github.com/hanwen/go-fuse/v2/fuse"
    keepass "github.com/tobischo/gokeepasslib/v3"
)

var (
    kp *keepass.Database
)

func main() {
    parser := argparse.NewParser("keepass-fuse", "Mounts keepass file as filesystem and allows access to stored information as files.")

    kpPassword := parser.String("p", "password", &argparse.Options{
        Required: false,
        Help: "Password for keepass database",
    })
    kpPasswordEnv := parser.String("e", "password-env", &argparse.Options{
        Required: false,
        Help: "Name of the environment variable to read keepass database password from.",
    })
    kpKeyFile := parser.File("k", "key-file", os.O_RDONLY, 0755, &argparse.Options{
        Required: false,
        Help: "Key file for keepass database",
        // This is a little bit querky, but without this default
        // it's impossible to detect not given argument
        Default: "/dev/null",
    })
    kpDatabase := parser.File("d", "db", os.O_RDONLY, 0755, &argparse.Options{
        Required: true,
        Help: "Keypass database file",
    })
    mountPoint := parser.String("m", "mount-point", &argparse.Options{
        Required: true,
        Help: "Path to mountpoint",
    })

    initialError := func(msg interface{}) {
        fmt.Println(parser.Help(msg))
        os.Exit(1)
    }

    err := parser.Parse(os.Args)
    if err != nil {
        initialError(err)
    }

    var password string
    if len(*kpPassword) > 0 {
        password = *kpPassword
    } else if len(*kpPasswordEnv) > 0 {
        password = os.Getenv(*kpPasswordEnv)
    }

    key, err := io.ReadAll(kpKeyFile)
    if err != nil {
        fmt.Printf("Error while reading key file: %s\n", err)
        os.Exit(2)
    }

    keyCredsErr := func(err error) {
        if err != nil {
            fmt.Printf("Error while creating keepass credentials: %s\n", err)
            os.Exit(3)
        }
    }

    var credentials *keepass.DBCredentials
    if len(password) > 0 && len(key) > 0 {
        credentials, err = keepass.NewPasswordAndKeyDataCredentials(password, key)
        keyCredsErr(err)
    } else if len(password) > 0 {
        credentials = keepass.NewPasswordCredentials(password)
    } else if len(key) > 0 {
        credentials, err = keepass.NewKeyDataCredentials(key)
        keyCredsErr(err)
    } else {
        initialError("Either a password [-p|--password|-e|--password-env] or a key file [-k|--key-file] or both are required")
    }

    kp = keepass.NewDatabase()
    kp.Credentials = credentials
    err = keepass.NewDecoder(kpDatabase).Decode(kp)
    if err != nil {
        fmt.Printf("Error decoding database file: %s\n", err)
        os.Exit(4)
    }

    err = kp.UnlockProtectedEntries()
    if err != nil {
        fmt.Printf("Error while unlocking protected entries: %s\n", err)
        os.Exit(5)
    }

    fssrv, err := fs.Mount(
        *mountPoint,
        &GroupsNode{
            groups: &kp.Content.Root.Groups,
        },
        &fs.Options{
            MountOptions: fuse.MountOptions{
                Options: []string{
                },
                FsName: *mountPoint,
                Name: "keepass",
                EnableLocks: false,
            },
        },
    )
    if err != nil {
        fmt.Printf("Error mounting keepass filesystem: %s\n", err)
        os.Exit(6)
    }
    fmt.Println("Successfully mounted keepass file")
    fssrv.Wait()
}

func entryTitle(e keepass.Entry) string {
    title := e.GetContent("Title")
    if len(title) == 0 {
        uuidBytes := [16]byte(e.UUID)
        return string(uuidBytes[:])
    }
    return title
}

type GroupsNode struct {
    fs.Inode
    group *keepass.Group
    groups *[]keepass.Group
}

func (rn *GroupsNode) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
    dirEntries := []fuse.DirEntry{}
    for _, g := range *rn.groups {
        dirEntries = append(dirEntries, fuse.DirEntry{
            Mode: syscall.S_IFDIR | 0444,
            Name: g.Name,
        })
    }
    return fs.NewListDirStream(dirEntries), syscall.Errno(0)
}

func (rn *GroupsNode) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
    for _, g := range *rn.groups {
        if name == g.Name {
            return rn.NewInode(
                ctx,
                &GroupNode{
                    group: &g,
                },
                fs.StableAttr{
                    Mode: syscall.S_IFDIR | 0444,
                },
            ), syscall.Errno(0)
        }
    }
    return nil, syscall.ENOENT
}

func (gn *GroupsNode) Getattr(ctx context.Context, f fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
    if (gn.group != nil) {
        timeZero := time.Unix(0, 0)
        out.SetTimes(
            &gn.group.Times.LastAccessTime.Time,
            &gn.group.Times.LastModificationTime.Time,
            &timeZero,
        )
    }
    return syscall.Errno(0)
}

type GroupNode struct {
    fs.Inode
    group *keepass.Group
}

func (gn *GroupNode) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
    return fs.NewListDirStream([]fuse.DirEntry{
        fuse.DirEntry{
            Mode: syscall.S_IFDIR | 0444,
            Name: "groups",
        },
        fuse.DirEntry{
            Mode: syscall.S_IFDIR | 0444,
            Name: "entries",
        },
    }), syscall.Errno(0)
}

func (gn *GroupNode) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
    switch name {
    case "groups":
        return gn.NewInode(
            ctx,
            &GroupsNode{
                group: gn.group,
                groups: &gn.group.Groups,
            },
            fs.StableAttr{
                Mode: syscall.S_IFDIR | 0444,
            },
        ), syscall.Errno(0)
    case "entries":
        return gn.NewInode(
            ctx,
            &EntriesNode{
                group: gn.group,
                entries: &gn.group.Entries,
            },
            fs.StableAttr{
                Mode: syscall.S_IFDIR | 0444,
            },
        ), syscall.Errno(0)
    }
    return nil, syscall.ENOENT
}

func (gn *GroupNode) Getattr(ctx context.Context, f fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
    timeZero := time.Unix(0, 0)
    out.SetTimes(
        &gn.group.Times.LastAccessTime.Time,
        &gn.group.Times.LastModificationTime.Time,
        &timeZero,
    )
    return syscall.Errno(0)
}

type EntriesNode struct {
    fs.Inode
    group *keepass.Group
    entries *[]keepass.Entry
}

func (en *EntriesNode) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
    dirEntries := []fuse.DirEntry{}
    for _, e := range *en.entries {
        dirEntries = append(dirEntries, fuse.DirEntry{
            Mode: syscall.S_IFDIR | 0444,
            Name: entryTitle(e),
        })
    }
    return fs.NewListDirStream(dirEntries), syscall.Errno(0)
}

func (en *EntriesNode) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
    for _, e := range *en.entries {
        if name == entryTitle(e) {
            return en.NewInode(
                ctx,
                &EntryNode{
                    entry: &e,
                },
                fs.StableAttr{
                    Mode: syscall.S_IFDIR | 0444,
                },
            ), syscall.Errno(0)
        }
    }
    return nil, syscall.ENOENT
}

func (en *EntriesNode) Getattr(ctx context.Context, f fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
    if (en.group != nil) {
        timeZero := time.Unix(0, 0)
        out.SetTimes(
            &en.group.Times.LastAccessTime.Time,
            &en.group.Times.LastModificationTime.Time,
            &timeZero,
        )
    }
    return syscall.Errno(0)
}

type EntryNode struct {
    fs.Inode
    entry *keepass.Entry
}

func (en * EntryNode) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
    dirEntries := []fuse.DirEntry{}
    for _, vd := range en.entry.Values {
        dirEntries = append(dirEntries, fuse.DirEntry{
            Mode: syscall.S_IFDIR | 0444,
            Name: vd.Key,
        })
    }
    return fs.NewListDirStream(dirEntries), syscall.Errno(0)
}

func (en *EntryNode) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
    for _, vd := range en.entry.Values {
        if vd.Key == name {
            return en.NewInode(
                ctx,
                &ValueNode{
                    entry: en.entry,
                    value: &vd,
                },
                fs.StableAttr{
                    Mode: 0444,
                },
            ), syscall.Errno(0)
        }
    }
    return nil, syscall.ENOENT
}

func (en *EntryNode) Getattr(ctx context.Context, f fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
    timeZero := time.Unix(0, 0)
    out.SetTimes(
        &en.entry.Times.LastAccessTime.Time,
        &en.entry.Times.LastModificationTime.Time,
        &timeZero,
    )
    return syscall.Errno(0)
}

type ValueNode struct {
    fs.Inode
    entry *keepass.Entry
    value *keepass.ValueData
}

func (vn *ValueNode) Getattr(ctx context.Context, f fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
    timeZero := time.Unix(0, 0)
    out.SetTimes(
        &vn.entry.Times.LastAccessTime.Time,
        &vn.entry.Times.LastModificationTime.Time,
        &timeZero,
    )
    out.Size = uint64(len(vn.value.Value.Content))
    return syscall.Errno(0)
}

func (vn *ValueNode) Open(ctx context.Context, flags uint32) (fh fs.FileHandle, fuseFlags uint32, errno syscall.Errno) {
	return nil, fuse.FOPEN_KEEP_CACHE, syscall.Errno(0)
}

func (vn *ValueNode) Read(ctx context.Context, fh fs.FileHandle, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
    end := int(off) + len(dest)
    data := []byte(vn.value.Value.Content)
	if end > len(data) {
		end = len(data)
	}
	return fuse.ReadResultData(data[off:end]), syscall.Errno(0)
}
