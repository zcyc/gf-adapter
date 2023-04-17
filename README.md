gf-adapter
====

[GF ORM](https://github.com/gogf/gf) adapter for [Casbin](https://github.com/casbin/casbin). 

Based on [GF ORM](https://github.com/gogf/gf), and tested in:
- MySQL

## Installation

    go get github.com/zcyc/gf-adapter/v2
    go mod tidy

## Usage example

```go
myDB, _ := gdb.New(gdb.ConfigNode{
    Type: "mysql",
    Link: "root:root@tcp(127.0.0.1:3306)/casbin",
})
a, _ := NewAdapter(myDB, "", "casbin_rule")
Enforcer, err = casbin.NewEnforcer("./examples/rbac_model.conf", a)
```

## Notice
you should create the database on your own.

## Getting Help

- [Casbin](https://github.com/casbin/casbin)

## License

This project is under Apache 2.0 License. See the [LICENSE](LICENSE) file for the full license text.
