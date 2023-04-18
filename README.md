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
db, err := gdb.New(gdb.ConfigNode{
    Type: "mysql",
    Link: "root:root@tcp(127.0.0.1:3306)/casbin",
})
if err != nil {
    panic(err)
}
a, _ := NewAdapter(context.Background(), db, "", "casbin_rule")
```

## Notice
you should create the database on your own.

## Getting Help

- [Casbin](https://github.com/casbin/casbin)

## License

This project is under Apache 2.0 License. See the [LICENSE](LICENSE) file for the full license text.
