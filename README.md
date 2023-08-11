# gf-adapter

[GF ORM](https://github.com/gogf/gf) adapter for [Casbin](https://github.com/casbin/casbin).

Tested in:

- MySQL

## Installation

    go get github.com/zcyc/gf-adapter/v2
    go mod tidy

## Usage example

```go
a, _ := NewAdapter(context.Background(), gdb.DefaultGroupName, "", nil)
```

## Notice

you should create the database on your own.

## Getting Help

- [Casbin](https://github.com/casbin/casbin)

## License

This project is under Apache 2.0 License. See the [LICENSE](LICENSE) file for the full license text.
