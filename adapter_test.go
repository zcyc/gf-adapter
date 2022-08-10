package adapter

import (
	"net/http"
	"testing"

	"github.com/casbin/casbin/v2"
	_ "github.com/gogf/gf/contrib/drivers/clickhouse/v2"
	_ "github.com/gogf/gf/contrib/drivers/mssql/v2"
	_ "github.com/gogf/gf/contrib/drivers/mysql/v2"
	_ "github.com/gogf/gf/contrib/drivers/pgsql/v2"
	_ "github.com/gogf/gf/contrib/drivers/sqlite/v2"

	// _ "github.com/gogf/gf/contrib/drivers/oracle/v2"
	"github.com/gogf/gf/v2/database/gdb"
)

const (
	ActionGet    = "GET"
	ActionPost   = "POST"
	ActionPut    = "PUT"
	ActionDelete = "DELETE"
	ActionAll    = "GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD"
	AdminName    = "admin" //超级管理员用户名
)

var Enforcer *casbin.Enforcer

// init description
func init() {
	var err error
	myDB, err := gdb.New(gdb.ConfigNode{
		Type: "mysql",
		Link: "root:root@tcp(127.0.0.1:3306)/casbin",
	})
	if err != nil {
		panic(err)
	}
	a, _ := NewAdapter(myDB, "", "casbin_rule")
	Enforcer, err = casbin.NewEnforcer("./examples/rbac_model.conf", a)
	if err != nil {
		panic(err)
	}
	err = Enforcer.LoadPolicy()
	if err != nil {
		panic(err)
	}
}

// TestNew description
func TestNew(t *testing.T) {
	user := AdminName
	path := "/"
	method := http.MethodGet
	t.Logf("\nuser:%v\npath:%v\nmethod:%v", user, path, method)

	ok, err := Enforcer.DeletePermissionsForUser(user)
	if err != nil {
		t.Error(err)
	}
	t.Logf("delete user premission:%v", ok)
	CheckPremission(t, user, path, method)
	AddPremission(t, user, "*", ActionAll)
	CheckPremission(t, user, path, method)

	user1 := "user1"
	path1 := "/api/v1/*"
	checkPathTrue := "/api/v1/user/list"
	checkPathFalse := "/api/v2/user/list"
	AddPremission(t, user1, path1, ActionGet)
	CheckPremission(t, user1, checkPathTrue, ActionPost)
	CheckPremission(t, user1, checkPathFalse, http.MethodGet)
	CheckPremission(t, user1, checkPathTrue, http.MethodGet)
}

// CheckPremission description
func CheckPremission(t *testing.T, user string, path string, method string) {
	ok, err := Enforcer.Enforce(user, path, method)
	if err != nil {
		t.Error(err)
	}
	t.Logf("check \tuser[%s] \tpremission[%s] \tpath[%s] \tallow[%v]", user, method, path, ok)
}

// Add description
func AddPremission(t *testing.T, user string, path string, method string) {
	ok, err := Enforcer.AddPolicy(user, path, method)
	if err != nil {
		t.Error(err)
	}
	t.Logf("add \tuser[%s] \tpremission[%s] \tpath[%s] \tresult[%v]", user, method, path, ok)
}
