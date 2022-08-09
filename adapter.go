package adapter

import (
	"context"
	"fmt"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"github.com/gogf/gf/v2/database/gdb"
	"math"
	"runtime"
)

type CasbinRule struct {
	Id    int64  `json:"id"`     //
	PType string `json:"p_type"` //
	V0    string `json:"v0"`     //
	V1    string `json:"v1"`     //
	V2    string `json:"v2"`     //
	V3    string `json:"v3"`     //
	V4    string `json:"v4"`     //
	V5    string `json:"v5"`     //
}

const (
	CasbinRuleTableName = "casbin_rule"
)

// Options 输入配置
type Options struct {
	GDB       gdb.DB // gdb
	TableName string // 表名
}

// Adapter represents the Xorm adapter for policy storage.
type Adapter struct {
	DriverName     string
	DataSourceName string
	db             gdb.DB
	tableName      string
}

func NewAdapter(opts Options) *Adapter {
	a := &Adapter{
		db:        opts.GDB,
		tableName: CasbinRuleTableName,
	}

	if opts.TableName != "" {
		a.tableName = opts.TableName
	}

	// Open the DB, create it if not existed.
	a.open()

	// Call the destructor when the object is released.
	runtime.SetFinalizer(a, finalizer)

	return a
}

// NewAdapterWithTableName 设置表名
func NewAdapterWithTableName(gdb gdb.DB, tableName string) *Adapter {
	return NewAdapter(Options{GDB: gdb, TableName: tableName})
}

// finalizer is the destructor for Adapter.
func finalizer(a *Adapter) {
}

func (a *Adapter) open() {
}

func (a *Adapter) close() {
}

func (a *Adapter) createTable() {
}

func (a *Adapter) dropTable() {
}

func loadPolicyLine(line CasbinRule, model model.Model) {
	lineText := line.PType
	if line.V0 != "" {
		lineText += ", " + line.V0
	}
	if line.V1 != "" {
		lineText += ", " + line.V1
	}
	if line.V2 != "" {
		lineText += ", " + line.V2
	}
	if line.V3 != "" {
		lineText += ", " + line.V3
	}
	if line.V4 != "" {
		lineText += ", " + line.V4
	}
	if line.V5 != "" {
		lineText += ", " + line.V5
	}

	persist.LoadPolicyLine(lineText, model)
}

// LoadPolicy loads policy from database.
func (a *Adapter) LoadPolicy(model model.Model) error {
	var lines []CasbinRule
	err := a.db.Model(a.tableName).Scan(&lines)
	if err != nil {
		return err
	}

	for _, line := range lines {
		loadPolicyLine(line, model)
	}

	return nil
}

func (a *Adapter) buildPolicyRule(ptype string, rule []string) CasbinRule {
	line := CasbinRule{}

	line.PType = ptype
	if len(rule) > 0 {
		line.V0 = rule[0]
	}
	if len(rule) > 1 {
		line.V1 = rule[1]
	}
	if len(rule) > 2 {
		line.V2 = rule[2]
	}
	if len(rule) > 3 {
		line.V3 = rule[3]
	}
	if len(rule) > 4 {
		line.V4 = rule[4]
	}
	if len(rule) > 5 {
		line.V5 = rule[5]
	}

	return line
}

// SavePolicy saves policy to database.
func (a *Adapter) SavePolicy(model model.Model) error {

	var lines []CasbinRule

	for ptype, ast := range model["p"] {
		for _, rule := range ast.Policy {
			line := a.buildPolicyRule(ptype, rule)
			lines = append(lines, line)
		}
	}

	for ptype, ast := range model["g"] {
		for _, rule := range ast.Policy {
			line := a.buildPolicyRule(ptype, rule)
			lines = append(lines, line)
		}
	}

	_, err := a.db.Insert(context.TODO(), a.tableName, lines)
	return err
}

// AddPolicy adds a policy rule to the storage.
func (a *Adapter) AddPolicy(sec string, ptype string, rule []string) error {
	line := a.buildPolicyRule(ptype, rule)
	_, err := a.db.Insert(context.TODO(), a.tableName, &line)
	return err
}

// AddPolicies adds policy rules to the storage.
func (a *Adapter) AddPolicies(sec string, ptype string, rules [][]string) (err error) {
	if len(rules) == 0 {
		return
	}

	policyRules := make([]CasbinRule, 0, len(rules))

	for _, rule := range rules {
		policyRules = append(policyRules, a.buildPolicyRule(ptype, rule))
	}

	_, err = a.db.Insert(context.TODO(), a.tableName, policyRules)

	return
}

// UpdatePolicy updates a policy rule from storage.
func (a *Adapter) UpdatePolicy(sec string, ptype string, oldRule, newRule []string) (err error) {
	_, err = a.db.Update(context.Background(), a.tableName, a.buildPolicyRule(ptype, newRule), a.buildPolicyRule(ptype, oldRule))

	return
}

// UpdatePolicies updates some policy rules to storage, like db, redis.
func (a *Adapter) UpdatePolicies(sec string, ptype string, oldRules, newRules [][]string) (err error) {
	if len(oldRules) == 0 || len(newRules) == 0 {
		return
	}

	err = a.db.Transaction(context.TODO(), func(ctx context.Context, tx *gdb.TX) error {
		for i := 0; i < int(math.Min(float64(len(oldRules)), float64(len(newRules)))); i++ {
			if _, err = tx.Model(a.tableName).Update(a.buildPolicyRule(ptype, newRules[i]), a.buildPolicyRule(ptype, oldRules[i])); err != nil {
				return err
			}
		}

		return nil
	})

	return
}

// RemovePolicy removes a policy rule from the storage.
func (a *Adapter) RemovePolicy(sec string, ptype string, rule []string) error {
	qs := a.db.Model(a.tableName).Safe()
	qs = qs.Where("p_type", ptype)
	for index := 0; index < len(rule); index++ {
		qs = qs.Where(fmt.Sprintf("v%d", index), rule[index])
	}
	_, err := qs.Delete()
	return err

}

// RemovePolicies removes policy rules from the storage (implements the persist.BatchAdapter interface).
func (a *Adapter) RemovePolicies(sec string, ptype string, rules [][]string) (err error) {
	db := a.db.Model()

	for _, rule := range rules {
		where := map[string]interface{}{"p_type": ptype}

		for i := 0; i <= 5; i++ {
			if len(rule) > i {
				where[fmt.Sprintf("v%d", i)] = rule[i]
			}
		}

		db = db.WhereOr(where)
	}

	_, err = db.Delete()

	return
}

// RemoveFilteredPolicy removes policy rules that match the filter from the storage.
func (a *Adapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	qs := a.db.Model(a.tableName).Safe()
	qs = qs.Where("p_type", ptype)
	for index := 0; index <= 5; index++ {
		if fieldIndex <= index && index < fieldIndex+len(fieldValues) {
			qs = qs.Where(fmt.Sprintf("v%d", index), fieldValues[index-fieldIndex])
		}
	}
	_, err := qs.Delete()
	return err
}
