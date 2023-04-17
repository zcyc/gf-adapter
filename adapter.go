package adapter

import (
	"context"
	"errors"
	"fmt"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"github.com/gogf/gf/v2/database/gdb"
	"math"
	"strings"
)

const (
	tableName      = "casbin_rule"
	dropTableSql   = `DROP TABLE IF EXISTS %s`
	createTableSql = `
CREATE TABLE IF NOT EXISTS %s (
  id bigint NOT NULL AUTO_INCREMENT,
  p_type varchar(10) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL,
  v0 varchar(256) COLLATE utf8mb4_general_ci DEFAULT NULL,
  v1 varchar(256) COLLATE utf8mb4_general_ci DEFAULT NULL,
  v2 varchar(256) COLLATE utf8mb4_general_ci DEFAULT NULL,
  v3 varchar(256) COLLATE utf8mb4_general_ci DEFAULT NULL,
  v4 varchar(256) COLLATE utf8mb4_general_ci DEFAULT NULL,
  v5 varchar(256) COLLATE utf8mb4_general_ci DEFAULT NULL,
  created_at datetime DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
`
)

type (
	Adapter struct {
		db        gdb.DB
		tableName string
	}

	policyColumns struct {
		PType string
		V0    string
		V1    string
		V2    string
		V3    string
		V4    string
		V5    string
	}

	// policy rule entity
	policyRule struct {
		PType string `orm:"p_type" json:"p_type"`
		V0    string `orm:"v0" json:"v0"`
		V1    string `orm:"v1" json:"v1"`
		V2    string `orm:"v2" json:"v2"`
		V3    string `orm:"v3" json:"v3"`
		V4    string `orm:"v4" json:"v4"`
		V5    string `orm:"v5" json:"v5"`
	}
)

var (
	errInvalidDatabaseLink = errors.New("invalid database link")
	policyColumnsName      = policyColumns{
		PType: "p_type",
		V0:    "v0",
		V1:    "v1",
		V2:    "v2",
		V3:    "v3",
		V4:    "v4",
		V5:    "v5",
	}
)

// NewAdapter Create a casbin adapter
func NewAdapter(db gdb.DB, link, table string) (adp *Adapter, err error) {
	adp = &Adapter{db, table}

	if adp.db == nil {
		config := strings.SplitN(link, ":", 2)

		if len(config) != 2 {
			err = errInvalidDatabaseLink
			return
		}

		if adp.db, err = gdb.New(gdb.ConfigNode{Type: config[0], Link: config[1]}); err != nil {
			return
		}
	}

	if adp.tableName == "" {
		adp.tableName = tableName
	}

	err = adp.createTable()

	return
}

func (a *Adapter) model() *gdb.Model {
	return a.db.Model(a.tableName).Safe().Ctx(context.TODO())
}

// create a policy tableName when it's not exists.
func (a *Adapter) createTable() (err error) {
	_, err = a.db.Exec(context.TODO(), fmt.Sprintf(createTableSql, a.tableName))

	return
}

// drop policy tableName from the storage.
func (a *Adapter) dropTable() (err error) {
	_, err = a.db.Exec(context.TODO(), fmt.Sprintf(dropTableSql, a.tableName))

	return
}

// LoadPolicy loads all policy rules from the storage.
func (a *Adapter) LoadPolicy(model model.Model) (err error) {
	var rules []policyRule

	if err = a.model().Scan(&rules); err != nil {
		return
	}

	for _, rule := range rules {
		a.loadPolicyRule(rule, model)
	}

	return
}

// SavePolicy Saves all policy rules to the storage.
func (a *Adapter) SavePolicy(model model.Model) (err error) {
	if err = a.dropTable(); err != nil {
		return
	}

	if err = a.createTable(); err != nil {
		return
	}

	policyRules := make([]policyRule, 0)

	for pType, ast := range model["p"] {
		for _, rule := range ast.Policy {
			policyRules = append(policyRules, a.buildPolicyRule(pType, rule))
		}
	}

	for pType, ast := range model["g"] {
		for _, rule := range ast.Policy {
			policyRules = append(policyRules, a.buildPolicyRule(pType, rule))
		}
	}

	if count := len(policyRules); count > 0 {
		if _, err = a.model().Insert(policyRules); err != nil {
			return
		}
	}

	return
}

// AddPolicy adds a policy rule to the storage.
func (a *Adapter) AddPolicy(sec string, pType string, rule []string) (err error) {
	_, err = a.model().Insert(a.buildPolicyRule(pType, rule))

	return
}

// AddPolicies adds policy rules to the storage.
func (a *Adapter) AddPolicies(sec string, pType string, rules [][]string) (err error) {
	if len(rules) == 0 {
		return
	}

	policyRules := make([]policyRule, 0, len(rules))

	for _, rule := range rules {
		policyRules = append(policyRules, a.buildPolicyRule(pType, rule))
	}

	_, err = a.model().Insert(policyRules)

	return
}

// RemovePolicy removes a policy rule from the storage.
func (a *Adapter) RemovePolicy(sec string, pType string, rule []string) (err error) {
	db := a.model()
	db = db.Where(policyColumnsName.PType, pType)
	for index := 0; index < len(rule); index++ {
		db = db.Where(fmt.Sprintf("v%d", index), rule[index])
	}
	_, err = db.Delete()
	return err
}

// RemoveFilteredPolicy removes policy rules that match the filter from the storage.
func (a *Adapter) RemoveFilteredPolicy(sec string, pType string, fieldIndex int, fieldValues ...string) (err error) {
	db := a.model()
	db = db.Where(policyColumnsName.PType, pType)
	for index := 0; index <= 5; index++ {
		if fieldIndex <= index && index < fieldIndex+len(fieldValues) {
			db = db.Where(fmt.Sprintf("v%d", index), fieldValues[index-fieldIndex])
		}
	}
	_, err = db.Delete()
	return
}

// RemovePolicies removes policy rules from the storage (implements the persist.BatchAdapter interface).
func (a *Adapter) RemovePolicies(sec string, pType string, rules [][]string) (err error) {
	db := a.model()

	for _, rule := range rules {
		where := map[string]interface{}{policyColumnsName.PType: pType}

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

// UpdatePolicy updates a policy rule from storage.
func (a *Adapter) UpdatePolicy(sec string, pType string, oldRule, newRule []string) (err error) {
	_, err = a.model().Update(a.buildPolicyRule(pType, newRule), a.buildPolicyRule(pType, oldRule))

	return
}

// UpdatePolicies updates some policy rules to storage, like db, redis.
func (a *Adapter) UpdatePolicies(sec string, pType string, oldRules, newRules [][]string) (err error) {
	if len(oldRules) == 0 || len(newRules) == 0 {
		return
	}

	err = a.db.Transaction(context.TODO(), func(ctx context.Context, tx gdb.TX) error {
		for i := 0; i < int(math.Min(float64(len(oldRules)), float64(len(newRules)))); i++ {
			if _, err = tx.Model(a.tableName).Update(a.buildPolicyRule(pType, newRules[i]), a.buildPolicyRule(pType, oldRules[i])); err != nil {
				return err
			}
		}

		return nil
	})

	return
}

// 加载策略规则
func (a *Adapter) loadPolicyRule(rule policyRule, model model.Model) {
	ruleText := rule.PType

	if rule.V0 != "" {
		ruleText += ", " + rule.V0
	}

	if rule.V1 != "" {
		ruleText += ", " + rule.V1
	}

	if rule.V2 != "" {
		ruleText += ", " + rule.V2
	}

	if rule.V3 != "" {
		ruleText += ", " + rule.V3
	}

	if rule.V4 != "" {
		ruleText += ", " + rule.V4
	}

	if rule.V5 != "" {
		ruleText += ", " + rule.V5
	}

	persist.LoadPolicyLine(ruleText, model)
}

// 构建策略规则
func (a *Adapter) buildPolicyRule(pType string, data []string) policyRule {
	rule := policyRule{PType: pType}

	if len(data) > 0 {
		rule.V0 = data[0]
	}

	if len(data) > 1 {
		rule.V1 = data[1]
	}

	if len(data) > 2 {
		rule.V2 = data[2]
	}

	if len(data) > 3 {
		rule.V3 = data[3]
	}

	if len(data) > 4 {
		rule.V4 = data[4]
	}

	if len(data) > 5 {
		rule.V5 = data[5]
	}

	return rule
}
