package adapter

import (
	"context"
	"errors"
	"fmt"
	"math"

	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"github.com/gogf/gf/v2/database/gdb"
	"github.com/gogf/gf/v2/frame/g"
)

const (
	defaultTableName = "casbin_rule"
	dropTableSql     = `DROP TABLE IF EXISTS %s`
	createTableSql   = `
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
	truncateTableSql = `TRUNCATE TABLE %s`
)

type (
	Adapter struct {
		ctx         context.Context
		dbGroupName string
		tableName   string
		db          gdb.DB
		isFiltered  bool
	}

	Rule struct {
		PType string `orm:"p_type" json:"p_type"`
		V0    string `orm:"v0" json:"v0"`
		V1    string `orm:"v1" json:"v1"`
		V2    string `orm:"v2" json:"v2"`
		V3    string `orm:"v3" json:"v3"`
		V4    string `orm:"v4" json:"v4"`
		V5    string `orm:"v5" json:"v5"`
	}

	Filter struct {
		PType []string
		V0    []string
		V1    []string
		V2    []string
		V3    []string
		V4    []string
		V5    []string
	}
)

var (
	Columns = Rule{
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
func NewAdapter(ctx context.Context, dbGroupName, tableName string, db gdb.DB) (adp *Adapter, err error) {
	adp = &Adapter{ctx: ctx, dbGroupName: dbGroupName, tableName: tableName, db: db}
	if adp.tableName == "" {
		adp.tableName = defaultTableName
	}
	err = adp.open()
	if err != nil {
		return nil, err
	}
	return
}

func (a *Adapter) open() error {
	if a.db == nil {
		a.db = g.DB(a.dbGroupName)
	}
	a.tableName = fmt.Sprintf("%s%s", a.db.GetPrefix(), a.tableName)
	return a.createTable()
}

func (a *Adapter) model() *gdb.Model {
	return a.db.Model(a.tableName).Safe().Ctx(a.ctx)
}

// IsFiltered returns true if the loaded policy has been filtered.
func (a *Adapter) IsFiltered() bool {
	return a.isFiltered
}

// create a policy tableName when it's not exists.
func (a *Adapter) createTable() (err error) {
	_, err = a.db.Exec(a.ctx, fmt.Sprintf(createTableSql, a.tableName))
	return
}

// drop policy tableName from the storage.
func (a *Adapter) dropTable() (err error) {
	_, err = a.db.Exec(a.ctx, fmt.Sprintf(dropTableSql, a.tableName))
	return
}

// truncate policy tableName from the storage.
func (a *Adapter) truncateTable() error {
	_, err := a.db.Exec(a.ctx, fmt.Sprintf(truncateTableSql, a.tableName))
	return err
}

// SavePolicy Saves all policy rules to the storage.
func (a *Adapter) SavePolicy(model model.Model) (err error) {
	if err = a.truncateTable(); err != nil {
		return
	}
	var rules []Rule
	for pType, ast := range model["p"] {
		for _, rule := range ast.Policy {
			rules = append(rules, a.buildRule(pType, rule))
		}
	}
	for pType, ast := range model["g"] {
		for _, rule := range ast.Policy {
			rules = append(rules, a.buildRule(pType, rule))
		}
	}
	if count := len(rules); count > 0 {
		if _, err = a.model().Insert(rules); err != nil {
			return
		}
	}
	return
}

// LoadPolicy loads all policy rules from the storage.
func (a *Adapter) LoadPolicy(model model.Model) (err error) {
	var rules []Rule
	if err = a.model().Scan(&rules); err != nil {
		return
	}
	for _, rule := range rules {
		a.loadPolicyRule(rule, model)
	}
	return
}

// LoadFilteredPolicy loads only policy rules that match the filter.
func (a *Adapter) LoadFilteredPolicy(model model.Model, filter interface{}) error {
	var rules []Rule
	filterRule, ok := filter.(Filter)
	if !ok {
		return errors.New("invalid filter type")
	}
	db := a.model()
	if len(filterRule.PType) > 0 {
		db = db.WhereIn(Columns.PType, filterRule.PType)
	}
	if len(filterRule.V0) > 0 {
		db = db.WhereIn(Columns.V0, filterRule.V0)
	}
	if len(filterRule.V1) > 0 {
		db = db.WhereIn(Columns.V1, filterRule.V1)
	}
	if len(filterRule.V2) > 0 {
		db = db.WhereIn(Columns.V2, filterRule.V2)
	}
	if len(filterRule.V3) > 0 {
		db = db.WhereIn(Columns.V3, filterRule.V3)
	}
	if len(filterRule.V4) > 0 {
		db = db.WhereIn(Columns.V4, filterRule.V4)
	}
	if len(filterRule.V5) > 0 {
		db = db.WhereIn(Columns.V5, filterRule.V5)
	}
	if err := db.Scan(&rules); err != nil {
		return err
	}
	for _, rule := range rules {
		a.loadPolicyRule(rule, model)
	}
	a.isFiltered = true
	return nil
}

// load Rule from slice.
func (a *Adapter) loadPolicyRule(rule Rule, model model.Model) {
	var p = []string{rule.PType, rule.V0, rule.V1, rule.V2, rule.V3, rule.V4, rule.V5}
	index := len(p) - 1
	for p[index] == "" {
		index--
	}
	persist.LoadPolicyArray(p[:index+1], model)
}

// AddPolicy adds a policy rule to the storage.
func (a *Adapter) AddPolicy(sec string, pType string, rule []string) (err error) {
	_, err = a.model().Insert(a.buildRule(pType, rule))
	return
}

// AddPolicies adds policy rules to the storage.
func (a *Adapter) AddPolicies(sec string, pType string, rules [][]string) (err error) {
	if len(rules) == 0 {
		return
	}
	policyRules := make([]Rule, 0, len(rules))
	for _, rule := range rules {
		policyRules = append(policyRules, a.buildRule(pType, rule))
	}
	_, err = a.model().Insert(policyRules)
	return
}

// RemovePolicy removes a policy rule from the storage.
func (a *Adapter) RemovePolicy(sec string, pType string, rule []string) (err error) {
	_, err = a.model().Delete(a.buildRule(pType, rule))
	return err
}

// RemovePolicies removes policy rules from the storage (implements the persist.BatchAdapter interface).
func (a *Adapter) RemovePolicies(sec string, pType string, rules [][]string) (err error) {
	db := a.model()
	for _, rule := range rules {
		where := map[string]interface{}{Columns.PType: pType}
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
func (a *Adapter) RemoveFilteredPolicy(sec string, pType string, fieldIndex int, fieldValues ...string) (err error) {
	db := a.model().Where(Columns.PType, pType)
	for index := 0; index <= 5; index++ {
		if fieldIndex <= index && index < fieldIndex+len(fieldValues) {
			db = db.Where(fmt.Sprintf("v%d", index), fieldValues[index-fieldIndex])
		}
	}
	_, err = db.Delete()
	return
}

// UpdatePolicy updates a policy rule from storage.
func (a *Adapter) UpdatePolicy(sec string, pType string, oldRule, newRule []string) (err error) {
	_, err = a.model().Update(a.buildRule(pType, newRule), a.buildRule(pType, oldRule))
	return
}

// UpdatePolicies updates some policy rules to storage, like db, redis.
func (a *Adapter) UpdatePolicies(sec string, pType string, oldRules, newRules [][]string) (err error) {
	if len(oldRules) == 0 || len(newRules) == 0 {
		return
	}
	err = a.db.Transaction(a.ctx, func(ctx context.Context, tx gdb.TX) error {
		for i := 0; i < int(math.Min(float64(len(oldRules)), float64(len(newRules)))); i++ {
			if _, err = tx.Model(a.tableName).Update(a.buildRule(pType, newRules[i]), a.buildRule(pType, oldRules[i])); err != nil {
				return err
			}
		}
		return nil
	})
	return
}

// UpdateFilteredPolicies deletes old rules and adds new rules.
func (a *Adapter) UpdateFilteredPolicies(sec string, pType string, newPolicies [][]string, fieldIndex int, fieldValues ...string) ([][]string, error) {
	rule := &Rule{}
	rule.PType = pType
	if fieldIndex <= 0 && 0 < fieldIndex+len(fieldValues) {
		rule.V0 = fieldValues[0-fieldIndex]
	}
	if fieldIndex <= 1 && 1 < fieldIndex+len(fieldValues) {
		rule.V1 = fieldValues[1-fieldIndex]
	}
	if fieldIndex <= 2 && 2 < fieldIndex+len(fieldValues) {
		rule.V2 = fieldValues[2-fieldIndex]
	}
	if fieldIndex <= 3 && 3 < fieldIndex+len(fieldValues) {
		rule.V3 = fieldValues[3-fieldIndex]
	}
	if fieldIndex <= 4 && 4 < fieldIndex+len(fieldValues) {
		rule.V4 = fieldValues[4-fieldIndex]
	}
	if fieldIndex <= 5 && 5 < fieldIndex+len(fieldValues) {
		rule.V5 = fieldValues[5-fieldIndex]
	}
	newRules := make([]Rule, 0, len(newPolicies))
	oldRules := make([]Rule, 0)
	for _, newRule := range newPolicies {
		newRules = append(newRules, a.buildRule(pType, newRule))
	}
	tx, err := a.db.Begin(a.ctx)
	if err != nil {
		panic(err)
	}
	for i := range newRules {
		str, args := rule.toQuery()
		if err = tx.Model(a.tableName).Where(str, args...).Scan(&oldRules); err != nil {
			err = tx.Rollback()
			return nil, err
		}
		if _, err = tx.Model(a.tableName).Where(str, args...).Delete([]Rule{}); err != nil {
			err = tx.Rollback()
			return nil, err
		}
		if _, err = tx.Model(a.tableName).Data(&newRules[i]).Insert(); err != nil {
			err = tx.Rollback()
			return nil, err
		}
	}
	oldPolicies := make([][]string, 0)
	for _, v := range oldRules {
		oldPolicy := v.toSlice()
		oldPolicies = append(oldPolicies, oldPolicy)
	}
	err = tx.Commit()
	if err != nil {
		return nil, err
	}
	return oldPolicies, err
}

// get query str and args from Rule.
func (c *Rule) toQuery() (interface{}, []interface{}) {
	queryArgs := []interface{}{c.PType}
	queryStr := "p_type = ?"
	if c.V0 != "" {
		queryStr += " and v0 = ?"
		queryArgs = append(queryArgs, c.V0)
	}
	if c.V1 != "" {
		queryStr += " and v1 = ?"
		queryArgs = append(queryArgs, c.V1)
	}
	if c.V2 != "" {
		queryStr += " and v2 = ?"
		queryArgs = append(queryArgs, c.V2)
	}
	if c.V3 != "" {
		queryStr += " and v3 = ?"
		queryArgs = append(queryArgs, c.V3)
	}
	if c.V4 != "" {
		queryStr += " and v4 = ?"
		queryArgs = append(queryArgs, c.V4)
	}
	if c.V5 != "" {
		queryStr += " and v5 = ?"
		queryArgs = append(queryArgs, c.V5)
	}
	return queryStr, queryArgs
}

// get slice from Rule.
func (c *Rule) toSlice() []string {
	var policy []string
	if c.PType != "" {
		policy = append(policy, c.PType)
	}
	if c.V0 != "" {
		policy = append(policy, c.V0)
	}
	if c.V1 != "" {
		policy = append(policy, c.V1)
	}
	if c.V2 != "" {
		policy = append(policy, c.V2)
	}
	if c.V3 != "" {
		policy = append(policy, c.V3)
	}
	if c.V4 != "" {
		policy = append(policy, c.V4)
	}
	if c.V5 != "" {
		policy = append(policy, c.V5)
	}
	return policy
}

// build Rule from slice.
func (a *Adapter) buildRule(pType string, data []string) Rule {
	rule := Rule{PType: pType}
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
