package adapter

import (
	"context"
	"errors"
	"fmt"

	"github.com/casbin/casbin/v2/model"
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

// NewAdapter creates a new Casbin adapter for GoFrame
func NewAdapter(ctx context.Context, dbGroupName, tableName string, db gdb.DB) (adp *Adapter, err error) {
	if ctx == nil {
		return nil, errors.New("context cannot be nil")
	}

	adp = &Adapter{
		ctx:         ctx,
		dbGroupName: dbGroupName,
		tableName:   tableName,
		db:          db,
	}

	if adp.tableName == "" {
		adp.tableName = defaultTableName
	}

	if err = adp.open(); err != nil {
		return nil, fmt.Errorf("failed to open adapter: %w", err)
	}

	return adp, nil
}

func (a *Adapter) open() error {
	if a.db == nil {
		if a.dbGroupName == "" {
			return errors.New("database group name cannot be empty when db is nil")
		}
		a.db = g.DB(a.dbGroupName)
		if a.db == nil {
			return fmt.Errorf("failed to get database instance for group: %s", a.dbGroupName)
		}
	}

	// Get database prefix and validate connection
	prefix := a.db.GetPrefix()
	a.tableName = fmt.Sprintf("%s%s", prefix, a.tableName)
	return a.createTable()
}

func (a *Adapter) model() *gdb.Model {
	return a.db.Model(a.tableName).Safe().Ctx(a.ctx)
}

// IsFiltered returns true if the loaded policy has been filtered.
func (a *Adapter) IsFiltered() bool {
	return a.isFiltered
}

// create a policy table when it doesn't exist.
func (a *Adapter) createTable() error {
	if a.tableName == "" {
		return errors.New("table name cannot be empty")
	}

	_, err := a.db.Exec(a.ctx, fmt.Sprintf(createTableSql, a.tableName))
	if err != nil {
		return fmt.Errorf("failed to create table: %w", err)
	}
	return nil
}

// drop policy table from the storage.
func (a *Adapter) dropTable() error {
	if a.tableName == "" {
		return errors.New("table name cannot be empty")
	}

	_, err := a.db.Exec(a.ctx, fmt.Sprintf(dropTableSql, a.tableName))
	if err != nil {
		return fmt.Errorf("failed to drop table: %w", err)
	}
	return nil
}

// truncate policy table in the storage.
func (a *Adapter) truncateTable() error {
	if a.tableName == "" {
		return errors.New("table name cannot be empty")
	}

	_, err := a.db.Exec(a.ctx, fmt.Sprintf(truncateTableSql, a.tableName))
	if err != nil {
		return fmt.Errorf("failed to truncate table: %w", err)
	}
	return nil
}

// SavePolicy saves all policy rules to the storage.
func (a *Adapter) SavePolicy(model model.Model) error {
	if model == nil {
		return errors.New("model cannot be nil")
	}

	if err := a.truncateTable(); err != nil {
		return fmt.Errorf("failed to truncate table: %w", err)
	}

	var rules []Rule

	// Convert policy rules to database records
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

	if len(rules) == 0 {
		return nil
	}

	// Use transaction for better reliability
	err := a.model().Transaction(a.ctx, func(ctx context.Context, tx gdb.TX) error {
		// Insert rules in batches for better performance
		const batchSize = 1000
		for i := 0; i < len(rules); i += batchSize {
			end := i + batchSize
			if end > len(rules) {
				end = len(rules)
			}
			batch := rules[i:end]
			if _, err := tx.Model(a.tableName).Ctx(ctx).Insert(batch); err != nil {
				return fmt.Errorf("failed to insert rules batch: %w", err)
			}
		}
		return nil
	})

	return err
}

// LoadPolicy loads all policy rules from the storage.
func (a *Adapter) LoadPolicy(model model.Model) error {
	if model == nil {
		return errors.New("model cannot be nil")
	}

	var rules []Rule
	err := a.model().
		OrderAsc("id").
		Scan(&rules)
	if err != nil {
		return fmt.Errorf("failed to scan policy rules: %w", err)
	}

	for _, rule := range rules {
		a.loadPolicyRule(rule, model)
	}

	return nil
}

// LoadFilteredPolicy loads only policy rules that match the filter.
func (a *Adapter) LoadFilteredPolicy(model model.Model, filter interface{}) error {
	if model == nil {
		return errors.New("model cannot be nil")
	}

	filterRule, ok := filter.(Filter)
	if !ok {
		return errors.New("invalid filter type")
	}

	query := a.model()

	if len(filterRule.PType) > 0 {
		query = query.WhereIn(Columns.PType, filterRule.PType)
	}
	if len(filterRule.V0) > 0 {
		query = query.WhereIn(Columns.V0, filterRule.V0)
	}
	if len(filterRule.V1) > 0 {
		query = query.WhereIn(Columns.V1, filterRule.V1)
	}
	if len(filterRule.V2) > 0 {
		query = query.WhereIn(Columns.V2, filterRule.V2)
	}
	if len(filterRule.V3) > 0 {
		query = query.WhereIn(Columns.V3, filterRule.V3)
	}
	if len(filterRule.V4) > 0 {
		query = query.WhereIn(Columns.V4, filterRule.V4)
	}
	if len(filterRule.V5) > 0 {
		query = query.WhereIn(Columns.V5, filterRule.V5)
	}

	var rules []Rule
	if err := query.Scan(&rules); err != nil {
		return fmt.Errorf("failed to scan filtered policy rules: %w", err)
	}

	for _, rule := range rules {
		a.loadPolicyRule(rule, model)
	}

	a.isFiltered = true
	return nil
}

// toQuery gets query string and args from Rule.
func (c *Rule) toQuery() (interface{}, []interface{}) {
	where := "p_type=?"
	args := []interface{}{c.PType}

	if c.V0 != "" {
		where += " AND v0=?"
		args = append(args, c.V0)
	}
	if c.V1 != "" {
		where += " AND v1=?"
		args = append(args, c.V1)
	}
	if c.V2 != "" {
		where += " AND v2=?"
		args = append(args, c.V2)
	}
	if c.V3 != "" {
		where += " AND v3=?"
		args = append(args, c.V3)
	}
	if c.V4 != "" {
		where += " AND v4=?"
		args = append(args, c.V4)
	}
	if c.V5 != "" {
		where += " AND v5=?"
		args = append(args, c.V5)
	}

	return where, args
}

// toSlice converts Rule to string slice.
func (c *Rule) toSlice() []string {
	if c == nil {
		return nil
	}

	res := make([]string, 0, 6)
	if c.V0 != "" {
		res = append(res, c.V0)
	}
	if c.V1 != "" {
		res = append(res, c.V1)
	}
	if c.V2 != "" {
		res = append(res, c.V2)
	}
	if c.V3 != "" {
		res = append(res, c.V3)
	}
	if c.V4 != "" {
		res = append(res, c.V4)
	}
	if c.V5 != "" {
		res = append(res, c.V5)
	}

	return res
}

// buildRule builds Rule from string slice.
func (a *Adapter) buildRule(pType string, data []string) Rule {
	rule := Rule{
		PType: pType,
	}

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

// loadPolicyRule loads a policy rule into the model.
func (a *Adapter) loadPolicyRule(rule Rule, model model.Model) {
	ruleText := rule.toSlice()
	if len(ruleText) == 0 {
		return
	}

	key := rule.PType
	sec := key[:1]
	model[sec][key].Policy = append(model[sec][key].Policy, ruleText)
}

// AddPolicy adds a policy rule to the storage.
func (a *Adapter) AddPolicy(sec string, pType string, rule []string) error {
	dbRule := a.buildRule(pType, rule)
	_, err := a.model().Insert(dbRule)
	if err != nil {
		return fmt.Errorf("failed to add policy: %w", err)
	}
	return nil
}

// AddPolicies adds policy rules to the storage.
func (a *Adapter) AddPolicies(sec string, pType string, rules [][]string) error {
	if len(rules) == 0 {
		return nil
	}

	dbRules := make([]Rule, 0, len(rules))
	for _, rule := range rules {
		dbRules = append(dbRules, a.buildRule(pType, rule))
	}

	err := a.model().Transaction(a.ctx, func(ctx context.Context, tx gdb.TX) error {
		// Insert rules in batches for better performance
		const batchSize = 1000
		for i := 0; i < len(dbRules); i += batchSize {
			end := i + batchSize
			if end > len(dbRules) {
				end = len(dbRules)
			}
			batch := dbRules[i:end]
			if _, err := tx.Model(a.tableName).Ctx(ctx).Insert(batch); err != nil {
				return fmt.Errorf("failed to insert rules batch: %w", err)
			}
		}
		return nil
	})

	return err
}

// RemovePolicy removes a policy rule from the storage.
func (a *Adapter) RemovePolicy(sec string, pType string, rule []string) error {
	dbRule := a.buildRule(pType, rule)
	query, args := dbRule.toQuery()
	_, err := a.model().Where(query, args...).Delete()
	if err != nil {
		return fmt.Errorf("failed to delete policy: %w", err)
	}
	return nil
}

// RemovePolicies removes policy rules from the storage.
func (a *Adapter) RemovePolicies(sec string, pType string, rules [][]string) error {
	if len(rules) == 0 {
		return nil
	}

	err := a.model().Transaction(a.ctx, func(ctx context.Context, tx gdb.TX) error {
		for _, rule := range rules {
			dbRule := a.buildRule(pType, rule)
			query, args := dbRule.toQuery()
			if _, err := tx.Model(a.tableName).Ctx(ctx).Where(query, args...).Delete(); err != nil {
				return fmt.Errorf("failed to delete rule: %w", err)
			}
		}
		return nil
	})

	return err
}

// RemoveFilteredPolicy removes policy rules that match the filter from the storage.
func (a *Adapter) RemoveFilteredPolicy(sec string, pType string, fieldIndex int, fieldValues ...string) error {
	if fieldIndex < 0 || fieldIndex > 5 {
		return fmt.Errorf("invalid field index: %d", fieldIndex)
	}

	query := a.model().Where(Columns.PType, pType)

	idx := fieldIndex
	for _, fieldValue := range fieldValues {
		if fieldValue != "" {
			query = query.Where(fmt.Sprintf("v%d", idx), fieldValue)
		}
		idx++
	}

	_, err := query.Delete()
	if err != nil {
		return fmt.Errorf("failed to delete filtered policies: %w", err)
	}

	return nil
}

// UpdatePolicy updates a policy rule from storage.
func (a *Adapter) UpdatePolicy(sec string, pType string, oldRule, newRule []string) error {
	err := a.model().Transaction(a.ctx, func(ctx context.Context, tx gdb.TX) error {
		oldData := a.buildRule(pType, oldRule)
		query, args := oldData.toQuery()

		// Delete old rule
		if _, err := tx.Model(a.tableName).Ctx(ctx).Where(query, args...).Delete(); err != nil {
			return fmt.Errorf("failed to delete old rule: %w", err)
		}

		// Insert new rule
		newData := a.buildRule(pType, newRule)
		if _, err := tx.Model(a.tableName).Ctx(ctx).Insert(newData); err != nil {
			return fmt.Errorf("failed to insert new rule: %w", err)
		}

		return nil
	})

	return err
}

// UpdatePolicies updates multiple policy rules in the storage.
func (a *Adapter) UpdatePolicies(sec string, pType string, oldRules, newRules [][]string) error {
	if len(oldRules) != len(newRules) {
		return errors.New("old rules and new rules have different length")
	}

	if len(oldRules) == 0 {
		return nil
	}

	err := a.model().Transaction(a.ctx, func(ctx context.Context, tx gdb.TX) error {
		for i := 0; i < len(oldRules); i++ {
			oldRule := a.buildRule(pType, oldRules[i])
			query, args := oldRule.toQuery()

			// Delete old rule
			if _, err := tx.Model(a.tableName).Ctx(ctx).Where(query, args...).Delete(); err != nil {
				return fmt.Errorf("failed to delete old rule: %w", err)
			}

			// Insert new rule
			newRule := a.buildRule(pType, newRules[i])
			if _, err := tx.Model(a.tableName).Ctx(ctx).Insert(newRule); err != nil {
				return fmt.Errorf("failed to insert new rule: %w", err)
			}
		}
		return nil
	})

	return err
}

// UpdateFilteredPolicies deletes old rules and adds new rules.
func (a *Adapter) UpdateFilteredPolicies(sec string, pType string, newPolicies [][]string, fieldIndex int, fieldValues ...string) ([][]string, error) {
	// Get old rules
	var oldRules []Rule
	query := a.model().Where(Columns.PType, pType)

	idx := fieldIndex
	for _, fieldValue := range fieldValues {
		if fieldValue != "" {
			query = query.Where(fmt.Sprintf("v%d", idx), fieldValue)
		}
		idx++
	}

	if err := query.Scan(&oldRules); err != nil {
		return nil, fmt.Errorf("failed to scan old rules: %w", err)
	}

	// Convert old rules to string arrays
	oldPolicies := make([][]string, 0, len(oldRules))
	for _, rule := range oldRules {
		oldPolicies = append(oldPolicies, rule.toSlice())
	}

	err := a.model().Transaction(a.ctx, func(ctx context.Context, tx gdb.TX) error {
		// Delete old rules
		if _, err := query.Ctx(ctx).Delete(); err != nil {
			return fmt.Errorf("failed to delete old rules: %w", err)
		}

		// Insert new rules
		if len(newPolicies) > 0 {
			dbRules := make([]Rule, 0, len(newPolicies))
			for _, policy := range newPolicies {
				dbRules = append(dbRules, a.buildRule(pType, policy))
			}

			// Insert rules in batches for better performance
			const batchSize = 1000
			for i := 0; i < len(dbRules); i += batchSize {
				end := i + batchSize
				if end > len(dbRules) {
					end = len(dbRules)
				}
				batch := dbRules[i:end]
				if _, err := tx.Model(a.tableName).Ctx(ctx).Insert(batch); err != nil {
					return fmt.Errorf("failed to insert new rules batch: %w", err)
				}
			}
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return oldPolicies, nil
}
