package logger

import (
	"database/sql"
	"fmt"
	"log"
	"strings"
)

const globalRequestStatsKey = "global"

type dailyStatsKey struct {
	BucketDate    string
	ProxyKeyID    string
	ProviderGroup string
	Model         string
	IsStream      bool
}

type dailyStatsValue struct {
	ProxyKeyName    string
	TotalRequests   int64
	SuccessRequests int64
	ErrorRequests   int64
	TotalTokens     int64
	SuccessTokens   int64
	TotalDuration   int64
	SuccessDuration int64
}

func (d *Database) ensureAnalyticsTables() error {
	var statements []string
	if d.dialect == "postgres" {
		statements = []string{
			`CREATE TABLE IF NOT EXISTS request_log_global_stats (
				stats_key TEXT PRIMARY KEY,
				total_requests BIGINT NOT NULL DEFAULT 0,
				success_requests BIGINT NOT NULL DEFAULT 0,
				error_requests BIGINT NOT NULL DEFAULT 0,
				total_tokens BIGINT NOT NULL DEFAULT 0,
				success_tokens BIGINT NOT NULL DEFAULT 0,
				total_duration BIGINT NOT NULL DEFAULT 0,
				success_duration BIGINT NOT NULL DEFAULT 0,
				updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
			)`,
			`CREATE TABLE IF NOT EXISTS request_log_daily_stats (
				bucket_date TEXT NOT NULL,
				proxy_key_name TEXT NOT NULL,
				proxy_key_id TEXT NOT NULL,
				provider_group TEXT NOT NULL,
				model TEXT NOT NULL,
				is_stream BOOLEAN NOT NULL DEFAULT FALSE,
				total_requests BIGINT NOT NULL DEFAULT 0,
				success_requests BIGINT NOT NULL DEFAULT 0,
				error_requests BIGINT NOT NULL DEFAULT 0,
				total_tokens BIGINT NOT NULL DEFAULT 0,
				success_tokens BIGINT NOT NULL DEFAULT 0,
				total_duration BIGINT NOT NULL DEFAULT 0,
				success_duration BIGINT NOT NULL DEFAULT 0,
				PRIMARY KEY (bucket_date, proxy_key_id, provider_group, model, is_stream)
			)`,
		}
	} else {
		statements = []string{
			`CREATE TABLE IF NOT EXISTS request_log_global_stats (
				stats_key TEXT PRIMARY KEY,
				total_requests INTEGER NOT NULL DEFAULT 0,
				success_requests INTEGER NOT NULL DEFAULT 0,
				error_requests INTEGER NOT NULL DEFAULT 0,
				total_tokens INTEGER NOT NULL DEFAULT 0,
				success_tokens INTEGER NOT NULL DEFAULT 0,
				total_duration INTEGER NOT NULL DEFAULT 0,
				success_duration INTEGER NOT NULL DEFAULT 0,
				updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
			)`,
			`CREATE TABLE IF NOT EXISTS request_log_daily_stats (
				bucket_date TEXT NOT NULL,
				proxy_key_name TEXT NOT NULL,
				proxy_key_id TEXT NOT NULL,
				provider_group TEXT NOT NULL,
				model TEXT NOT NULL,
				is_stream BOOLEAN NOT NULL DEFAULT 0,
				total_requests INTEGER NOT NULL DEFAULT 0,
				success_requests INTEGER NOT NULL DEFAULT 0,
				error_requests INTEGER NOT NULL DEFAULT 0,
				total_tokens INTEGER NOT NULL DEFAULT 0,
				success_tokens INTEGER NOT NULL DEFAULT 0,
				total_duration INTEGER NOT NULL DEFAULT 0,
				success_duration INTEGER NOT NULL DEFAULT 0,
				PRIMARY KEY (bucket_date, proxy_key_id, provider_group, model, is_stream)
			)`,
		}
	}

	for _, statement := range statements {
		if _, err := d.exec(statement); err != nil {
			return fmt.Errorf("failed to create analytics table: %w", err)
		}
	}

	indexes := []string{
		`CREATE INDEX IF NOT EXISTS idx_request_log_daily_stats_bucket_date ON request_log_daily_stats(bucket_date)`,
		`CREATE INDEX IF NOT EXISTS idx_request_log_daily_stats_proxy_key_name ON request_log_daily_stats(proxy_key_name)`,
		`CREATE INDEX IF NOT EXISTS idx_request_log_daily_stats_provider_group ON request_log_daily_stats(provider_group)`,
		`CREATE INDEX IF NOT EXISTS idx_request_log_daily_stats_model ON request_log_daily_stats(model)`,
	}
	for _, indexSQL := range indexes {
		if _, err := d.exec(indexSQL); err != nil {
			return fmt.Errorf("failed to create analytics index: %w", err)
		}
	}

	_, err := d.exec(`
		INSERT INTO request_log_global_stats (
			stats_key, total_requests, success_requests, error_requests,
			total_tokens, success_tokens, total_duration, success_duration, updated_at
		) VALUES (?, 0, 0, 0, 0, 0, 0, 0, CURRENT_TIMESTAMP)
		ON CONFLICT(stats_key) DO NOTHING
	`, globalRequestStatsKey)
	if err != nil {
		return fmt.Errorf("failed to seed request log global stats: %w", err)
	}

	return nil
}

func (d *Database) ensureLargeDatasetIndexes() error {
	indexes := []string{
		`CREATE INDEX IF NOT EXISTS idx_request_logs_created_at_id ON request_logs(created_at DESC, id DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_request_logs_proxy_key_created_at ON request_logs(proxy_key_name, created_at DESC, id DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_request_logs_provider_group_created_at ON request_logs(provider_group, created_at DESC, id DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_request_logs_model_created_at ON request_logs(model, created_at DESC, id DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_request_logs_status_created_at ON request_logs(status_code, created_at DESC, id DESC)`,
	}

	for _, indexSQL := range indexes {
		if _, err := d.exec(indexSQL); err != nil {
			return fmt.Errorf("failed to create large dataset index: %w", err)
		}
	}

	return nil
}

func (d *Database) statsNeedBackfill() (bool, error) {
	var hasLogs int
	if err := d.queryRow(`SELECT CASE WHEN EXISTS(SELECT 1 FROM request_logs LIMIT 1) THEN 1 ELSE 0 END`).Scan(&hasLogs); err != nil {
		return false, fmt.Errorf("failed to inspect request logs: %w", err)
	}
	if hasLogs == 0 {
		return false, nil
	}

	var hasDailyStats int
	if err := d.queryRow(`SELECT CASE WHEN EXISTS(SELECT 1 FROM request_log_daily_stats LIMIT 1) THEN 1 ELSE 0 END`).Scan(&hasDailyStats); err != nil {
		return false, fmt.Errorf("failed to inspect daily stats: %w", err)
	}

	return hasDailyStats == 0, nil
}

func (d *Database) rebuildStatsTables() error {
	tx, err := d.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin stats rebuild transaction: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	if _, err := tx.Exec(d.rebind(`DELETE FROM request_log_daily_stats`)); err != nil {
		return fmt.Errorf("failed to clear request_log_daily_stats: %w", err)
	}
	if _, err := tx.Exec(d.rebind(`DELETE FROM request_log_global_stats WHERE stats_key = ?`), globalRequestStatsKey); err != nil {
		return fmt.Errorf("failed to clear request_log_global_stats: %w", err)
	}

	if _, err := tx.Exec(d.rebind(`
		INSERT INTO request_log_global_stats (
			stats_key, total_requests, success_requests, error_requests,
			total_tokens, success_tokens, total_duration, success_duration, updated_at
		)
		SELECT
			?,
			COUNT(*) AS total_requests,
			COALESCE(SUM(CASE WHEN status_code = 200 THEN 1 ELSE 0 END), 0) AS success_requests,
			COALESCE(SUM(CASE WHEN status_code != 200 THEN 1 ELSE 0 END), 0) AS error_requests,
			COALESCE(SUM(tokens_used), 0) AS total_tokens,
			COALESCE(SUM(CASE WHEN status_code = 200 THEN tokens_used ELSE 0 END), 0) AS success_tokens,
			COALESCE(SUM(duration), 0) AS total_duration,
			COALESCE(SUM(CASE WHEN status_code = 200 THEN duration ELSE 0 END), 0) AS success_duration,
			CURRENT_TIMESTAMP
		FROM request_logs
	`), globalRequestStatsKey); err != nil {
		return fmt.Errorf("failed to rebuild global request stats: %w", err)
	}

	bucketExpr := "strftime('%Y-%m-%d', created_at)"
	if d.dialect == "postgres" {
		bucketExpr = "to_char(date_trunc('day', created_at), 'YYYY-MM-DD')"
	}

	insertDailyQuery := fmt.Sprintf(`
		INSERT INTO request_log_daily_stats (
			bucket_date, proxy_key_name, proxy_key_id, provider_group, model, is_stream,
			total_requests, success_requests, error_requests, total_tokens, success_tokens,
			total_duration, success_duration
		)
		SELECT
			%s AS bucket_date,
			proxy_key_name,
			proxy_key_id,
			COALESCE(provider_group, '') AS provider_group,
			COALESCE(model, '') AS model,
			is_stream,
			COUNT(*) AS total_requests,
			COALESCE(SUM(CASE WHEN status_code = 200 THEN 1 ELSE 0 END), 0) AS success_requests,
			COALESCE(SUM(CASE WHEN status_code != 200 THEN 1 ELSE 0 END), 0) AS error_requests,
			COALESCE(SUM(tokens_used), 0) AS total_tokens,
			COALESCE(SUM(CASE WHEN status_code = 200 THEN tokens_used ELSE 0 END), 0) AS success_tokens,
			COALESCE(SUM(duration), 0) AS total_duration,
			COALESCE(SUM(CASE WHEN status_code = 200 THEN duration ELSE 0 END), 0) AS success_duration
		FROM request_logs
		GROUP BY 1, 2, 3, 4, 5, 6
	`, bucketExpr)
	if _, err := tx.Exec(d.rebind(insertDailyQuery)); err != nil {
		return fmt.Errorf("failed to rebuild daily request stats: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit stats rebuild transaction: %w", err)
	}

	return nil
}

func (d *Database) applyStatsUpdates(tx *sql.Tx, logs []*RequestLog) error {
	if len(logs) == 0 {
		return nil
	}

	dailyStats := make(map[dailyStatsKey]*dailyStatsValue)
	var totalRequests, successRequests, errorRequests int64
	var totalTokens, successTokens int64
	var totalDuration, successDuration int64

	for _, row := range logs {
		totalRequests++
		totalTokens += int64(row.TokensUsed)
		totalDuration += row.Duration

		success := row.StatusCode == 200
		if success {
			successRequests++
			successTokens += int64(row.TokensUsed)
			successDuration += row.Duration
		} else {
			errorRequests++
		}

		key := dailyStatsKey{
			BucketDate:    row.CreatedAt.Format("2006-01-02"),
			ProxyKeyID:    row.ProxyKeyID,
			ProviderGroup: row.ProviderGroup,
			Model:         row.Model,
			IsStream:      row.IsStream,
		}
		acc, exists := dailyStats[key]
		if !exists {
			acc = &dailyStatsValue{
				ProxyKeyName: row.ProxyKeyName,
			}
			dailyStats[key] = acc
		}
		acc.TotalRequests++
		acc.TotalTokens += int64(row.TokensUsed)
		acc.TotalDuration += row.Duration
		if success {
			acc.SuccessRequests++
			acc.SuccessTokens += int64(row.TokensUsed)
			acc.SuccessDuration += row.Duration
		} else {
			acc.ErrorRequests++
		}
	}

	if _, err := tx.Exec(d.rebind(`
		INSERT INTO request_log_global_stats (
			stats_key, total_requests, success_requests, error_requests,
			total_tokens, success_tokens, total_duration, success_duration, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(stats_key) DO UPDATE SET
			total_requests = request_log_global_stats.total_requests + excluded.total_requests,
			success_requests = request_log_global_stats.success_requests + excluded.success_requests,
			error_requests = request_log_global_stats.error_requests + excluded.error_requests,
			total_tokens = request_log_global_stats.total_tokens + excluded.total_tokens,
			success_tokens = request_log_global_stats.success_tokens + excluded.success_tokens,
			total_duration = request_log_global_stats.total_duration + excluded.total_duration,
			success_duration = request_log_global_stats.success_duration + excluded.success_duration,
			updated_at = CURRENT_TIMESTAMP
	`), globalRequestStatsKey, totalRequests, successRequests, errorRequests, totalTokens, successTokens, totalDuration, successDuration); err != nil {
		return fmt.Errorf("failed to update global request stats: %w", err)
	}

	dailyUpsertQuery := `
		INSERT INTO request_log_daily_stats (
			bucket_date, proxy_key_name, proxy_key_id, provider_group, model, is_stream,
			total_requests, success_requests, error_requests, total_tokens, success_tokens,
			total_duration, success_duration
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(bucket_date, proxy_key_id, provider_group, model, is_stream) DO UPDATE SET
			proxy_key_name = excluded.proxy_key_name,
			total_requests = request_log_daily_stats.total_requests + excluded.total_requests,
			success_requests = request_log_daily_stats.success_requests + excluded.success_requests,
			error_requests = request_log_daily_stats.error_requests + excluded.error_requests,
			total_tokens = request_log_daily_stats.total_tokens + excluded.total_tokens,
			success_tokens = request_log_daily_stats.success_tokens + excluded.success_tokens,
			total_duration = request_log_daily_stats.total_duration + excluded.total_duration,
			success_duration = request_log_daily_stats.success_duration + excluded.success_duration
	`
	stmt, err := tx.Prepare(d.rebind(dailyUpsertQuery))
	if err != nil {
		return fmt.Errorf("failed to prepare daily stats upsert: %w", err)
	}
	defer stmt.Close()

	for key, value := range dailyStats {
		if _, err := stmt.Exec(
			key.BucketDate,
			value.ProxyKeyName,
			key.ProxyKeyID,
			key.ProviderGroup,
			key.Model,
			key.IsStream,
			value.TotalRequests,
			value.SuccessRequests,
			value.ErrorRequests,
			value.TotalTokens,
			value.SuccessTokens,
			value.TotalDuration,
			value.SuccessDuration,
		); err != nil {
			return fmt.Errorf("failed to update daily request stats: %w", err)
		}
	}

	return nil
}

func (d *Database) canUseAggregateStats(filter *LogFilter) bool {
	return filter == nil || (filter.StartTime == nil && filter.EndTime == nil)
}

func (d *Database) appendDailyDimensionFilters(filter *LogFilter) ([]string, []interface{}) {
	var (
		conds []string
		args  []interface{}
	)

	if filter == nil {
		return conds, args
	}

	if filter.ProxyKeyName != "" {
		conds = append(conds, "proxy_key_name = ?")
		args = append(args, filter.ProxyKeyName)
	}
	if filter.ProviderGroup != "" {
		conds = append(conds, "provider_group = ?")
		args = append(args, filter.ProviderGroup)
	}
	if filter.Model != "" {
		conds = append(conds, "model = ?")
		args = append(args, filter.Model)
	}
	if filter.Stream != "" {
		if filter.Stream == "true" {
			conds = append(conds, "is_stream = TRUE")
		} else if filter.Stream == "false" {
			conds = append(conds, "is_stream = FALSE")
		}
	}

	return conds, args
}

func (d *Database) getGlobalStats() (*TotalTokensStats, error) {
	stats := &TotalTokensStats{}
	err := d.queryRow(`
		SELECT total_tokens, success_tokens, total_requests, success_requests
		FROM request_log_global_stats
		WHERE stats_key = ?
	`, globalRequestStatsKey).Scan(
		&stats.TotalTokens,
		&stats.SuccessTokens,
		&stats.TotalRequests,
		&stats.SuccessRequests,
	)
	if err == sql.ErrNoRows {
		return stats, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query global request stats: %w", err)
	}

	return stats, nil
}

func (d *Database) getRequestCountFromDaily(filter *LogFilter) (int64, error) {
	selectExpr := "COALESCE(SUM(total_requests), 0)"
	if filter != nil {
		switch filter.Status {
		case "200":
			selectExpr = "COALESCE(SUM(success_requests), 0)"
		case "error":
			selectExpr = "COALESCE(SUM(error_requests), 0)"
		}
	}

	conds, args := d.appendDailyDimensionFilters(filter)
	query := fmt.Sprintf("SELECT %s FROM request_log_daily_stats", selectExpr)
	if len(conds) > 0 {
		query += " WHERE " + strings.Join(conds, " AND ")
	}

	var count int64
	if err := d.queryRow(query, args...).Scan(&count); err != nil {
		return 0, fmt.Errorf("failed to query daily request count: %w", err)
	}

	return count, nil
}

func (d *Database) getProxyKeyStatsFromDaily() ([]*ProxyKeyStats, error) {
	rows, err := d.query(`
		SELECT
			proxy_key_name,
			proxy_key_id,
			COALESCE(SUM(total_requests), 0) AS total_requests,
			COALESCE(SUM(success_requests), 0) AS success_requests,
			COALESCE(SUM(error_requests), 0) AS error_requests,
			COALESCE(SUM(total_tokens), 0) AS total_tokens,
			CASE WHEN COALESCE(SUM(total_requests), 0) > 0
				THEN (SUM(total_duration) * 1.0) / SUM(total_requests)
				ELSE 0
			END AS avg_duration
		FROM request_log_daily_stats
		GROUP BY proxy_key_name, proxy_key_id
		ORDER BY total_requests DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query daily proxy key stats: %w", err)
	}
	defer rows.Close()

	var stats []*ProxyKeyStats
	for rows.Next() {
		stat := &ProxyKeyStats{}
		if err := rows.Scan(
			&stat.ProxyKeyName,
			&stat.ProxyKeyID,
			&stat.TotalRequests,
			&stat.SuccessRequests,
			&stat.ErrorRequests,
			&stat.TotalTokens,
			&stat.AvgDuration,
		); err != nil {
			return nil, fmt.Errorf("failed to scan daily proxy key stats: %w", err)
		}
		stats = append(stats, stat)
	}

	return stats, nil
}

func (d *Database) getModelStatsFromDaily(filter *LogFilter) ([]*ModelStats, error) {
	conds, args := d.appendDailyDimensionFilters(filter)
	query := `
		SELECT
			model,
			COALESCE(SUM(success_requests), 0) AS total_requests,
			COALESCE(SUM(success_tokens), 0) AS total_tokens,
			CASE WHEN COALESCE(SUM(success_requests), 0) > 0
				THEN (SUM(success_duration) * 1.0) / SUM(success_requests)
				ELSE 0
			END AS avg_duration
		FROM request_log_daily_stats`
	if len(conds) > 0 {
		query += " WHERE " + strings.Join(conds, " AND ")
	}
	query += " GROUP BY model ORDER BY total_requests DESC"

	rows, err := d.query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query daily model stats: %w", err)
	}
	defer rows.Close()

	var stats []*ModelStats
	for rows.Next() {
		stat := &ModelStats{}
		if err := rows.Scan(&stat.Model, &stat.TotalRequests, &stat.TotalTokens, &stat.AvgDuration); err != nil {
			return nil, fmt.Errorf("failed to scan daily model stats: %w", err)
		}
		stats = append(stats, stat)
	}

	return stats, nil
}

func (d *Database) getStatusStatsFromDaily(filter *LogFilter) (*StatusStats, error) {
	successExpr := "COALESCE(SUM(success_requests), 0)"
	errorExpr := "COALESCE(SUM(error_requests), 0)"
	if filter != nil {
		switch filter.Status {
		case "200":
			errorExpr = "0"
		case "error":
			successExpr = "0"
		}
	}

	conds, args := d.appendDailyDimensionFilters(filter)
	query := fmt.Sprintf(`SELECT %s AS success_count, %s AS error_count FROM request_log_daily_stats`, successExpr, errorExpr)
	if len(conds) > 0 {
		query += " WHERE " + strings.Join(conds, " AND ")
	}

	stats := &StatusStats{}
	if err := d.queryRow(query, args...).Scan(&stats.Success, &stats.Error); err != nil {
		return nil, fmt.Errorf("failed to query daily status stats: %w", err)
	}

	return stats, nil
}

func (d *Database) getTokensTimelineFromDaily(filter *LogFilter) ([]*TimelinePoint, error) {
	conds, args := d.appendDailyDimensionFilters(filter)
	query := `
		SELECT
			bucket_date,
			COALESCE(SUM(total_tokens), 0) AS total_tokens,
			COALESCE(SUM(success_tokens), 0) AS success_tokens
		FROM request_log_daily_stats`
	if len(conds) > 0 {
		query += " WHERE " + strings.Join(conds, " AND ")
	}
	query += " GROUP BY bucket_date ORDER BY bucket_date ASC"

	rows, err := d.query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query daily token timeline: %w", err)
	}
	defer rows.Close()

	var out []*TimelinePoint
	for rows.Next() {
		point := &TimelinePoint{}
		if err := rows.Scan(&point.Date, &point.Total, &point.Success); err != nil {
			return nil, fmt.Errorf("failed to scan daily token timeline: %w", err)
		}
		out = append(out, point)
	}

	return out, nil
}

func (d *Database) getGroupTokensStatsFromDaily(filter *LogFilter) ([]*GroupTokensStat, error) {
	totalExpr := "COALESCE(SUM(total_tokens), 0)"
	successExpr := "COALESCE(SUM(success_tokens), 0)"
	if filter != nil {
		switch filter.Status {
		case "200":
			totalExpr = "COALESCE(SUM(success_tokens), 0)"
		case "error":
			totalExpr = "COALESCE(SUM(total_tokens - success_tokens), 0)"
			successExpr = "0"
		}
	}

	conds, args := d.appendDailyDimensionFilters(filter)
	query := fmt.Sprintf(`
		SELECT
			COALESCE(NULLIF(provider_group, ''), '-') AS grp,
			%s AS total_tokens,
			%s AS success_tokens
		FROM request_log_daily_stats`, totalExpr, successExpr)
	if len(conds) > 0 {
		query += " WHERE " + strings.Join(conds, " AND ")
	}
	query += " GROUP BY grp ORDER BY total_tokens DESC"

	rows, err := d.query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query daily group token stats: %w", err)
	}
	defer rows.Close()

	var out []*GroupTokensStat
	for rows.Next() {
		stat := &GroupTokensStat{}
		if err := rows.Scan(&stat.Group, &stat.Total, &stat.Success); err != nil {
			return nil, fmt.Errorf("failed to scan daily group token stats: %w", err)
		}
		out = append(out, stat)
	}

	return out, nil
}

func (d *Database) getLogFilterOptionsFromDaily() (*LogFilterOptions, error) {
	options := &LogFilterOptions{}

	loadDistinct := func(column string, target *[]string) error {
		query := fmt.Sprintf(`
			SELECT DISTINCT %s
			FROM request_log_daily_stats
			WHERE %s IS NOT NULL AND TRIM(%s) != ''
			ORDER BY %s ASC
		`, column, column, column, column)
		rows, err := d.query(query)
		if err != nil {
			return err
		}
		defer rows.Close()

		var values []string
		for rows.Next() {
			var value string
			if err := rows.Scan(&value); err != nil {
				return err
			}
			values = append(values, value)
		}
		*target = values
		return nil
	}

	if err := loadDistinct("proxy_key_name", &options.ProxyKeys); err != nil {
		return nil, fmt.Errorf("failed to load proxy key options from daily stats: %w", err)
	}
	if err := loadDistinct("provider_group", &options.ProviderGroups); err != nil {
		return nil, fmt.Errorf("failed to load provider group options from daily stats: %w", err)
	}
	if err := loadDistinct("model", &options.Models); err != nil {
		return nil, fmt.Errorf("failed to load model options from daily stats: %w", err)
	}

	return options, nil
}

func (d *Database) rebuildStatsTablesIfNeeded() error {
	needsBackfill, err := d.statsNeedBackfill()
	if err != nil {
		return err
	}
	if !needsBackfill {
		return nil
	}

	log.Println("Backfilling request log aggregate stats for large dataset queries")
	if err := d.rebuildStatsTables(); err != nil {
		return err
	}
	log.Println("Request log aggregate stats backfill completed")
	return nil
}
