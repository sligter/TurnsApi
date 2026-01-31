package storage

import "time"

type DatabaseConfig struct {
	// Driver supports: "sqlite" (default), "postgres"
	Driver string `yaml:"driver"`

	// SQLite settings
	Path string `yaml:"path"`

	// Postgres settings (recommended for high concurrency)
	DSN string `yaml:"dsn"`

	// Connection pool tuning (applies to postgres; sqlite is forced to 1)
	MaxOpenConns    int           `yaml:"max_open_conns"`
	MaxIdleConns    int           `yaml:"max_idle_conns"`
	ConnMaxLifetime time.Duration `yaml:"conn_max_lifetime"`

	// Request logs retention (days)
	RetentionDays int `yaml:"retention_days"`
}

type RequestLogsConfig struct {
	// AsyncWrite enables background batching to avoid blocking request handlers.
	AsyncWrite bool `yaml:"async_write"`

	// Buffer is the channel size for queued log writes.
	Buffer int `yaml:"buffer"`

	// BatchSize is the maximum number of log rows written per batch.
	BatchSize int `yaml:"batch_size"`

	// FlushInterval controls how often buffered logs are flushed.
	FlushInterval time.Duration `yaml:"flush_interval"`
}
