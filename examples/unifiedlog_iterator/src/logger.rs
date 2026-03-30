// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use chrono::Utc;
use clap::ValueEnum;
use serde_json::{Map, Value};
use std::fmt;
use std::fs::OpenOptions;
use std::path::Path;
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_log::LogTracer;
use tracing_subscriber::fmt as tracing_fmt;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

// Field visitor to convert event fields into a JSON map, while filtering out unwanted log crate fields.
struct JsonFieldVisitor {
    map: Map<String, Value>,
}

impl Visit for JsonFieldVisitor {
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.insert(field, Value::from(value));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.insert(field, Value::from(value));
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.insert(field, Value::from(value));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.insert(field, Value::from(value));
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.insert(field, Value::String(format!("{:?}", value)));
    }
}

impl JsonFieldVisitor {
    fn insert(&mut self, field: &Field, value: Value) {
        let name = field.name();

        // Filter unwanted log crate fields
        if matches!(
            name,
            "log.target" | "log.module_path" | "log.file" | "log.line"
        ) {
            return;
        }

        self.map.insert(name.to_string(), value);
    }
}

// Custom event formatter that output structured JSON  with event fields and span context.
// Filters out unwanted log crate fields as per the JsonFieldVisitor and includes timestamp and log level in the output.
struct FilteredJson;

impl<S, N> tracing_fmt::FormatEvent<S, N> for FilteredJson
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> tracing_fmt::FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &tracing_fmt::FmtContext<'_, S, N>,
        mut writer: tracing_fmt::format::Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let mut out = Map::new();
        // ---- Base fields ----
        out.insert("datetime".into(), Value::String(Utc::now().to_rfc3339()));
        out.insert(
            "level".into(),
            Value::String(event.metadata().level().to_string()),
        );
        // ---- Event fields ----
        let mut visitor = JsonFieldVisitor { map: Map::new() };
        event.record(&mut visitor);

        for (k, v) in visitor.map {
            out.insert(k, v);
        }

        // ---- Span context ----
        if let Some(scope) = ctx.event_scope() {
            let mut spans = Vec::new();

            for span in scope.from_root() {
                let mut span_obj = Map::new();

                span_obj.insert("name".into(), Value::String(span.name().to_string()));

                // Capture span fields (if any)
                let mut fields = Map::new();
                if let Some(f) = span
                    .extensions()
                    .get::<tracing_subscriber::fmt::FormattedFields<N>>()
                {
                    fields.insert("fields".into(), Value::String(f.to_string()));
                }

                if !fields.is_empty() {
                    span_obj.insert("fields".into(), Value::Object(fields));
                }

                spans.push(Value::Object(span_obj));
            }

            out.insert("spans".into(), Value::Array(spans));
        }

        writeln!(writer, "{}", serde_json::to_string(&out).unwrap())
    }
}

/// Log level configuration for CLI.
///
/// This is separate from `log::LevelFilter` to get nice clap `ValueEnum` support.
#[derive(ValueEnum, Clone, Debug)]
pub enum LogLevel {
    Off,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl From<LogLevel> for tracing_subscriber::filter::LevelFilter {
    fn from(level: LogLevel) -> Self {
        match level {
            LogLevel::Off => tracing_subscriber::filter::LevelFilter::OFF,
            LogLevel::Error => tracing_subscriber::filter::LevelFilter::ERROR,
            LogLevel::Warn => tracing_subscriber::filter::LevelFilter::WARN,
            LogLevel::Info => tracing_subscriber::filter::LevelFilter::INFO,
            LogLevel::Debug => tracing_subscriber::filter::LevelFilter::DEBUG,
            LogLevel::Trace => tracing_subscriber::filter::LevelFilter::TRACE,
        }
    }
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            LogLevel::Off => "off",
            LogLevel::Error => "error",
            LogLevel::Warn => "warn",
            LogLevel::Info => "info",
            LogLevel::Debug => "debug",
            LogLevel::Trace => "trace",
        };
        write!(f, "{}", s)
    }
}

/// Initialize tracing-based logging.
///
/// Always logs to stderr/terminal, and optionally also writes structured JSON to a file.
pub fn init_logging(
    log_file: Option<&Path>,
    level: LogLevel,
) -> Result<Option<tracing_appender::non_blocking::WorkerGuard>, Box<dyn std::error::Error>> {
    // Forward `log` records (log crate macros) into tracing
    let _ = LogTracer::init();

    let level_filter: tracing_subscriber::filter::LevelFilter = level.into();

    let stdout_layer = tracing_fmt::layer().with_writer(std::io::stderr);

    let (json_layer, guard) = if let Some(path) = log_file {
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)?;
        let (non_blocking, guard) = tracing_appender::non_blocking(file);

        let json_layer = tracing_fmt::layer()
            .with_writer(non_blocking)
            .event_format(FilteredJson);

        (Some(json_layer), Some(guard))
    } else {
        (None, None)
    };

    let _ = tracing_subscriber::registry()
        .with(level_filter)
        .with(stdout_layer)
        .with(json_layer)
        .try_init();
    Ok(guard)
}
