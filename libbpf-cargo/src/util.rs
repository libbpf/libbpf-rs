//! Utility functionality for working with generated skeletons.

use std::error::Error;
use std::fmt::Arguments;
use std::fmt::Debug;
use std::fmt::Result;

use tracing::field::Field;
use tracing::field::Visit;
use tracing::Event;
use tracing::Subscriber;
use tracing_subscriber::fmt::format::FormatFields;
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::FmtContext;
use tracing_subscriber::fmt::FormatEvent;
use tracing_subscriber::registry::LookupSpan;


/// A visitor for "extracting" captured field values from a tracing
/// span/event.
#[derive(Debug)]
struct Visitor<'w> {
    writer: Writer<'w>,
}

impl<'w> Visitor<'w> {
    fn new(writer: Writer<'w>) -> Self {
        Self { writer }
    }

    fn record_value(&mut self, field: &Field, value: Arguments<'_>) {
        let name = field.name();
        // Special case the field "message", only printing the value and
        // not the name.
        if name == "message" {
            let _result = writeln!(self.writer, "cargo:warning={value}");
        } else {
            let _result = writeln!(self.writer, "cargo:warning={name}={value}");
        }
    }
}

impl Visit for Visitor<'_> {
    fn record_debug(&mut self, field: &Field, value: &dyn Debug) {
        self.record_value(field, format_args!("{value:?}"))
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        self.record_value(field, format_args!("{value}"))
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.record_value(field, format_args!("{value}"))
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.record_value(field, format_args!("{value}"))
    }

    fn record_i128(&mut self, field: &Field, value: i128) {
        self.record_value(field, format_args!("{value}"))
    }

    fn record_u128(&mut self, field: &Field, value: u128) {
        self.record_value(field, format_args!("{value}"))
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.record_value(field, format_args!("{value}"))
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.record_value(field, format_args!("{value}"))
    }

    fn record_error(&mut self, field: &Field, value: &(dyn Error + 'static)) {
        self.record_value(field, format_args!("{value}"))
    }
}


/// A `tracing` formatter intended for surfacing compiler
/// warnings/messages from within a build script.
///
/// ```no_run
/// # use libbpf_cargo::SkeletonBuilder;
/// # use libbpf_cargo::util::CargoWarningFormatter;
/// let () = tracing_subscriber::fmt()
///     .event_format(CargoWarningFormatter)
///     .init();
///
/// // Generate and build the skeleton, which may emit compiler
/// // warnings.
/// SkeletonBuilder::new()
///     // [...]
///     .build()
///     .unwrap();
/// ```
#[derive(Debug)]
pub struct CargoWarningFormatter;

impl<S, N> FormatEvent<S, N> for CargoWarningFormatter
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        _ctx: &FmtContext<'_, S, N>,
        writer: Writer<'_>,
        event: &Event<'_>,
    ) -> Result {
        let mut visitor = Visitor::new(writer);
        let () = event.record(&mut visitor);
        Ok(())
    }
}
