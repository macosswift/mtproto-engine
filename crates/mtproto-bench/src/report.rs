#[derive(Debug, Clone, Default)]
pub struct Latency {
    pub p50: f64,
    pub p95: f64,
    pub p99: f64,
    pub max: f64,
}

impl Latency {
    pub fn from_samples(mut samples: Vec<f64>) -> Self {
        if samples.is_empty() {
            return Self::default();
        }
        samples.sort_by(f64::total_cmp);
        let at = |q: f64| samples[((samples.len() as f64 - 1.0) * q).round() as usize];
        Self { p50: at(0.50), p95: at(0.95), p99: at(0.99), max: *samples.last().expect("non-empty") }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ClientReport {
    pub engine: String,
    pub workload: String,
    pub completed: usize,
    pub failed: usize,
    pub elapsed: f64,
    pub latency: Latency,
    pub bytes: u64,
    pub throughput_mbps: f64,
    pub requests: Vec<(f64, Option<f64>)>,
    /// Files downloaded or uploaded in full, when the client counts them apart from its calls.
    pub transfers_done: Option<usize>,
    /// When the last of those files was done. Calls still in flight after it say nothing about how
    /// fast the files went.
    pub transfers_elapsed: Option<f64>,
}

fn number(value: f64) -> String {
    if value.is_finite() { format!("{value:.6}") } else { "null".into() }
}

impl ClientReport {
    /// Bytes a second the files went at: up to the last one done when the client says when that
    /// was and nothing failed or hung, over the whole run otherwise.
    pub fn transfer_rate(&self) -> f64 {
        let span = self.transfers_elapsed.filter(|at| *at > 0.0 && self.failed == 0).unwrap_or(self.elapsed);
        if span > 0.0 { self.bytes as f64 / span } else { 0.0 }
    }

    pub fn to_json(&self) -> String {
        let requests: Vec<String> = self
            .requests
            .iter()
            .map(|(sent, done)| format!("[{},{}]", number(*sent), done.map(number).unwrap_or_else(|| "null".into())))
            .collect();
        format!(
            "{{\"engine\":\"{}\",\"workload\":\"{}\",\"completed\":{},\"failed\":{},\"elapsed\":{},\"latency_ms\":{{\"p50\":{},\"p95\":{},\"p99\":{},\"max\":{}}},\"bytes\":{},\"throughput_mbps\":{},\"requests\":[{}]}}",
            self.engine,
            self.workload,
            self.completed,
            self.failed,
            number(self.elapsed),
            number(self.latency.p50),
            number(self.latency.p95),
            number(self.latency.p99),
            number(self.latency.max),
            self.bytes,
            number(self.throughput_mbps),
            requests.join(",")
        )
    }

    pub fn from_json(text: &str) -> Option<Self> {
        let value = crate::json::parse(text)?;
        let latency = value.get("latency_ms");
        let requests = value
            .get("requests")
            .and_then(|r| r.as_array())
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| {
                        let pair = item.as_array()?;
                        Some((pair.first()?.as_f64()?, pair.get(1).and_then(|v| v.as_f64())))
                    })
                    .collect()
            })
            .unwrap_or_default();
        Some(Self {
            engine: value.get("engine")?.as_str()?.to_string(),
            workload: value.get("workload")?.as_str()?.to_string(),
            completed: value.get("completed")?.as_f64()? as usize,
            failed: value.get("failed")?.as_f64()? as usize,
            elapsed: value.get("elapsed")?.as_f64()?,
            latency: Latency {
                p50: latency.and_then(|l| l.get("p50")).and_then(|v| v.as_f64()).unwrap_or(0.0),
                p95: latency.and_then(|l| l.get("p95")).and_then(|v| v.as_f64()).unwrap_or(0.0),
                p99: latency.and_then(|l| l.get("p99")).and_then(|v| v.as_f64()).unwrap_or(0.0),
                max: latency.and_then(|l| l.get("max")).and_then(|v| v.as_f64()).unwrap_or(0.0),
            },
            bytes: value.get("bytes").and_then(|v| v.as_f64()).unwrap_or(0.0) as u64,
            throughput_mbps: value.get("throughput_mbps").and_then(|v| v.as_f64()).unwrap_or(0.0),
            requests,
            transfers_done: value.get("transfers_done").and_then(|v| v.as_f64()).map(|v| v as usize),
            transfers_elapsed: value.get("transfers_elapsed").and_then(|v| v.as_f64()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(failed: usize) -> ClientReport {
        let text = format!(
            "{{\"engine\":\"tc-rust\",\"workload\":\"tc-mixed\",\"completed\":40,\"failed\":{failed},\"elapsed\":12.0,\"bytes\":48000,\"transfers_done\":4,\"transfers_elapsed\":9.6,\"requests\":[]}}"
        );
        ClientReport::from_json(&text).expect("report")
    }

    #[test]
    fn calls_answered_after_the_last_file_do_not_lower_its_rate() {
        assert_eq!(report(0).transfer_rate(), 5000.0);
    }

    #[test]
    fn a_run_where_something_failed_is_rated_over_its_whole_length() {
        assert_eq!(report(1).transfer_rate(), 4000.0);
    }
}
