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
}

fn number(value: f64) -> String {
    if value.is_finite() { format!("{value:.6}") } else { "null".into() }
}

impl ClientReport {
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
        })
    }
}
