#[derive(Debug, Clone)]
pub struct ClientArgs {
    pub engine_label: String,
    pub mode: String,
    pub address: String,
    pub dc: i32,
    pub key_hex: Option<String>,
    pub salt: i64,
    pub secret: Option<String>,
    pub workload: String,
    pub requests: usize,
    pub concurrency: usize,
    pub part_size: u32,
    pub total_bytes: u64,
    pub sessions: usize,
    pub session_concurrency: usize,
    pub rate: f64,
    pub duration: f64,
    pub deadline: f64,
}

impl Default for ClientArgs {
    fn default() -> Self {
        Self {
            engine_label: "rust".into(),
            mode: "fake".into(),
            address: String::new(),
            dc: 2,
            key_hex: None,
            salt: 0,
            secret: None,
            workload: "small".into(),
            requests: 1000,
            concurrency: 32,
            part_size: 512 * 1024,
            total_bytes: 32 * 1024 * 1024,
            sessions: 4,
            session_concurrency: 3,
            rate: 10.0,
            duration: 10.0,
            deadline: 120.0,
        }
    }
}

impl ClientArgs {
    pub fn parse(arguments: &[String]) -> Self {
        let mut args = Self::default();
        let mut iter = arguments.iter();
        while let Some(flag) = iter.next() {
            let mut value = || iter.next().cloned().unwrap_or_else(|| panic!("{flag} needs a value"));
            match flag.as_str() {
                "--engine-label" => args.engine_label = value(),
                "--mode" => args.mode = value(),
                "--address" => args.address = value(),
                "--dc" => args.dc = value().parse().expect("dc"),
                "--key-hex" => args.key_hex = Some(value()),
                "--salt" => args.salt = value().parse().expect("salt"),
                "--secret" => args.secret = Some(value()),
                "--workload" => args.workload = value(),
                "--requests" => args.requests = value().parse().expect("requests"),
                "--concurrency" => args.concurrency = value().parse().expect("concurrency"),
                "--part-size" => args.part_size = value().parse().expect("part size"),
                "--total-bytes" => args.total_bytes = value().parse().expect("total bytes"),
                "--sessions" => args.sessions = value().parse().expect("sessions"),
                "--session-concurrency" => args.session_concurrency = value().parse().expect("session concurrency"),
                "--rate" => args.rate = value().parse().expect("rate"),
                "--duration" => args.duration = value().parse().expect("duration"),
                "--deadline" => args.deadline = value().parse().expect("deadline"),
                other => panic!("unknown argument {other}"),
            }
        }
        args
    }

    pub fn to_arguments(&self) -> Vec<String> {
        let mut out = vec![
            "--engine-label".into(),
            self.engine_label.clone(),
            "--mode".into(),
            self.mode.clone(),
            "--address".into(),
            self.address.clone(),
            "--dc".into(),
            self.dc.to_string(),
            "--salt".into(),
            self.salt.to_string(),
            "--workload".into(),
            self.workload.clone(),
            "--requests".into(),
            self.requests.to_string(),
            "--concurrency".into(),
            self.concurrency.to_string(),
            "--part-size".into(),
            self.part_size.to_string(),
            "--total-bytes".into(),
            self.total_bytes.to_string(),
            "--sessions".into(),
            self.sessions.to_string(),
            "--session-concurrency".into(),
            self.session_concurrency.to_string(),
            "--rate".into(),
            self.rate.to_string(),
            "--duration".into(),
            self.duration.to_string(),
            "--deadline".into(),
            self.deadline.to_string(),
        ];
        if let Some(key) = &self.key_hex {
            out.push("--key-hex".into());
            out.push(key.clone());
        }
        if let Some(secret) = &self.secret {
            out.push("--secret".into());
            out.push(secret.clone());
        }
        out
    }
}

pub fn unhex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex")).collect()
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
