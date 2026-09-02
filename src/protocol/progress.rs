use std::io::{self, Write};

use serde::Serialize;

use crate::protocol::Response;

/// A named, stable step identifier chosen by operation code (e.g.
/// `"validate"`, `"fetch"`, `"switch"`). Never derived from request input.
pub type Step = &'static str;

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ProgressStatus {
    Start,
    Ok,
    Failed,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProgressEvent {
    pub step: Step,
    pub status: ProgressStatus,
}

/// One line of a JSON Lines mutation stream: zero or more `Progress` lines
/// followed by exactly one `Result` line carrying the final envelope.
#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum Line {
    Progress(ProgressEvent),
    Result(Response),
}

#[derive(Debug)]
pub enum JsonLinesError {
    Io(io::Error),
    Serialization,
}

/// Writes a bounded JSON Lines stream to `sink`: each line is one compact
/// JSON object followed by `\n`, flushed immediately so a slow or
/// disconnecting reader sees progress as it happens rather than only at
/// process exit. `finish` consumes the writer, so at most one `Result` line
/// can ever be emitted through a given writer.
pub struct JsonLinesWriter<W: Write> {
    sink: W,
}

impl<W: Write> JsonLinesWriter<W> {
    pub fn new(sink: W) -> Self {
        Self { sink }
    }

    pub fn progress(&mut self, step: Step, status: ProgressStatus) -> Result<(), JsonLinesError> {
        self.write_line(&Line::Progress(ProgressEvent { step, status }))
    }

    pub fn finish(mut self, response: Response) -> Result<(), JsonLinesError> {
        self.write_line(&Line::Result(response))
    }

    fn write_line(&mut self, line: &Line) -> Result<(), JsonLinesError> {
        let mut json = serde_json::to_vec(line).map_err(|_| JsonLinesError::Serialization)?;
        json.push(b'\n');
        self.sink.write_all(&json).map_err(JsonLinesError::Io)?;
        self.sink.flush().map_err(JsonLinesError::Io)
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, Write};

    use serde_json::Value;

    use super::{JsonLinesWriter, ProgressStatus};
    use crate::{error::ErrorCode, protocol::Response};

    fn lines(bytes: &[u8]) -> Vec<Value> {
        String::from_utf8(bytes.to_vec())
            .expect("output should be UTF-8")
            .lines()
            .map(|line| serde_json::from_str(line).expect("each line should be valid JSON"))
            .collect()
    }

    #[test]
    fn progress_lines_precede_a_single_result_line() {
        let mut buffer = Vec::new();
        let mut writer = JsonLinesWriter::new(&mut buffer);
        writer
            .progress("validate", ProgressStatus::Start)
            .expect("progress line should write");
        writer
            .progress("validate", ProgressStatus::Ok)
            .expect("progress line should write");
        writer
            .finish(Response::failure(
                "site.deploy",
                ErrorCode::SubprocessFailed,
                "git fetch failed",
            ))
            .expect("result line should write");

        let events = lines(&buffer);
        assert_eq!(events.len(), 3);
        assert_eq!(events[0]["type"], "progress");
        assert_eq!(events[0]["step"], "validate");
        assert_eq!(events[0]["status"], "start");
        assert_eq!(events[1]["status"], "ok");
        assert_eq!(events[2]["type"], "result");
        assert_eq!(events[2]["ok"], false);
        assert_eq!(events[2]["error"]["code"], "SUBPROCESS_FAILED");
    }

    #[test]
    fn result_line_carries_the_full_response_envelope() {
        let mut buffer = Vec::new();
        let writer = JsonLinesWriter::new(&mut buffer);
        writer
            .finish(
                Response::success("site.deploy", serde_json::json!({"releaseId": "r-1"}))
                    .expect("response should build"),
            )
            .expect("result line should write");

        let events = lines(&buffer);
        assert_eq!(events.len(), 1);
        let result = &events[0];
        assert_eq!(result["type"], "result");
        assert_eq!(result["protocolVersion"], 1);
        assert_eq!(result["operation"], "site.deploy");
        assert_eq!(result["ok"], true);
        assert_eq!(result["result"]["releaseId"], "r-1");
    }

    struct FlushCounter<'a> {
        inner: &'a mut Vec<u8>,
        flushes: usize,
    }

    impl Write for FlushCounter<'_> {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.inner.write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.flushes += 1;
            Ok(())
        }
    }

    #[test]
    fn each_line_is_flushed_immediately_rather_than_buffered() {
        let mut buffer = Vec::new();
        let mut counter = FlushCounter {
            inner: &mut buffer,
            flushes: 0,
        };
        {
            let mut writer = JsonLinesWriter::new(&mut counter);
            writer
                .progress("validate", ProgressStatus::Start)
                .expect("progress line should write");
            writer
                .progress("validate", ProgressStatus::Ok)
                .expect("progress line should write");
            writer
                .finish(Response::failure(
                    "site.deploy",
                    ErrorCode::Internal,
                    "boom",
                ))
                .expect("result line should write");
        }
        assert_eq!(counter.flushes, 3);
    }
}
