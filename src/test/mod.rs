
use crate::ast::*;
use crate::error::{CompileError, Result, Span};
use std::collections::HashMap;

pub struct TestRunner {
    tests: Vec<TestCase>,
    results: Vec<TestResult>,
    fail_fast: bool,
}

#[derive(Debug, Clone)]
pub struct TestCase {
    pub name: String,
    pub ty: TestType,
    pub code: String,
    pub expectation: TestExpectation,
    pub source_file: String,
    pub line: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestType {
    Unit,
    Integration,
    Doc,
    Property,
}

#[derive(Debug, Clone)]
pub enum TestExpectation {
    Success,
    Failure(String),
    CompileError(String),
    RuntimeError(String),
    Output(String),
}

#[derive(Debug, Clone)]
pub struct TestResult {
    pub name: String,
    pub passed: bool,
    pub duration_us: u64,
    pub output: String,
    pub error: Option<String>,
}

pub struct TestSuite {
    pub name: String,
    pub tests: Vec<TestCase>,
    pub setup: Option<String>,
    pub teardown: Option<String>,
}

pub struct TestContext {
    pub globals: HashMap<String, Value>,
    pub module: Option<Module>,
    pub output: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum Value {
    U64(u64),
    U128(u128),
    Bool(bool),
    String(String),
    Address([u8; 32]),
    Hash([u8; 32]),
    Resource(String, HashMap<String, Value>),
    Receipt(String, HashMap<String, Value>),
    Unit,
}

impl TestRunner {
    pub fn new() -> Self {
        Self { tests: Vec::new(), results: Vec::new(), fail_fast: false }
    }

    pub fn fail_fast(mut self, enabled: bool) -> Self {
        self.fail_fast = enabled;
        self
    }

    pub fn add_test(&mut self, test: TestCase) {
        self.tests.push(test);
    }

    pub fn add_suite(&mut self, suite: TestSuite) {
        for test in suite.tests {
            self.add_test(test);
        }
    }

    pub fn run(&mut self) -> TestSummary {
        let start = std::time::Instant::now();

        for test in &self.tests {
            let result = self.run_test(test);
            let passed = result.passed;
            self.results.push(result);

            if !passed && self.fail_fast {
                break;
            }
        }

        let duration = start.elapsed();

        TestSummary {
            total: self.results.len(),
            passed: self.results.iter().filter(|r| r.passed).count(),
            failed: self.results.iter().filter(|r| !r.passed).count(),
            duration,
            results: self.results.clone(),
        }
    }

    fn run_test(&self, test: &TestCase) -> TestResult {
        let start = std::time::Instant::now();

        let (passed, output, error) = match &test.ty {
            TestType::Unit => self.run_unit_test(test),
            TestType::Integration => self.run_integration_test(test),
            TestType::Doc => self.run_doc_test(test),
            TestType::Property => self.run_property_test(test),
        };

        let duration = start.elapsed();

        TestResult {
            name: test.name.clone(),
            passed,
            duration_us: duration.as_micros() as u64,
            output: output.unwrap_or_default(),
            error,
        }
    }

    fn run_unit_test(&self, test: &TestCase) -> (bool, Option<String>, Option<String>) {
        self.unsupported_test_execution(test, "unit")
    }

    fn run_integration_test(&self, test: &TestCase) -> (bool, Option<String>, Option<String>) {
        self.unsupported_test_execution(test, "integration")
    }

    fn run_doc_test(&self, test: &TestCase) -> (bool, Option<String>, Option<String>) {
        self.unsupported_test_execution(test, "doc")
    }

    fn run_property_test(&self, test: &TestCase) -> (bool, Option<String>, Option<String>) {
        self.unsupported_test_execution(test, "property")
    }

    fn unsupported_test_execution(&self, test: &TestCase, kind: &str) -> (bool, Option<String>, Option<String>) {
        let message = format!(
            "cellscript {} test execution is still experimental and has no trusted runtime backend; refusing to report '{}' as passed",
            kind, test.name
        );
        (false, None, Some(message))
    }

    pub fn print_results(&self) {
        println!("\n{}", "Running tests:".bold());

        for result in &self.results {
            if result.passed {
                println!("  {} {} ({} µs)", "✓".green(), result.name, result.duration_us);
            } else {
                println!("  {} {} ({} µs)", "✗".red(), result.name, result.duration_us);
                if let Some(error) = &result.error {
                    println!("    {}", error.red());
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct TestSummary {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub duration: std::time::Duration,
    pub results: Vec<TestResult>,
}

impl TestSummary {
    pub fn all_passed(&self) -> bool {
        self.failed == 0
    }

    pub fn print(&self) {
        println!("\n{}", "Test Summary:".bold());
        println!("  Total:   {}", self.total);
        println!("  Passed:  {}", self.passed.to_string().green());
        println!("  Failed:  {}", self.failed.to_string().red());
        println!("  Time:    {:.2}s", self.duration.as_secs_f64());

        if self.all_passed() {
            println!("\n{}", "All tests passed!".green().bold());
        } else {
            println!("\n{}", "Some tests failed!".red().bold());
        }
    }
}

#[macro_export]
macro_rules! test {
    ($name:ident, $code:expr) => {
        TestCase {
            name: stringify!($name).to_string(),
            ty: TestType::Unit,
            code: $code.to_string(),
            expectation: TestExpectation::Success,
            source_file: file!().to_string(),
            line: line!(),
        }
    };
    ($name:ident, $code:expr, expect: $expect:expr) => {
        TestCase {
            name: stringify!($name).to_string(),
            ty: TestType::Unit,
            code: $code.to_string(),
            expectation: TestExpectation::Output($expect.to_string()),
            source_file: file!().to_string(),
            line: line!(),
        }
    };
}

#[macro_export]
macro_rules! assert_eq {
    ($left:expr, $right:expr) => {
        if $left != $right {
            panic!("Assertion failed: {:?} != {:?}", $left, $right);
        }
    };
}

pub struct TestParser;

impl TestParser {
    pub fn extract_tests(module: &Module) -> Vec<TestCase> {
        let mut tests = Vec::new();

        for item in &module.items {
            if let Item::Action(action) = item {
                if action.name.starts_with("test_") {
                    tests.push(TestCase {
                        name: action.name.clone(),
                        ty: TestType::Unit,
                        code: String::new(),
                        expectation: TestExpectation::Success,
                        source_file: String::new(),
                        line: 0,
                    });
                }
            }
        }

        tests
    }

    pub fn extract_doc_tests(source: &str) -> Vec<TestCase> {
        let mut tests = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        let mut in_test = false;
        let mut test_code = Vec::new();
        let mut line_num = 0;

        for (i, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("/// ```cellscript") {
                in_test = true;
                test_code.clear();
                line_num = i + 1;
            } else if trimmed == "/// ```" && in_test {
                in_test = false;
                tests.push(TestCase {
                    name: format!("doc_test_{}", line_num),
                    ty: TestType::Doc,
                    code: test_code.join("\n"),
                    expectation: TestExpectation::Success,
                    source_file: String::new(),
                    line: line_num as u32,
                });
            } else if in_test && trimmed.starts_with("/// ") {
                test_code.push(&trimmed[4..]);
            }
        }

        tests
    }
}

pub struct PropertyTester;

impl PropertyTester {
    pub fn random_u64() -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        use std::time::SystemTime;

        let mut hasher = DefaultHasher::new();
        SystemTime::now().hash(&mut hasher);
        hasher.finish()
    }

    pub fn random_address() -> [u8; 32] {
        let mut addr = [0u8; 32];
        for i in 0..32 {
            addr[i] = (Self::random_u64() >> (i * 2)) as u8;
        }
        addr
    }

    pub fn verify<F>(name: &str, property: F, iterations: usize) -> TestResult
    where
        F: Fn() -> bool,
    {
        let start = std::time::Instant::now();

        for i in 0..iterations {
            if !property() {
                return TestResult {
                    name: name.to_string(),
                    passed: false,
                    duration_us: start.elapsed().as_micros() as u64,
                    output: String::new(),
                    error: Some(format!("Property failed at iteration {}", i)),
                };
            }
        }

        TestResult {
            name: name.to_string(),
            passed: true,
            duration_us: start.elapsed().as_micros() as u64,
            output: format!("Verified {} iterations", iterations),
            error: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_test_runner() {
        let mut runner = TestRunner::new();

        runner.add_test(TestCase {
            name: "test_pass".to_string(),
            ty: TestType::Unit,
            code: String::new(),
            expectation: TestExpectation::Success,
            source_file: String::new(),
            line: 0,
        });

        let summary = runner.run();
        assert_eq!(summary.total, 1);
        assert_eq!(summary.failed, 1);
        assert!(!summary.all_passed());
        assert!(summary.results[0].error.as_deref().unwrap_or_default().contains("still experimental"));
    }

    #[test]
    fn test_property_tester() {
        let result = PropertyTester::verify("always_true", || true, 100);
        assert!(result.passed);

        let result = PropertyTester::verify("always_false", || false, 100);
        assert!(!result.passed);
    }

    #[test]
    fn test_doc_test_extraction() {
        let source = r#"
/// Some documentation
/// ```cellscript
/// let x = 42;
/// assert!(x == 42);
/// ```
resource Test {}
"#;

        let tests = TestParser::extract_doc_tests(source);
        assert_eq!(tests.len(), 1);
        assert!(tests[0].code.contains("let x = 42"));
    }
}

use colored::Colorize;
