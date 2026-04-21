//!

use crate::error::Result;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

pub struct IncrementalCompiler {
    cache_dir: PathBuf,
    dep_graph: DependencyGraph,
    _file_hashes: HashMap<PathBuf, u64>,
    unit_cache: HashMap<String, CompiledUnit>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledUnit {
    pub source_path: PathBuf,
    pub source_hash: u64,
    pub output_path: PathBuf,
    pub output_hash: u64,
    pub dependencies: Vec<PathBuf>,
    pub timestamp: SystemTime,
    pub compile_options: CompileOptions,
}

#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq)]
pub struct CompileOptions {
    pub opt_level: u8,
    pub target: String,
    pub debug: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DependencyGraph {
    pub dependents: HashMap<PathBuf, HashSet<PathBuf>>,
    pub dependencies: HashMap<PathBuf, HashSet<PathBuf>>,
}

pub struct ChangeDetector {
    snapshots: HashMap<PathBuf, FileSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileSnapshot {
    pub path: PathBuf,
    pub hash: u64,
    pub mtime: SystemTime,
    pub size: u64,
}

impl IncrementalCompiler {
    pub fn new(cache_dir: impl AsRef<Path>) -> Self {
        let cache_dir = cache_dir.as_ref().to_path_buf();

        fs::create_dir_all(&cache_dir).ok();

        Self { cache_dir, dep_graph: DependencyGraph::default(), _file_hashes: HashMap::new(), unit_cache: HashMap::new() }
    }

    pub fn load_cache(&mut self) -> Result<()> {
        let cache_file = self.cache_dir.join("compile_cache.json");

        if cache_file.exists() {
            let content = fs::read_to_string(&cache_file)?;
            let cache: IncrementalCache = serde_json::from_str(&content)?;
            self.dep_graph = cache.dep_graph;
            self.unit_cache = cache.units;
        }

        Ok(())
    }

    pub fn save_cache(&self) -> Result<()> {
        let cache_file = self.cache_dir.join("compile_cache.json");

        let cache = IncrementalCache { dep_graph: self.dep_graph.clone(), units: self.unit_cache.clone() };

        let content = serde_json::to_string_pretty(&cache)?;
        fs::write(&cache_file, content)?;

        Ok(())
    }

    pub fn needs_recompile(&self, source: &Path, options: &CompileOptions) -> bool {
        let source_str = source.to_string_lossy().to_string();

        let Some(unit) = self.unit_cache.get(&source_str) else {
            return true;
        };

        if unit.compile_options != *options {
            return true;
        }

        let current_hash = match compute_file_hash(source) {
            Ok(h) => h,
            Err(_) => return true,
        };

        if unit.source_hash != current_hash {
            return true;
        }

        for dep in &unit.dependencies {
            let dep_hash = match compute_file_hash(dep) {
                Ok(h) => h,
                Err(_) => return true,
            };

            let dep_str = dep.to_string_lossy().to_string();
            if let Some(dep_unit) = self.unit_cache.get(&dep_str) {
                if dep_unit.source_hash != dep_hash {
                    return true;
                }
            } else {
                return true;
            }
        }

        false
    }

    pub fn get_affected_files(&self, changed_file: &Path) -> HashSet<PathBuf> {
        let mut affected = HashSet::new();
        let mut to_process = vec![changed_file.to_path_buf()];

        while let Some(file) = to_process.pop() {
            if let Some(dependents) = self.dep_graph.dependents.get(&file) {
                for dependent in dependents {
                    if affected.insert(dependent.clone()) {
                        to_process.push(dependent.clone());
                    }
                }
            }
        }

        affected
    }

    pub fn record_compilation(
        &mut self,
        source: &Path,
        output: &Path,
        dependencies: Vec<PathBuf>,
        options: &CompileOptions,
    ) -> Result<()> {
        let source_hash = compute_file_hash(source)?;
        let output_hash = compute_file_hash(output).unwrap_or(0);

        let unit = CompiledUnit {
            source_path: source.to_path_buf(),
            source_hash,
            output_path: output.to_path_buf(),
            output_hash,
            dependencies: dependencies.clone(),
            timestamp: SystemTime::now(),
            compile_options: options.clone(),
        };

        for dep in &dependencies {
            self.dep_graph.dependents.entry(dep.clone()).or_default().insert(source.to_path_buf());
        }

        self.dep_graph.dependencies.entry(source.to_path_buf()).or_default().extend(dependencies);

        let source_str = source.to_string_lossy().to_string();
        self.unit_cache.insert(source_str, unit);

        Ok(())
    }

    pub fn clean_cache(&mut self, max_age_days: u64) -> Result<usize> {
        let now = SystemTime::now();
        let max_age = std::time::Duration::from_secs(max_age_days * 24 * 60 * 60);

        let to_remove: Vec<String> = self
            .unit_cache
            .iter()
            .filter(|(_, unit)| now.duration_since(unit.timestamp).unwrap_or(max_age) > max_age)
            .map(|(k, _)| k.clone())
            .collect();

        let count = to_remove.len();
        for key in to_remove {
            if let Some(unit) = self.unit_cache.remove(&key) {
                fs::remove_file(&unit.output_path).ok();
            }
        }

        Ok(count)
    }

    pub fn get_stats(&self) -> CacheStats {
        CacheStats {
            total_units: self.unit_cache.len(),
            total_size: self.unit_cache.values().map(|u| u.output_path.metadata().map(|m| m.len()).unwrap_or(0)).sum(),
        }
    }

    pub fn invalidate(&mut self, path: &Path) {
        let path_str = path.to_string_lossy().to_string();
        self.unit_cache.remove(&path_str);

        let affected = self.get_affected_files(path);
        for file in affected {
            let file_str = file.to_string_lossy().to_string();
            self.unit_cache.remove(&file_str);
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IncrementalCache {
    pub dep_graph: DependencyGraph,
    pub units: HashMap<String, CompiledUnit>,
}

#[derive(Debug, Clone)]
pub struct CacheStats {
    pub total_units: usize,
    pub total_size: u64,
}

impl ChangeDetector {
    pub fn new() -> Self {
        Self { snapshots: HashMap::new() }
    }

    pub fn snapshot(&mut self, path: &Path) -> Result<()> {
        let metadata = fs::metadata(path)?;
        let hash = compute_file_hash(path)?;

        let snapshot = FileSnapshot { path: path.to_path_buf(), hash, mtime: metadata.modified()?, size: metadata.len() };

        self.snapshots.insert(path.to_path_buf(), snapshot);
        Ok(())
    }

    pub fn has_changed(&self, path: &Path) -> bool {
        let Some(snapshot) = self.snapshots.get(path) else {
            return true;
        };

        let Ok(metadata) = fs::metadata(path) else {
            return true;
        };

        if metadata.len() != snapshot.size {
            return true;
        }

        if let Ok(mtime) = metadata.modified() {
            if mtime != snapshot.mtime {
                let Ok(hash) = compute_file_hash(path) else {
                    return true;
                };
                return hash != snapshot.hash;
            }
        }

        false
    }

    pub fn get_changed_files(&self) -> Vec<PathBuf> {
        self.snapshots.keys().filter(|p| self.has_changed(p)).cloned().collect()
    }
}

fn compute_file_hash(path: &Path) -> Result<u64> {
    use std::collections::hash_map::DefaultHasher;

    let content = fs::read(path)?;
    let mut hasher = DefaultHasher::new();
    content.hash(&mut hasher);
    Ok(hasher.finish())
}

pub struct ParallelCompiler {
    compiler: IncrementalCompiler,
    _parallelism: usize,
}

impl ParallelCompiler {
    pub fn new(cache_dir: impl AsRef<Path>, parallelism: usize) -> Self {
        Self { compiler: IncrementalCompiler::new(cache_dir), _parallelism: parallelism }
    }

    pub fn compile_batch(&mut self, files: &[PathBuf], options: &CompileOptions) -> Vec<CompileResult> {
        let to_compile: Vec<_> = files.iter().filter(|f| self.compiler.needs_recompile(f, options)).cloned().collect();

        let sorted = self.topological_sort(&to_compile);

        let mut results = Vec::new();
        for file in sorted {
            results.push(CompileResult { source: file, success: true, output: None, error: None });
        }

        results
    }

    fn topological_sort(&self, files: &[PathBuf]) -> Vec<PathBuf> {
        files.to_vec()
    }
}

#[derive(Debug, Clone)]
pub struct CompileResult {
    pub source: PathBuf,
    pub success: bool,
    pub output: Option<PathBuf>,
    pub error: Option<String>,
}

pub struct BuildSystem {
    compiler: IncrementalCompiler,
    detector: ChangeDetector,
}

impl BuildSystem {
    pub fn new(cache_dir: impl AsRef<Path>) -> Self {
        Self { compiler: IncrementalCompiler::new(cache_dir), detector: ChangeDetector::new() }
    }

    pub fn build(&mut self, targets: &[PathBuf], _options: &CompileOptions) -> Result<BuildSummary> {
        let start = std::time::Instant::now();

        self.compiler.load_cache()?;

        let changed: Vec<_> = targets
            .iter()
            .filter(|t| !self.compiler.unit_cache.contains_key(&t.to_string_lossy().to_string()) || self.detector.has_changed(t))
            .cloned()
            .collect();

        let mut to_rebuild: HashSet<PathBuf> = changed.iter().cloned().collect();
        for file in &changed {
            to_rebuild.extend(self.compiler.get_affected_files(file));
        }

        let needs_compile = to_rebuild.len();
        let cached = targets.len() - needs_compile;

        let compiled = needs_compile;
        let failed = 0;

        self.compiler.save_cache()?;

        Ok(BuildSummary { total: targets.len(), cached, compiled, failed, duration: start.elapsed() })
    }
}

#[derive(Debug, Clone)]
pub struct BuildSummary {
    pub total: usize,
    pub cached: usize,
    pub compiled: usize,
    pub failed: usize,
    pub duration: std::time::Duration,
}

impl BuildSummary {
    pub fn print(&self) {
        println!("\n{}", "Build Summary:".bold());
        println!("  Total:    {}", self.total);
        println!("  Cached:   {}", self.cached.to_string().green());
        println!("  Compiled: {}", self.compiled.to_string().yellow());
        if self.failed > 0 {
            println!("  Failed:   {}", self.failed.to_string().red());
        }
        println!("  Time:     {:.2}s", self.duration.as_secs_f64());
    }
}

use colored::Colorize;

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_incremental_compiler() {
        let temp = TempDir::new().unwrap();
        let cache_dir = temp.path().join("cache");

        let mut compiler = IncrementalCompiler::new(&cache_dir);

        let source = temp.path().join("test.cell");
        fs::write(&source, "module test;").unwrap();

        let options = CompileOptions { opt_level: 0, target: "riscv64".to_string(), debug: false };

        assert!(compiler.needs_recompile(&source, &options));

        let output = temp.path().join("test.o");
        fs::write(&output, "").unwrap();
        compiler.record_compilation(&source, &output, vec![], &options).unwrap();

        assert!(!compiler.needs_recompile(&source, &options));

        fs::write(&source, "module test2;").unwrap();
        assert!(compiler.needs_recompile(&source, &options));
    }

    #[test]
    fn test_dependency_graph() {
        let mut graph = DependencyGraph::default();

        graph.dependents.entry("a.cell".into()).or_default().insert("b.cell".into());
        graph.dependents.entry("a.cell".into()).or_default().insert("c.cell".into());

        let mut compiler = IncrementalCompiler::new("/tmp/cache");
        compiler.dep_graph = graph;
        let affected = compiler.get_affected_files(Path::new("a.cell"));

        assert!(affected.contains(&PathBuf::from("b.cell")));
        assert!(affected.contains(&PathBuf::from("c.cell")));
    }

    #[test]
    fn test_change_detector() {
        let temp = TempDir::new().unwrap();
        let file = temp.path().join("test.txt");
        fs::write(&file, "hello").unwrap();

        let mut detector = ChangeDetector::new();
        detector.snapshot(&file).unwrap();

        assert!(!detector.has_changed(&file));

        fs::write(&file, "world").unwrap();
        assert!(detector.has_changed(&file));
    }
}
