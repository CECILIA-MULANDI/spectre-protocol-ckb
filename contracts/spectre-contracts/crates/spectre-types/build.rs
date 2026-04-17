use molecule_codegen::{Compiler, Language};

fn main() {
    let schema = "../../schemas/agent-record.mol";
    Compiler::new()
        .input_schema_file(schema)
        .generate_code(Language::Rust)
        .output_dir_set_default()
        .run()
        .expect("molecule codegen failed");
    println!("cargo:rerun-if-changed={schema}");
}
