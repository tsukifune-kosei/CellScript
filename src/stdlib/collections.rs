use crate::ir::IrType;

pub struct Collections;

impl Collections {
    pub fn functions() -> Vec<CollectionFunction> {
        vec![
            CollectionFunction { name: "vec_new".to_string(), params: vec![], return_type: Some(IrType::Named("Vec".to_string())) },
            CollectionFunction {
                name: "vec_with_capacity".to_string(),
                params: vec![("capacity".to_string(), IrType::U64)],
                return_type: Some(IrType::Named("Vec".to_string())),
            },
            CollectionFunction {
                name: "vec_push".to_string(),
                params: vec![
                    ("vec".to_string(), IrType::MutRef(Box::new(IrType::Named("Vec".to_string())))),
                    ("value".to_string(), IrType::U64),
                ],
                return_type: None,
            },
            CollectionFunction {
                name: "vec_pop".to_string(),
                params: vec![("vec".to_string(), IrType::MutRef(Box::new(IrType::Named("Vec".to_string()))))],
                return_type: Some(IrType::Named("Option".to_string())),
            },
            CollectionFunction {
                name: "vec_get".to_string(),
                params: vec![
                    ("vec".to_string(), IrType::Ref(Box::new(IrType::Named("Vec".to_string())))),
                    ("index".to_string(), IrType::U64),
                ],
                return_type: Some(IrType::Named("Option".to_string())),
            },
            CollectionFunction {
                name: "vec_len".to_string(),
                params: vec![("vec".to_string(), IrType::Ref(Box::new(IrType::Named("Vec".to_string()))))],
                return_type: Some(IrType::U64),
            },
            CollectionFunction {
                name: "vec_is_empty".to_string(),
                params: vec![("vec".to_string(), IrType::Ref(Box::new(IrType::Named("Vec".to_string()))))],
                return_type: Some(IrType::Bool),
            },
            CollectionFunction {
                name: "vec_clear".to_string(),
                params: vec![("vec".to_string(), IrType::MutRef(Box::new(IrType::Named("Vec".to_string()))))],
                return_type: None,
            },
            CollectionFunction {
                name: "vec_contains".to_string(),
                params: vec![
                    ("vec".to_string(), IrType::Ref(Box::new(IrType::Named("Vec".to_string())))),
                    ("value".to_string(), IrType::U64),
                ],
                return_type: Some(IrType::Bool),
            },
            CollectionFunction {
                name: "vec_remove".to_string(),
                params: vec![
                    ("vec".to_string(), IrType::MutRef(Box::new(IrType::Named("Vec".to_string())))),
                    ("index".to_string(), IrType::U64),
                ],
                return_type: Some(IrType::U64),
            },
            CollectionFunction {
                name: "vec_insert".to_string(),
                params: vec![
                    ("vec".to_string(), IrType::MutRef(Box::new(IrType::Named("Vec".to_string())))),
                    ("index".to_string(), IrType::U64),
                    ("value".to_string(), IrType::U64),
                ],
                return_type: None,
            },
            CollectionFunction {
                name: "vec_sort".to_string(),
                params: vec![("vec".to_string(), IrType::MutRef(Box::new(IrType::Named("Vec".to_string()))))],
                return_type: None,
            },
            CollectionFunction {
                name: "vec_reverse".to_string(),
                params: vec![("vec".to_string(), IrType::MutRef(Box::new(IrType::Named("Vec".to_string()))))],
                return_type: None,
            },
            CollectionFunction {
                name: "hashmap_new".to_string(),
                params: vec![],
                return_type: Some(IrType::Named("HashMap".to_string())),
            },
            CollectionFunction {
                name: "hashmap_with_capacity".to_string(),
                params: vec![("capacity".to_string(), IrType::U64)],
                return_type: Some(IrType::Named("HashMap".to_string())),
            },
            CollectionFunction {
                name: "hashmap_insert".to_string(),
                params: vec![
                    ("map".to_string(), IrType::MutRef(Box::new(IrType::Named("HashMap".to_string())))),
                    ("key".to_string(), IrType::U64),
                    ("value".to_string(), IrType::U64),
                ],
                return_type: Some(IrType::Named("Option".to_string())),
            },
            CollectionFunction {
                name: "hashmap_get".to_string(),
                params: vec![
                    ("map".to_string(), IrType::Ref(Box::new(IrType::Named("HashMap".to_string())))),
                    ("key".to_string(), IrType::U64),
                ],
                return_type: Some(IrType::Named("Option".to_string())),
            },
            CollectionFunction {
                name: "hashmap_remove".to_string(),
                params: vec![
                    ("map".to_string(), IrType::MutRef(Box::new(IrType::Named("HashMap".to_string())))),
                    ("key".to_string(), IrType::U64),
                ],
                return_type: Some(IrType::Named("Option".to_string())),
            },
            CollectionFunction {
                name: "hashmap_contains_key".to_string(),
                params: vec![
                    ("map".to_string(), IrType::Ref(Box::new(IrType::Named("HashMap".to_string())))),
                    ("key".to_string(), IrType::U64),
                ],
                return_type: Some(IrType::Bool),
            },
            CollectionFunction {
                name: "hashmap_len".to_string(),
                params: vec![("map".to_string(), IrType::Ref(Box::new(IrType::Named("HashMap".to_string()))))],
                return_type: Some(IrType::U64),
            },
            CollectionFunction {
                name: "hashmap_is_empty".to_string(),
                params: vec![("map".to_string(), IrType::Ref(Box::new(IrType::Named("HashMap".to_string()))))],
                return_type: Some(IrType::Bool),
            },
            CollectionFunction {
                name: "hashmap_clear".to_string(),
                params: vec![("map".to_string(), IrType::MutRef(Box::new(IrType::Named("HashMap".to_string()))))],
                return_type: None,
            },
            CollectionFunction {
                name: "hashmap_keys".to_string(),
                params: vec![("map".to_string(), IrType::Ref(Box::new(IrType::Named("HashMap".to_string()))))],
                return_type: Some(IrType::Named("Vec".to_string())),
            },
            CollectionFunction {
                name: "hashmap_values".to_string(),
                params: vec![("map".to_string(), IrType::Ref(Box::new(IrType::Named("HashMap".to_string()))))],
                return_type: Some(IrType::Named("Vec".to_string())),
            },
            CollectionFunction {
                name: "hashset_new".to_string(),
                params: vec![],
                return_type: Some(IrType::Named("HashSet".to_string())),
            },
            CollectionFunction {
                name: "hashset_with_capacity".to_string(),
                params: vec![("capacity".to_string(), IrType::U64)],
                return_type: Some(IrType::Named("HashSet".to_string())),
            },
            CollectionFunction {
                name: "hashset_insert".to_string(),
                params: vec![
                    ("set".to_string(), IrType::MutRef(Box::new(IrType::Named("HashSet".to_string())))),
                    ("value".to_string(), IrType::U64),
                ],
                return_type: Some(IrType::Bool),
            },
            CollectionFunction {
                name: "hashset_remove".to_string(),
                params: vec![
                    ("set".to_string(), IrType::MutRef(Box::new(IrType::Named("HashSet".to_string())))),
                    ("value".to_string(), IrType::U64),
                ],
                return_type: Some(IrType::Bool),
            },
            CollectionFunction {
                name: "hashset_contains".to_string(),
                params: vec![
                    ("set".to_string(), IrType::Ref(Box::new(IrType::Named("HashSet".to_string())))),
                    ("value".to_string(), IrType::U64),
                ],
                return_type: Some(IrType::Bool),
            },
            CollectionFunction {
                name: "hashset_len".to_string(),
                params: vec![("set".to_string(), IrType::Ref(Box::new(IrType::Named("HashSet".to_string()))))],
                return_type: Some(IrType::U64),
            },
            CollectionFunction {
                name: "hashset_is_empty".to_string(),
                params: vec![("set".to_string(), IrType::Ref(Box::new(IrType::Named("HashSet".to_string()))))],
                return_type: Some(IrType::Bool),
            },
            CollectionFunction {
                name: "hashset_clear".to_string(),
                params: vec![("set".to_string(), IrType::MutRef(Box::new(IrType::Named("HashSet".to_string()))))],
                return_type: None,
            },
            CollectionFunction {
                name: "hashset_union".to_string(),
                params: vec![
                    ("a".to_string(), IrType::Ref(Box::new(IrType::Named("HashSet".to_string())))),
                    ("b".to_string(), IrType::Ref(Box::new(IrType::Named("HashSet".to_string())))),
                ],
                return_type: Some(IrType::Named("HashSet".to_string())),
            },
            CollectionFunction {
                name: "hashset_intersection".to_string(),
                params: vec![
                    ("a".to_string(), IrType::Ref(Box::new(IrType::Named("HashSet".to_string())))),
                    ("b".to_string(), IrType::Ref(Box::new(IrType::Named("HashSet".to_string())))),
                ],
                return_type: Some(IrType::Named("HashSet".to_string())),
            },
            CollectionFunction {
                name: "hashset_difference".to_string(),
                params: vec![
                    ("a".to_string(), IrType::Ref(Box::new(IrType::Named("HashSet".to_string())))),
                    ("b".to_string(), IrType::Ref(Box::new(IrType::Named("HashSet".to_string())))),
                ],
                return_type: Some(IrType::Named("HashSet".to_string())),
            },
            CollectionFunction {
                name: "option_some".to_string(),
                params: vec![("value".to_string(), IrType::U64)],
                return_type: Some(IrType::Named("Option".to_string())),
            },
            CollectionFunction {
                name: "option_none".to_string(),
                params: vec![],
                return_type: Some(IrType::Named("Option".to_string())),
            },
            CollectionFunction {
                name: "option_is_some".to_string(),
                params: vec![("opt".to_string(), IrType::Ref(Box::new(IrType::Named("Option".to_string()))))],
                return_type: Some(IrType::Bool),
            },
            CollectionFunction {
                name: "option_is_none".to_string(),
                params: vec![("opt".to_string(), IrType::Ref(Box::new(IrType::Named("Option".to_string()))))],
                return_type: Some(IrType::Bool),
            },
            CollectionFunction {
                name: "option_unwrap".to_string(),
                params: vec![("opt".to_string(), IrType::Named("Option".to_string()))],
                return_type: Some(IrType::U64),
            },
            CollectionFunction {
                name: "option_unwrap_or".to_string(),
                params: vec![("opt".to_string(), IrType::Named("Option".to_string())), ("default".to_string(), IrType::U64)],
                return_type: Some(IrType::U64),
            },
            CollectionFunction {
                name: "option_map".to_string(),
                params: vec![
                    ("opt".to_string(), IrType::Named("Option".to_string())),
                    ("f".to_string(), IrType::Named("Function".to_string())),
                ],
                return_type: Some(IrType::Named("Option".to_string())),
            },
            CollectionFunction {
                name: "result_ok".to_string(),
                params: vec![("value".to_string(), IrType::U64)],
                return_type: Some(IrType::Named("Result".to_string())),
            },
            CollectionFunction {
                name: "result_err".to_string(),
                params: vec![("error".to_string(), IrType::U64)],
                return_type: Some(IrType::Named("Result".to_string())),
            },
            CollectionFunction {
                name: "result_is_ok".to_string(),
                params: vec![("res".to_string(), IrType::Ref(Box::new(IrType::Named("Result".to_string()))))],
                return_type: Some(IrType::Bool),
            },
            CollectionFunction {
                name: "result_is_err".to_string(),
                params: vec![("res".to_string(), IrType::Ref(Box::new(IrType::Named("Result".to_string()))))],
                return_type: Some(IrType::Bool),
            },
            CollectionFunction {
                name: "result_unwrap".to_string(),
                params: vec![("res".to_string(), IrType::Named("Result".to_string()))],
                return_type: Some(IrType::U64),
            },
            CollectionFunction {
                name: "result_unwrap_or".to_string(),
                params: vec![("res".to_string(), IrType::Named("Result".to_string())), ("default".to_string(), IrType::U64)],
                return_type: Some(IrType::U64),
            },
        ]
    }

    pub fn generate_assembly() -> String {
        let mut asm = String::new();

        asm.push_str("# CellScript Collections Library\n\n");
        asm.push_str(".section .text\n\n");

        asm.push_str(&Self::generate_vec_impl());

        asm.push_str(&Self::generate_hashmap_impl());

        asm.push_str(&Self::generate_hashset_impl());

        asm
    }

    fn generate_vec_impl() -> String {
        let mut asm = String::new();

        asm.push_str("# Vec::new\n");
        asm.push_str(".global __vec_new\n");
        asm.push_str("__vec_new:\n");
        asm.push_str("    li a0, 24          # sizeof(Vec) = 24 bytes\n");
        asm.push_str("    li a7, 2101        # alloc syscall\n");
        asm.push_str("    ecall\n");
        asm.push_str("    sd zero, 0(a0)     # capacity = 0\n");
        asm.push_str("    sd zero, 8(a0)     # length = 0\n");
        asm.push_str("    sd zero, 16(a0)    # data = null\n");
        asm.push_str("    ret\n\n");

        asm.push_str("# Vec::push\n");
        asm.push_str(".global __vec_push\n");
        asm.push_str("__vec_push:\n");
        asm.push_str("    addi sp, sp, -32\n");
        asm.push_str("    sd ra, 24(sp)\n");
        asm.push_str("    sd s0, 16(sp)\n");
        asm.push_str("    sd s1, 8(sp)\n");
        asm.push_str("    mv s0, a0          # vec pointer\n");
        asm.push_str("    mv s1, a1          # value to push\n");
        asm.push_str("    ld t0, 0(s0)       # capacity\n");
        asm.push_str("    ld t1, 8(s0)       # length\n");
        asm.push_str("    bge t1, t0, .Lvec_push_grow\n");
        asm.push_str(".Lvec_push_insert:\n");
        asm.push_str("    ld t2, 16(s0)      # data pointer\n");
        asm.push_str("    slli t3, t1, 3     # offset = length * 8\n");
        asm.push_str("    add t2, t2, t3\n");
        asm.push_str("    sd s1, 0(t2)       # store value\n");
        asm.push_str("    addi t1, t1, 1\n");
        asm.push_str("    sd t1, 8(s0)       # length++\n");
        asm.push_str("    ld ra, 24(sp)\n");
        asm.push_str("    ld s0, 16(sp)\n");
        asm.push_str("    ld s1, 8(sp)\n");
        asm.push_str("    addi sp, sp, 32\n");
        asm.push_str("    ret\n");
        asm.push_str(".Lvec_push_grow:\n");
        asm.push_str("    # Grow capacity (simplified: double)\n");
        asm.push_str("    beqz t0, .Lvec_push_init\n");
        asm.push_str("    slli t0, t0, 1\n");
        asm.push_str("    j .Lvec_push_alloc\n");
        asm.push_str(".Lvec_push_init:\n");
        asm.push_str("    li t0, 4           # initial capacity\n");
        asm.push_str(".Lvec_push_alloc:\n");
        asm.push_str("    sd t0, 0(s0)       # update capacity\n");
        asm.push_str("    slli a0, t0, 3     # new_size = capacity * 8\n");
        asm.push_str("    li a7, 2101        # alloc\n");
        asm.push_str("    ecall\n");
        asm.push_str("    sd a0, 16(s0)      # update data pointer\n");
        asm.push_str("    j .Lvec_push_insert\n\n");

        asm.push_str("# Vec::len\n");
        asm.push_str(".global __vec_len\n");
        asm.push_str("__vec_len:\n");
        asm.push_str("    ld a0, 8(a0)       # return length\n");
        asm.push_str("    ret\n\n");

        asm.push_str("# Vec::is_empty\n");
        asm.push_str(".global __vec_is_empty\n");
        asm.push_str("__vec_is_empty:\n");
        asm.push_str("    ld t0, 8(a0)       # length\n");
        asm.push_str("    seqz a0, t0        # return length == 0\n");
        asm.push_str("    ret\n\n");

        asm
    }

    fn generate_hashmap_impl() -> String {
        let mut asm = String::new();

        asm.push_str("# HashMap::new\n");
        asm.push_str(".global __hashmap_new\n");
        asm.push_str("__hashmap_new:\n");
        asm.push_str("    li a0, 32          # sizeof(HashMap)\n");
        asm.push_str("    li a7, 2101        # alloc\n");
        asm.push_str("    ecall\n");
        asm.push_str("    li t0, 16          # default bucket count\n");
        asm.push_str("    sd t0, 0(a0)       # bucket_count\n");
        asm.push_str("    sd zero, 8(a0)     # entry_count\n");
        asm.push_str("    sd zero, 16(a0)    # buckets\n");
        asm.push_str("    sd zero, 24(a0)    # hasher state\n");
        asm.push_str("    ret\n\n");

        asm.push_str("# HashMap::insert\n");
        asm.push_str(".global __hashmap_insert\n");
        asm.push_str("__hashmap_insert:\n");
        asm.push_str("    addi sp, sp, -48\n");
        asm.push_str("    sd ra, 40(sp)\n");
        asm.push_str("    sd s0, 32(sp)\n");
        asm.push_str("    sd s1, 24(sp)\n");
        asm.push_str("    sd s2, 16(sp)\n");
        asm.push_str("    sd s3, 8(sp)\n");
        asm.push_str("    mv s0, a0          # map\n");
        asm.push_str("    mv s1, a1          # key\n");
        asm.push_str("    mv s2, a2          # value\n");
        asm.push_str("    # Compute hash (simplified: key % bucket_count)\n");
        asm.push_str("    ld t0, 0(s0)       # bucket_count\n");
        asm.push_str("    rem s3, s1, t0     # hash = key % bucket_count\n");
        asm.push_str("    # Insert entry...\n");
        asm.push_str("    ld ra, 40(sp)\n");
        asm.push_str("    ld s0, 32(sp)\n");
        asm.push_str("    ld s1, 24(sp)\n");
        asm.push_str("    ld s2, 16(sp)\n");
        asm.push_str("    ld s3, 8(sp)\n");
        asm.push_str("    addi sp, sp, 48\n");
        asm.push_str("    ret\n\n");

        asm.push_str("# HashMap::len\n");
        asm.push_str(".global __hashmap_len\n");
        asm.push_str("__hashmap_len:\n");
        asm.push_str("    ld a0, 8(a0)       # return entry_count\n");
        asm.push_str("    ret\n\n");

        asm
    }

    fn generate_hashset_impl() -> String {
        let mut asm = String::new();

        asm.push_str("# HashSet::new\n");
        asm.push_str(".global __hashset_new\n");
        asm.push_str("__hashset_new:\n");
        asm.push_str("    j __hashmap_new    # HashSet is HashMap with unit values\n\n");

        asm.push_str("# HashSet::insert\n");
        asm.push_str(".global __hashset_insert\n");
        asm.push_str("__hashset_insert:\n");
        asm.push_str("    li a2, 1           # value = 1 (unit)\n");
        asm.push_str("    j __hashmap_insert\n\n");

        asm.push_str("# HashSet::contains\n");
        asm.push_str(".global __hashset_contains\n");
        asm.push_str("__hashset_contains:\n");
        asm.push_str("    addi sp, sp, -16\n");
        asm.push_str("    sd ra, 8(sp)\n");
        asm.push_str("    call __hashmap_get\n");
        asm.push_str("    ld ra, 8(sp)\n");
        asm.push_str("    addi sp, sp, 16\n");
        asm.push_str("    # Check if result is Some\n");
        asm.push_str("    ret\n\n");

        asm
    }
}

#[derive(Debug, Clone)]
pub struct CollectionFunction {
    pub name: String,
    pub params: Vec<(String, IrType)>,
    pub return_type: Option<IrType>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collection_functions() {
        let funcs = Collections::functions();

        assert!(funcs.iter().any(|f| f.name == "vec_new"));
        assert!(funcs.iter().any(|f| f.name == "vec_push"));
        assert!(funcs.iter().any(|f| f.name == "vec_pop"));

        assert!(funcs.iter().any(|f| f.name == "hashmap_new"));
        assert!(funcs.iter().any(|f| f.name == "hashmap_insert"));
        assert!(funcs.iter().any(|f| f.name == "hashmap_get"));

        assert!(funcs.iter().any(|f| f.name == "hashset_new"));
        assert!(funcs.iter().any(|f| f.name == "hashset_insert"));
        assert!(funcs.iter().any(|f| f.name == "hashset_contains"));
    }

    #[test]
    fn test_generate_assembly() {
        let asm = Collections::generate_assembly();
        assert!(asm.contains("__vec_new"));
        assert!(asm.contains("__hashmap_new"));
        assert!(asm.contains("__hashset_new"));
    }
}
