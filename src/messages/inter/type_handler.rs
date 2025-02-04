use std::collections::HashMap;

pub struct TypeHandler {
    keys: HashMap<String, u16>,
    values: HashMap<u16, String>
}

impl TypeHandler {

    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
            values: HashMap::new()
        }
    }

    pub fn register_type(&mut self, key: &str, code: u16) {
        self.keys.insert(key.to_string(), code);
        self.values.insert(code, key.to_string());
    }

    pub fn find_type_by_key(&self, key: &str) -> Option<&u16> {
        self.keys.get(&key.to_string())
    }

    pub fn find_type_by_code(&self, code: u16) -> Option<&String> {
        self.values.get(&code)
    }
}
