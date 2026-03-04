/// Configuration for creating a new identifier via inception.
#[derive(Debug, Clone)]
pub struct InceptionConfig {
    /// Signing algorithm code, default "A" (Ed25519).
    pub code: String,
    /// Number of signing keys, default 1.
    pub count: usize,
    /// Signing threshold, default 1.
    pub threshold: usize,
    /// Number of next keys, default 1.
    pub next_count: usize,
    /// Next signing threshold, default 1.
    pub next_threshold: usize,
    /// Whether the identifier is transferable, default true.
    pub transferable: bool,
    /// Witness threshold, default 0.
    pub backer_threshold: usize,
    /// Witness prefixes, default empty.
    pub backers: Vec<String>,
    /// Configuration traits, default empty.
    pub config_traits: Vec<String>,
    /// Optional salt for key derivation; uses random if None.
    pub salt: Option<Vec<u8>>,
}

impl Default for InceptionConfig {
    fn default() -> Self {
        Self {
            code: "A".to_string(),
            count: 1,
            threshold: 1,
            next_count: 1,
            next_threshold: 1,
            transferable: true,
            backer_threshold: 0,
            backers: Vec::new(),
            config_traits: Vec::new(),
            salt: None,
        }
    }
}

impl InceptionConfig {
    /// Start building an `InceptionConfig` with defaults.
    pub fn builder() -> InceptionConfigBuilder {
        InceptionConfigBuilder {
            config: InceptionConfig::default(),
        }
    }
}

/// Builder for `InceptionConfig`.
pub struct InceptionConfigBuilder {
    config: InceptionConfig,
}

impl InceptionConfigBuilder {
    /// Set the signing algorithm code (e.g. "A" for Ed25519).
    pub fn code(mut self, code: &str) -> Self {
        self.config.code = code.to_string();
        self
    }

    /// Set the number of signing keys.
    pub fn count(mut self, count: usize) -> Self {
        self.config.count = count;
        self
    }

    /// Set the signing threshold.
    pub fn threshold(mut self, threshold: usize) -> Self {
        self.config.threshold = threshold;
        self
    }

    /// Set the number of next keys.
    pub fn next_count(mut self, next_count: usize) -> Self {
        self.config.next_count = next_count;
        self
    }

    /// Set the next signing threshold.
    pub fn next_threshold(mut self, next_threshold: usize) -> Self {
        self.config.next_threshold = next_threshold;
        self
    }

    /// Set whether the identifier is transferable.
    pub fn transferable(mut self, transferable: bool) -> Self {
        self.config.transferable = transferable;
        self
    }

    /// Set the witness threshold.
    pub fn backer_threshold(mut self, backer_threshold: usize) -> Self {
        self.config.backer_threshold = backer_threshold;
        self
    }

    /// Set the witness prefixes.
    pub fn backers(mut self, backers: Vec<String>) -> Self {
        self.config.backers = backers;
        self
    }

    /// Set the configuration traits.
    pub fn config_traits(mut self, config_traits: Vec<String>) -> Self {
        self.config.config_traits = config_traits;
        self
    }

    /// Set the salt for key derivation.
    pub fn salt(mut self, salt: Vec<u8>) -> Self {
        self.config.salt = Some(salt);
        self
    }

    /// Build the `InceptionConfig`.
    pub fn build(self) -> InceptionConfig {
        self.config
    }
}

/// Configuration for rotation.
#[derive(Debug, Clone)]
pub struct RotationConfig {
    /// Number of new signing keys.
    pub count: usize,
    /// New signing threshold.
    pub threshold: usize,
    /// Number of next keys.
    pub next_count: usize,
    /// Next signing threshold.
    pub next_threshold: usize,
    /// Backers (witnesses) to add.
    pub backers_add: Vec<String>,
    /// Backers (witnesses) to remove.
    pub backers_remove: Vec<String>,
}

impl Default for RotationConfig {
    fn default() -> Self {
        Self {
            count: 1,
            threshold: 1,
            next_count: 1,
            next_threshold: 1,
            backers_add: Vec::new(),
            backers_remove: Vec::new(),
        }
    }
}
