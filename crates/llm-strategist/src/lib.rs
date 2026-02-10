use program_analyzer::VulnerabilityFinding;
use serde::{Deserialize, Serialize};

pub struct LlmStrategist {
    api_key: String,
    model: String,
    client: reqwest::Client,
}

impl LlmStrategist {
    pub fn new(api_key: String, model: String) -> Self {
        Self {
            api_key,
            model,
            client: reqwest::Client::new(),
        }
    }

    /// Get the API key
    pub fn api_key(&self) -> &str {
        &self.api_key
    }

    /// Get the model name
    pub fn model(&self) -> &str {
        &self.model
    }

    /// Generate exploit strategy using LLM via OpenRouter + vulnerability training prompt
    pub async fn generate_exploit_strategy(
        &self,
        vulnerability: &VulnerabilityFinding,
        instruction_code: &str,
    ) -> Result<ExploitStrategy, StrategistError> {
        let prompt = self.build_exploit_prompt(vulnerability, instruction_code);

        let response = self.call_llm(&prompt).await?;

        self.parse_strategy_response(&response)
    }

    fn build_exploit_prompt(&self, vulnerability: &VulnerabilityFinding, code: &str) -> String {
        format!(
            r#"
You are a security researcher analyzing a Solana smart contract vulnerability.

VULNERABILITY DETECTED:
Type: {}
Severity: {}/5
Location: {}
Description: {}

INSTRUCTION SOURCE CODE:
```rust
{}
```

Your task: Generate a CONCRETE exploit strategy.

Provide:
1. attack_vector: Exactly what input/action triggers the vulnerability
2. payload: Concrete values to send (use actual numbers like 18446744073709551615 for u64::MAX)
3. expected_outcome: What happens when exploit succeeds (error code or state change)
4. explanation: 2-sentence technical explanation

Format as JSON:
{{
    "attack_vector": "...",
    "payload": {{
        "amount": 18446744073709551615,
        "recipient": "PUBKEY_STRING"
    }},
    "expected_outcome": "Program error 0x1770 (Arithmetic overflow)",
    "explanation": "..."
}}
NOTE: ensure payload keys match instruction argument names exactly.
"#,
            vulnerability.vuln_type,
            vulnerability.severity,
            vulnerability.location,
            vulnerability.description,
            code
        )
    }

    async fn call_llm(&self, prompt: &str) -> Result<String, StrategistError> {
        // Detect API type based on key prefix
        let is_nvidia = self.api_key.starts_with("nvapi-");
        let is_openai = !is_nvidia
            && (self.api_key.starts_with("sk-proj-")
                || (self.api_key.starts_with("sk-") && !self.api_key.starts_with("sk-or-")));

        // Specific configuration for NVIDIA models
        let (max_tokens, reasoning_budget, chat_template_kwargs) = if is_nvidia {
            // Moonshot AI Kimi K2.5 via NVIDIA API
            if self.model.contains("kimi") || self.model.contains("moonshot") {
                (
                    Some(16384), // Kimi K2.5 supports up to 16K tokens
                    None,
                    Some(serde_json::json!({"thinking": true})), // Enable thinking mode for Kimi
                )
            }
            // NVIDIA Nemotron models
            else if self.model.contains("nemotron") {
                (
                    Some(16384),
                    Some(16384),
                    Some(serde_json::json!({"enable_thinking": true})),
                )
            }
            // Default NVIDIA configuration
            else {
                (Some(4096), None, None)
            }
        } else {
            (Some(2048), None, None)
        };

        let request = OpenRouterRequest {
            model: self.model.clone(),
            messages: vec![OpenRouterMessage {
                role: "user".to_string(),
                content: prompt.to_string(),
            }],
            temperature: if is_openai { None } else { Some(1.0) },
            max_tokens,
            reasoning_budget,
            chat_template_kwargs,
        };

        let api_url = if is_nvidia {
            "https://integrate.api.nvidia.com/v1/chat/completions"
        } else if is_openai {
            "https://api.openai.com/v1/chat/completions"
        } else {
            "https://openrouter.ai/api/v1/chat/completions"
        };

        let mut req_builder = self
            .client
            .post(api_url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json");

        if !is_openai && !is_nvidia {
            req_builder = req_builder
                .header("HTTP-Referer", "https://solana-security-swarm.ai")
                .header("X-Title", "Solana Security Swarm");
        }

        let response = req_builder
            .json(&request)
            .send()
            .await
            .map_err(|e| StrategistError::Http(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            return Err(StrategistError::Api(format!(
                "LLM API error ({}): {}",
                status, error_text
            )));
        }

        let or_response: OpenRouterResponse = response
            .json()
            .await
            .map_err(|e| StrategistError::Http(e.to_string()))?;

        if or_response.choices.is_empty() {
            return Err(StrategistError::Api("Empty response from LLM".to_string()));
        }

        Ok(or_response.choices[0].message.content.clone())
    }

    fn parse_strategy_response(&self, response: &str) -> Result<ExploitStrategy, StrategistError> {
        // Extract JSON from response (may be wrapped in markdown)
        let json_str = if response.contains("```json") {
            response
                .split("```json")
                .nth(1)
                .and_then(|s| s.split("```").next())
                .unwrap_or(response)
        } else {
            response
        };

        let strategy: ExploitStrategy = serde_json::from_str(json_str.trim())?;

        Ok(strategy)
    }

    pub async fn infer_system_invariants(
        &self,
        program_code: &str,
    ) -> Result<Vec<LogicInvariant>, StrategistError> {
        let prompt = format!(
            r#"
You are a formal methods engineer specialized in Solana security.
Analyze the following Anchor program code and identify CRITICAL logical invariants that must hold for the system to remain secure and solvent.

CODE:
```rust
{}
```

Identify invariants concerning:
1. Total Supply vs. Reserved Liquidity
2. User Balance consistency
3. Authorization mapping (e.g. only owner can withdraw)
4. State transition rules

Provide findings as a JSON array of objects:
{{
    "name": "short_name",
    "description": "what this invariant ensures",
    "formal_property": "Z3-like logical expression (e.g. user_balance <= total_vault_balance)",
    "failure_impact": "what happens if violated"
}}

Output ONLY the JSON array.
"#,
            program_code
        );

        let response = self.call_llm(&prompt).await?;

        let invariants: Vec<LogicInvariant> = if response.contains("[") {
            let json_str = response
                .split("[")
                .nth(1)
                .and_then(|s| s.rsplit("]").nth(0))
                .map(|s| format!("[{}]", s))
                .unwrap_or(response.clone());
            serde_json::from_str(&json_str)?
        } else {
            Vec::new()
        };

        Ok(invariants)
    }

    /// Enhance a finding with AI-generated insights - REAL IMPLEMENTATION
    pub async fn enhance_finding(
        &self,
        description: &str,
        attack_scenario: &str,
    ) -> Result<EnhancedFinding, StrategistError> {
        self.enhance_finding_with_context(description, attack_scenario, None, None)
            .await
    }

    /// Enhance a finding with full context
    pub async fn enhance_finding_with_context(
        &self,
        description: &str,
        attack_scenario: &str,
        code_snippet: Option<&str>,
        related_functions: Option<&str>,
    ) -> Result<EnhancedFinding, StrategistError> {
        let prompt = format!(
            r#"
You are a Solana security expert analyzing a vulnerability finding.

VULNERABILITY DETAILS:
Description: {}
Attack Scenario: {}

{}{}

TASK: Provide a comprehensive security analysis in JSON format:
{{
    "explanation": "Detailed technical explanation of why this is vulnerable (3-5 sentences)",
    "vulnerability_type": "The specific vulnerability category (e.g., Missing Signer Check, Integer Overflow, etc.)",
    "attack_vector": "Step-by-step attack execution path",
    "economic_impact": "Estimated impact in terms of funds at risk (LOW/MEDIUM/HIGH/CRITICAL)",
    "exploit_difficulty": "trivial|easy|medium|hard",
    "poc_code": "Minimal TypeScript/Rust proof-of-concept code (10-20 lines)",
    "fix_code": "Secure implementation that fixes the vulnerability (10-20 lines)",
    "fix_explanation": "Clear explanation of what the fix does and why it works",
    "related_exploits": ["List of similar real-world Solana exploits if applicable"],
    "detection_evasion": "How attackers might try to hide this exploitation",
    "monitoring_recommendation": "What to monitor to detect exploitation attempts"
}}

Be specific and technical. Include actual code examples. Reference real Solana exploits where applicable.
Focus on Solana-specific attack patterns like CPI manipulation, PDA hijacking, and token authority issues.
"#,
            description,
            attack_scenario,
            code_snippet
                .map(|c| format!("CODE SNIPPET:\n```rust\n{}\n```\n", c))
                .unwrap_or_default(),
            related_functions
                .map(|f| format!("RELATED FUNCTIONS:\n{}\n", f))
                .unwrap_or_default(),
        );

        let response = self.call_llm(&prompt).await?;

        // Parse the JSON response
        let enhanced = self.parse_enhanced_finding(&response, description, attack_scenario)?;

        Ok(enhanced)
    }

    /// Parse enhanced finding from LLM response with fallback
    fn parse_enhanced_finding(
        &self,
        response: &str,
        original_description: &str,
        original_attack: &str,
    ) -> Result<EnhancedFinding, StrategistError> {
        // Try to extract JSON from response
        let json_str = if response.contains("{") {
            let start = response.find('{').unwrap_or(0);
            let end = response.rfind('}').map(|i| i + 1).unwrap_or(response.len());
            &response[start..end]
        } else {
            response
        };

        // Try to parse as structured JSON
        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(json_str) {
            Ok(EnhancedFinding {
                explanation: parsed
                    .get("explanation")
                    .and_then(|v| v.as_str())
                    .unwrap_or("AI analysis not available")
                    .to_string(),
                vulnerability_type: parsed
                    .get("vulnerability_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown")
                    .to_string(),
                description: original_description.to_string(),
                attack_scenario: parsed
                    .get("attack_vector")
                    .and_then(|v| v.as_str())
                    .unwrap_or(original_attack)
                    .to_string(),
                fix_suggestion: parsed
                    .get("fix_explanation")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Review and fix the identified issue.")
                    .to_string(),
                economic_impact: parsed
                    .get("economic_impact")
                    .and_then(|v| v.as_str())
                    .unwrap_or("UNKNOWN")
                    .to_string(),
                exploit_difficulty: parsed
                    .get("exploit_difficulty")
                    .and_then(|v| v.as_str())
                    .unwrap_or("medium")
                    .to_string(),
                poc_code: parsed
                    .get("poc_code")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                fix_code: parsed
                    .get("fix_code")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                related_exploits: parsed
                    .get("related_exploits")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default(),
                monitoring_recommendation: parsed
                    .get("monitoring_recommendation")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
            })
        } else {
            // Fallback: use raw response as explanation
            Ok(EnhancedFinding {
                explanation: if response.len() > 50 {
                    response.to_string()
                } else {
                    format!("AI analysis of: {}", original_description)
                },
                vulnerability_type: "Unknown".to_string(),
                description: original_description.to_string(),
                attack_scenario: original_attack.to_string(),
                fix_suggestion: "Review and fix the identified issue.".to_string(),
                economic_impact: "UNKNOWN".to_string(),
                exploit_difficulty: "medium".to_string(),
                poc_code: None,
                fix_code: None,
                related_exploits: vec![],
                monitoring_recommendation: None,
            })
        }
    }
}

/// Enhanced vulnerability finding with AI-generated insights
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedFinding {
    /// Detailed technical explanation of the vulnerability
    pub explanation: String,
    /// Category of vulnerability (e.g., "Missing Signer Check")
    pub vulnerability_type: String,
    /// Original description
    pub description: String,
    /// Step-by-step attack scenario
    pub attack_scenario: String,
    /// How to fix the vulnerability
    pub fix_suggestion: String,
    /// Economic impact assessment (LOW/MEDIUM/HIGH/CRITICAL)
    pub economic_impact: String,
    /// How difficult to exploit (trivial/easy/medium/hard)
    pub exploit_difficulty: String,
    /// Proof-of-concept code
    pub poc_code: Option<String>,
    /// Secure code fix
    pub fix_code: Option<String>,
    /// Similar real-world exploits
    pub related_exploits: Vec<String>,
    /// What to monitor for exploitation attempts
    pub monitoring_recommendation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogicInvariant {
    pub name: String,
    pub description: String,
    pub formal_property: String,
    pub failure_impact: String,
}

#[derive(Debug, Serialize)]
struct OpenRouterRequest {
    model: String,
    messages: Vec<OpenRouterMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reasoning_budget: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    chat_template_kwargs: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct OpenRouterMessage {
    role: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct OpenRouterResponse {
    choices: Vec<OpenRouterChoice>,
}

#[derive(Debug, Deserialize)]
struct OpenRouterChoice {
    message: OpenRouterChoiceMessage,
}

#[derive(Debug, Deserialize)]
struct OpenRouterChoiceMessage {
    content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExploitStrategy {
    pub attack_vector: String,
    pub payload: serde_json::Value,
    pub expected_outcome: String,
    pub explanation: String,
}

#[derive(Debug, thiserror::Error)]
pub enum StrategistError {
    #[error("HTTP error: {0}")]
    Http(String),
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("API error: {0}")]
    Api(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_strategist() -> LlmStrategist {
        LlmStrategist::new("test-key".to_string(), "test-model".to_string())
    }

    #[test]
    fn test_strategist_creation() {
        let s = make_strategist();
        assert_eq!(s.api_key(), "test-key");
        assert_eq!(s.model(), "test-model");
    }

    #[test]
    fn test_parse_strategy_response_valid_json() {
        let s = make_strategist();
        let response = r#"{
            "attack_vector": "Send u64::MAX as amount",
            "payload": {"amount": 18446744073709551615},
            "expected_outcome": "Overflow error",
            "explanation": "Causes arithmetic overflow."
        }"#;
        let result = s.parse_strategy_response(response);
        assert!(result.is_ok());
        let strategy = result.unwrap();
        assert_eq!(strategy.attack_vector, "Send u64::MAX as amount");
        assert_eq!(strategy.expected_outcome, "Overflow error");
    }

    #[test]
    fn test_parse_strategy_response_markdown_wrapped() {
        let s = make_strategist();
        let response = "Here is the strategy:\n```json\n{\"attack_vector\": \"test\", \"payload\": {}, \"expected_outcome\": \"err\", \"explanation\": \"x\"}\n```";
        let result = s.parse_strategy_response(response);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().attack_vector, "test");
    }

    #[test]
    fn test_parse_strategy_response_invalid() {
        let s = make_strategist();
        let result = s.parse_strategy_response("not json at all");
        assert!(result.is_err());
    }

    #[test]
    fn test_exploit_strategy_default() {
        let strategy = ExploitStrategy::default();
        assert!(strategy.attack_vector.is_empty());
        assert!(strategy.explanation.is_empty());
    }

    #[test]
    fn test_exploit_strategy_serialization() {
        let strategy = ExploitStrategy {
            attack_vector: "overflow".to_string(),
            payload: serde_json::json!({"amount": 100}),
            expected_outcome: "error".to_string(),
            explanation: "test".to_string(),
        };
        let json = serde_json::to_string(&strategy).unwrap();
        let deserialized: ExploitStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.attack_vector, "overflow");
    }

    #[test]
    fn test_logic_invariant_serialization() {
        let invariant = LogicInvariant {
            name: "balance_conservation".to_string(),
            description: "Total supply must equal sum of balances".to_string(),
            formal_property: "total_supply == sum(balances)".to_string(),
            failure_impact: "Token inflation".to_string(),
        };
        let json = serde_json::to_string(&invariant).unwrap();
        let deserialized: LogicInvariant = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.name, "balance_conservation");
    }

    #[test]
    fn test_enhanced_finding_serialization() {
        let finding = EnhancedFinding {
            explanation: "test explanation".to_string(),
            vulnerability_type: "Missing Signer".to_string(),
            description: "desc".to_string(),
            attack_scenario: "scenario".to_string(),
            fix_suggestion: "fix".to_string(),
            economic_impact: "HIGH".to_string(),
            exploit_difficulty: "easy".to_string(),
            poc_code: Some("let x = 1;".to_string()),
            fix_code: None,
            related_exploits: vec!["Wormhole".to_string()],
            monitoring_recommendation: None,
        };
        let json = serde_json::to_string(&finding).unwrap();
        assert!(json.contains("Missing Signer"));
        assert!(json.contains("Wormhole"));
    }

    #[test]
    fn test_build_exploit_prompt() {
        let s = make_strategist();
        let vuln = program_analyzer::VulnerabilityFinding {
            id: "2.1".to_string(),
            category: "Arithmetic".to_string(),
            vuln_type: "Integer Overflow".to_string(),
            severity: 4,
            severity_label: "High".to_string(),
            cwe: Some("CWE-190".to_string()),
            location: "line 42".to_string(),
            function_name: "deposit".to_string(),
            line_number: 42,
            vulnerable_code: "amount + fee".to_string(),
            description: "Unchecked arithmetic".to_string(),
            attack_scenario: "Send max u64 value".to_string(),
            real_world_incident: None,
            secure_fix: "Use checked_add".to_string(),
            prevention: "Always use checked math".to_string(),
        };
        let prompt = s.build_exploit_prompt(&vuln, "pub fn deposit() {}");
        assert!(prompt.contains("Integer Overflow"));
        assert!(prompt.contains("pub fn deposit"));
        assert!(prompt.contains("attack_vector"));
    }
}
