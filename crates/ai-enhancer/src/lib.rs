use futures_util::stream::{self, StreamExt};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{info, warn};

/// Generic Chat Completion API request format (compatible with OpenRouter, OpenAI, and NVIDIA)
#[derive(Debug, Serialize)]
struct OpenRouterRequest {
    model: String,
    messages: Vec<ChatMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_completion_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reasoning_budget: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    chat_template_kwargs: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct ChatMessage {
    role: String,
    content: String,
}

/// OpenRouter API response format
#[derive(Debug, Deserialize)]
struct OpenRouterResponse {
    choices: Option<Vec<Choice>>,
    error: Option<OpenRouterError>,
}

#[derive(Debug, Deserialize)]
struct Choice {
    message: ResponseMessage,
}

#[derive(Debug, Deserialize)]
struct ResponseMessage {
    content: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct OpenRouterError {
    message: String,
    code: Option<i32>,
}

/// Enhanced explanation with AI-generated insights
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EnhancedExplanation {
    pub technical_explanation: String,
    pub attack_scenario: String,
    pub proof_of_concept: String,
    pub recommended_fix: String,
    pub economic_impact: String,
    pub severity_justification: String,
}

/// Input for AI enhancement - simplified vulnerability info
#[derive(Debug, Clone, Serialize)]
pub struct VulnerabilityInput {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: u8,
    pub code_snippet: String,
    pub file_path: String,
    pub line_number: usize,
}

/// Configuration for the AI enhancer
#[derive(Debug, Clone)]
pub struct AIEnhancerConfig {
    pub model: String,
    pub max_retries: u32,
    pub retry_delay_ms: u64,
    pub concurrency_limit: usize,
    pub temperature: f32,
    pub max_tokens: u32,
}

impl Default for AIEnhancerConfig {
    fn default() -> Self {
        Self {
            model: "anthropic/claude-3.5-sonnet".to_string(),
            max_retries: 3,
            retry_delay_ms: 1000,
            concurrency_limit: 1, // Reduced for rate-limited models like gpt-5-nano
            temperature: 0.3,

            max_tokens: 1000,
        }
    }
}

/// Production-grade AI enhancer using OpenRouter
pub struct AIEnhancer {
    api_key: String,
    config: AIEnhancerConfig,
    client: reqwest::Client,
}

impl AIEnhancer {
    /// Create a new AI enhancer with specified API key and model
    pub fn new(api_key: String, model: String) -> Self {
        let config = AIEnhancerConfig {
            model,
            ..Default::default()
        };
        Self::with_config(api_key, config)
    }

    /// Create a new AI enhancer with full configuration
    pub fn with_config(api_key: String, config: AIEnhancerConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(120))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            api_key,
            config,
            client,
        }
    }

    /// Generate the expert prompt for vulnerability analysis
    fn generate_prompt(&self, vuln: &VulnerabilityInput) -> String {
        format!(
            r#"You are an elite Solana smart contract security auditor. Analyze this vulnerability and provide a comprehensive assessment.

## VULNERABILITY DETAILS
- **ID**: {}
- **Title**: {}
- **Description**: {}
- **Severity**: {} (1=Low, 3=Medium, 4=High, 5=Critical)
- **Location**: {}:{}

## VULNERABLE CODE
```rust
{}
```

## REQUIRED OUTPUT
Provide your analysis as a JSON object with these exact fields:

```json
{{
  "technical_explanation": "Detailed technical explanation of WHY this code is vulnerable. Reference specific lines and explain the root cause. 2-3 paragraphs.",
  "attack_scenario": "Step-by-step attack scenario showing exactly how an attacker would exploit this. Include account setup, transaction sequence, and expected outcome with profit mechanism.",
  "proof_of_concept": "Rust/TypeScript code snippet demonstrating the exploit. Use anchor_client or solana_sdk patterns.",
  "recommended_fix": "The corrected Rust code that fixes this vulnerability. Show the entire fixed function/struct.",
  "economic_impact": "Quantified economic impact estimate with reasoning. Consider TVL, transaction volume, and exploit repeatability. Format: '$X - $Y with confidence level'",
  "severity_justification": "Justify the severity rating. Consider exploitability, impact, and likelihood. Reference CWE/CVSS if applicable."
}}
```

IMPORTANT: Output ONLY the JSON object, no additional text or markdown fencing."#,
            vuln.id,
            vuln.title,
            vuln.description,
            vuln.severity,
            vuln.file_path,
            vuln.line_number,
            vuln.code_snippet
        )
    }

    /// Make API call with retry logic and rate-limit awareness
    async fn call_api_with_retry(&self, prompt: &str) -> Result<String, String> {
        let mut last_error = String::new();
        let max_attempts = 5; // Increased for low-quota keys

        for attempt in 1..=max_attempts {
            match self.call_api(prompt).await {
                Ok(response) => return Ok(response),
                Err(e) => {
                    last_error = e.clone();
                    if attempt < max_attempts {
                        // Check if it's a rate limit error
                        let is_rate_limit = e.contains("429")
                            || e.contains("rate_limit_exceeded")
                            || e.contains("quota");

                        let delay = if is_rate_limit {
                            warn!("Rate limit reached. Waiting 35 seconds before retry...");
                            35000 // 35 seconds to clear 3 RPM sliding window
                        } else {
                            self.config.retry_delay_ms * (attempt as u64)
                        };

                        warn!(
                            "API call failed (attempt {}/{}): {}. Retrying in {}ms...",
                            attempt, max_attempts, e, delay
                        );
                        tokio::time::sleep(Duration::from_millis(delay)).await;
                    }
                }
            }
        }

        Err(format!(
            "API call failed after {} attempts: {}",
            max_attempts, last_error
        ))
    }

    /// Single API call - auto-detects OpenAI vs OpenRouter vs NVIDIA based on key prefix
    async fn call_api(&self, prompt: &str) -> Result<String, String> {
        // Detect API type based on key prefix
        let is_nvidia = self.api_key.starts_with("nvapi-");
        let is_openai = !is_nvidia
            && (self.api_key.starts_with("sk-proj-")
                || (self.api_key.starts_with("sk-") && !self.api_key.starts_with("sk-or-")));

        // Specific configuration for NVIDIA nemotron-3-nano-30b-a3b if requested
        let (max_tokens, reasoning_budget, chat_template_kwargs) =
            if is_nvidia && self.config.model.contains("nemotron") {
                (
                    Some(16384),
                    Some(16384),
                    Some(serde_json::json!({"enable_thinking": true})),
                )
            } else {
                (Some(self.config.max_tokens), None, None)
            };

        // Use max_completion_tokens for OpenAI (newer models like gpt-5-nano require it)
        // Use max_tokens for OpenRouter/NVIDIA
        let request = OpenRouterRequest {
            model: self.config.model.clone(),
            messages: vec![ChatMessage {
                role: "user".to_string(),
                content: prompt.to_string(),
            }],
            temperature: if is_openai {
                None
            } else {
                Some(self.config.temperature)
            },
            max_tokens: if is_openai { None } else { max_tokens },
            max_completion_tokens: if is_openai {
                Some(self.config.max_tokens)
            } else {
                None
            },
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

        // Add OpenRouter-specific headers only for OpenRouter
        if !is_openai && !is_nvidia {
            req_builder = req_builder
                .header("HTTP-Referer", "https://solana-security-swarm.local")
                .header("X-Title", "Solana Security Swarm Auditor");
        }

        let response = req_builder
            .json(&request)
            .send()
            .await
            .map_err(|e| format!("HTTP request failed: {}", e))?;

        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|e| format!("Failed to read response: {}", e))?;

        if !status.is_success() {
            return Err(format!("API returned {}: {}", status, body));
        }

        let parsed: OpenRouterResponse = serde_json::from_str(&body)
            .map_err(|e| format!("Failed to parse response: {} - Body: {}", e, body))?;

        if let Some(error) = parsed.error {
            return Err(format!("API error: {}", error.message));
        }

        parsed
            .choices
            .and_then(|c| c.into_iter().next())
            .map(|c| c.message.content)
            .ok_or_else(|| "Empty response from API".to_string())
    }

    /// Parse JSON response from AI, handling common issues
    fn parse_response(&self, response: &str) -> Result<EnhancedExplanation, String> {
        // Try direct parse first
        if let Ok(parsed) = serde_json::from_str::<EnhancedExplanation>(response.trim()) {
            return Ok(parsed);
        }

        // Try extracting JSON from markdown code blocks
        let json_str = if response.contains("```json") {
            response
                .split("```json")
                .nth(1)
                .and_then(|s| s.split("```").next())
                .unwrap_or(response)
        } else if response.contains("```") {
            response.split("```").nth(1).unwrap_or(response)
        } else {
            response
        };

        serde_json::from_str::<EnhancedExplanation>(json_str.trim()).map_err(|e| {
            format!(
                "JSON parse error: {} - Response: {}",
                e,
                &response[..response.len().min(500)]
            )
        })
    }

    /// Enhance a single vulnerability with AI analysis
    pub async fn enhance_vulnerability(
        &self,
        vuln: &VulnerabilityInput,
    ) -> Result<EnhancedExplanation, String> {
        info!("Enhancing vulnerability: {} - {}", vuln.id, vuln.title);

        let prompt = self.generate_prompt(vuln);
        let response = self.call_api_with_retry(&prompt).await?;
        let enhanced = self.parse_response(&response)?;

        info!("Successfully enhanced vulnerability: {}", vuln.id);
        Ok(enhanced)
    }

    /// Batch enhance multiple vulnerabilities with controlled concurrency
    pub async fn enhance_vulnerabilities_batch(
        &self,
        vulns: Vec<VulnerabilityInput>,
    ) -> Vec<(String, Result<EnhancedExplanation, String>)> {
        info!(
            "Starting batch enhancement of {} vulnerabilities",
            vulns.len()
        );

        let results: Vec<_> = stream::iter(vulns)
            .map(|vuln| async move {
                let id = vuln.id.clone();
                let result = self.enhance_vulnerability(&vuln).await;
                (id, result)
            })
            .buffer_unordered(self.config.concurrency_limit)
            .collect()
            .await;

        let success_count = results.iter().filter(|(_, r)| r.is_ok()).count();
        info!(
            "Batch enhancement complete: {}/{} successful",
            success_count,
            results.len()
        );

        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_parsing_clean() {
        let json = r#"{
            "technical_explanation": "The code lacks signer verification.",
            "attack_scenario": "Attacker calls instruction directly.",
            "proof_of_concept": "// exploit code here",
            "recommended_fix": "Add Signer constraint.",
            "economic_impact": "$100k - $1M",
            "severity_justification": "Critical due to direct fund access."
        }"#;

        let enhancer = AIEnhancer::new("test".to_string(), "test".to_string());
        let result = enhancer.parse_response(json);
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap().technical_explanation,
            "The code lacks signer verification."
        );
    }

    #[test]
    fn test_json_parsing_with_markdown() {
        let response = r#"Here's my analysis:

```json
{
    "technical_explanation": "Missing signer check.",
    "attack_scenario": "Direct call.",
    "proof_of_concept": "code",
    "recommended_fix": "Add check.",
    "economic_impact": "$50k",
    "severity_justification": "High risk."
}
```

Hope this helps!"#;

        let enhancer = AIEnhancer::new("test".to_string(), "test".to_string());
        let result = enhancer.parse_response(response);
        assert!(result.is_ok());
    }

    #[test]
    fn test_prompt_generation() {
        let vuln = VulnerabilityInput {
            id: "1.1".to_string(),
            title: "Missing Signer Check".to_string(),
            description: "Authority not verified".to_string(),
            severity: 5,
            code_snippet: "pub authority: AccountInfo<'info>".to_string(),
            file_path: "src/lib.rs".to_string(),
            line_number: 42,
        };

        let enhancer = AIEnhancer::new(
            "test".to_string(),
            "anthropic/claude-3.5-sonnet".to_string(),
        );
        let prompt = enhancer.generate_prompt(&vuln);

        assert!(prompt.contains("Missing Signer Check"));
        assert!(prompt.contains("src/lib.rs:42"));
        assert!(prompt.contains("JSON object"));
    }
}
