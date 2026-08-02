//! **Spend metering + budget enforcement** — the LLM-cost kill switch.
//!
//! Foreguard's proxy governs *actions* (what a tool call would do). This module
//! governs *spend* (what the model itself costs). They're different surfaces: token
//! spend happens on the agent→model-API path, not the MCP tool-call path, so this is
//! a sibling interception point, not a patch to the proxy — but it shares Foreguard's
//! philosophy: **deterministic, fail-safe, and enforcement over alerts.**
//!
//! Why enforcement and not alerting: an agent in a retry loop can burn *multiples* of
//! a budget in the time it takes a human to read an alert (a real 4-agent loop is on
//! record burning ~$47k over 11 days). So the meter doesn't warn — it **refuses**.
//! Because a request's cost isn't known until the response comes back, the kill
//! switch is a pre-flight check on *cumulative* spend: the moment total spend crosses
//! the budget, every further request is blocked.
//!
//! The core here is pure and deterministic — parse usage, price it, accumulate,
//! decide — which is where the real IP lives. A live HTTP gateway that points
//! `ANTHROPIC_BASE_URL`/`OPENAI_BASE_URL` at Foreguard is a thin front-end over this.

use std::collections::HashMap;

use serde_json::Value;

/// Token usage from one model response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Usage {
    pub input_tokens: u64,
    pub output_tokens: u64,
}

impl Usage {
    /// Parse usage out of a model-API JSON response, accepting the Anthropic shape
    /// (`usage.input_tokens` / `output_tokens`) and the OpenAI shape
    /// (`usage.prompt_tokens` / `completion_tokens`). Returns `None` only when no
    /// recognizable usage is present.
    ///
    /// Two subtleties, both in the direction of **not under-counting** a budget:
    /// - Anthropic's streaming `message_start` nests usage under `message.usage`
    ///   rather than at the top level — where the (often dominant) input-token count
    ///   lives — so we look there too. Missing it would silently drop input cost.
    /// - Cache tokens (`cache_creation_input_tokens` / `cache_read_input_tokens`)
    ///   are billed input; we fold them into `input_tokens` at the input rate. Cache
    ///   *reads* are actually cheaper, so this is a conservative over-estimate — the
    ///   safe direction for a kill switch (it trips a touch early, never late).
    pub fn from_response(v: &Value) -> Option<Usage> {
        // Top level for non-streaming and OpenAI; nested under `message` for
        // Anthropic's streaming `message_start`.
        let u = v
            .get("usage")
            .or_else(|| v.get("message").and_then(|m| m.get("usage")))?;
        let input = field(u, &["input_tokens", "prompt_tokens"]);
        let output = field(u, &["output_tokens", "completion_tokens"]);
        let cache = field(u, &["cache_creation_input_tokens"]).unwrap_or(0)
            + field(u, &["cache_read_input_tokens"]).unwrap_or(0);
        // An empty or unrecognized `usage` object is treated as "no usage".
        if input.is_none() && output.is_none() && cache == 0 {
            return None;
        }
        Some(Usage {
            input_tokens: input.unwrap_or(0) + cache,
            output_tokens: output.unwrap_or(0),
        })
    }
}

/// First of `keys` present as a non-negative integer.
fn field(obj: &Value, keys: &[&str]) -> Option<u64> {
    keys.iter()
        .find_map(|k| obj.get(*k).and_then(Value::as_u64))
}

/// Price for one model, in **cents per million tokens** (integers keep the math
/// exact and deterministic — no floats in the accounting path).
#[derive(Debug, Clone, Copy)]
pub struct Price {
    pub input_per_mtok_cents: u64,
    pub output_per_mtok_cents: u64,
}

/// A per-model price book. The built-in numbers are **illustrative defaults** meant
/// to be overridden (`--price name=IN:OUT`); the enforcement logic doesn't depend on
/// them being exact, only on them being applied deterministically.
#[derive(Debug, Clone)]
pub struct PriceTable {
    exact: HashMap<String, Price>,
    default: Price,
}

impl Default for PriceTable {
    fn default() -> Self {
        Self::builtin()
    }
}

impl PriceTable {
    /// Illustrative defaults, matched by model *family* (see [`Self::price_for`]).
    pub fn builtin() -> Self {
        Self {
            exact: HashMap::new(),
            default: Price {
                input_per_mtok_cents: 1000,
                output_per_mtok_cents: 3000,
            },
        }
    }

    /// Add or override an exact-name price (from a `--price name=IN:OUT` flag).
    pub fn set(&mut self, model: &str, price: Price) {
        self.exact.insert(model.to_ascii_lowercase(), price);
    }

    /// The price for a model: an exact override wins; otherwise match by family
    /// substring; otherwise the default. Family matching lets `claude-opus-4-8` and
    /// `claude-opus-5` share one entry without enumerating every version.
    pub fn price_for(&self, model: &str) -> Price {
        let m = model.to_ascii_lowercase();
        if let Some(p) = self.exact.get(&m) {
            return *p;
        }
        // (family substring, input cents/Mtok, output cents/Mtok) — illustrative.
        const FAMILIES: &[(&str, u64, u64)] = &[
            ("opus", 1500, 7500),
            ("sonnet", 300, 1500),
            ("fable", 300, 1500),
            ("haiku", 80, 400),
            ("gpt-4", 250, 1000),
            ("gpt-5", 250, 1000),
            ("gpt", 150, 600),
            ("gemini", 200, 800),
        ];
        for (needle, i, o) in FAMILIES {
            if m.contains(needle) {
                return Price {
                    input_per_mtok_cents: *i,
                    output_per_mtok_cents: *o,
                };
            }
        }
        self.default
    }

    /// Cost of one usage record for `model`, in cents (rounded to nearest). Uses
    /// `u128` so a huge token count can't overflow the intermediate product.
    pub fn cost_cents(&self, model: &str, u: &Usage) -> u64 {
        let p = self.price_for(model);
        let micro = u128::from(u.input_tokens) * u128::from(p.input_per_mtok_cents)
            + u128::from(u.output_tokens) * u128::from(p.output_per_mtok_cents);
        // Divide by 1e6 tokens/Mtok, rounding to the nearest cent.
        let cents = (micro + 500_000) / 1_000_000;
        cents.min(u128::from(u64::MAX)) as u64
    }
}

/// The result of metering one response against the budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Charge {
    /// The request was within budget; here is its cost and the new running total.
    Ok { cost_cents: u64, spent_cents: u64 },
    /// Cumulative spend has crossed the budget — this and every later request is
    /// refused. Carries the total and the budget it exceeded.
    Blocked { spent_cents: u64, budget_cents: u64 },
}

/// Accumulates spend and enforces a hard budget. Fail-safe: with no budget set it
/// only meters (never blocks); with a budget it blocks the moment spend crosses it.
#[derive(Debug, Clone)]
pub struct SpendMeter {
    budget_cents: Option<u64>,
    spent_cents: u64,
    blocked: bool,
    prices: PriceTable,
}

impl SpendMeter {
    pub fn new(budget_cents: Option<u64>, prices: PriceTable) -> Self {
        Self {
            budget_cents,
            spent_cents: 0,
            blocked: false,
            prices,
        }
    }

    /// Total spent so far, in cents.
    pub fn spent_cents(&self) -> u64 {
        self.spent_cents
    }

    /// The budget ceiling in cents, if one was set.
    pub fn budget_cents(&self) -> Option<u64> {
        self.budget_cents
    }

    /// Has the budget been crossed? Once true, it stays true (a tripped kill switch
    /// does not silently re-arm).
    pub fn is_blocked(&self) -> bool {
        self.blocked
    }

    /// Pre-flight: may another request proceed? False once the budget is crossed.
    pub fn allow_request(&self) -> bool {
        !self.over_budget()
    }

    fn over_budget(&self) -> bool {
        matches!(self.budget_cents, Some(b) if self.spent_cents >= b)
    }

    /// Meter one model response. If the budget is already crossed, the request is
    /// `Blocked` and nothing is added (it should never have been sent). Otherwise its
    /// cost is recorded and returned; crossing the budget trips the kill switch so
    /// the *next* call is blocked.
    pub fn charge(&mut self, model: &str, usage: &Usage) -> Charge {
        if self.over_budget() {
            self.blocked = true;
            return Charge::Blocked {
                spent_cents: self.spent_cents,
                budget_cents: self.budget_cents.unwrap_or(0),
            };
        }
        let cost = self.prices.cost_cents(model, usage);
        self.spent_cents = self.spent_cents.saturating_add(cost);
        if self.over_budget() {
            self.blocked = true;
        }
        Charge::Ok {
            cost_cents: cost,
            spent_cents: self.spent_cents,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_anthropic_and_openai_usage_shapes() {
        let anthropic =
            json!({"model":"claude-opus-4-8","usage":{"input_tokens":100,"output_tokens":50}});
        assert_eq!(
            Usage::from_response(&anthropic),
            Some(Usage {
                input_tokens: 100,
                output_tokens: 50
            })
        );
        let openai = json!({"model":"gpt-5","usage":{"prompt_tokens":200,"completion_tokens":80}});
        assert_eq!(
            Usage::from_response(&openai),
            Some(Usage {
                input_tokens: 200,
                output_tokens: 80
            })
        );
        // A chunk with no usage yields None, not a zero charge.
        assert_eq!(
            Usage::from_response(&json!({"type":"content_block_delta"})),
            None
        );
        // An empty usage object is also "no usage", not a zero charge.
        assert_eq!(Usage::from_response(&json!({"usage":{}})), None);
    }

    #[test]
    fn finds_nested_usage_and_folds_in_cache_tokens() {
        // Anthropic streaming `message_start` nests usage under `message` — the
        // input count must not be dropped.
        let start = json!({
            "type":"message_start",
            "message":{"usage":{"input_tokens":25000,"output_tokens":1}}
        });
        assert_eq!(
            Usage::from_response(&start),
            Some(Usage {
                input_tokens: 25000,
                output_tokens: 1
            })
        );
        // Cache tokens are billed input and are folded in (conservatively).
        let cached = json!({"usage":{
            "input_tokens": 1000,
            "cache_creation_input_tokens": 2000,
            "cache_read_input_tokens": 500,
            "output_tokens": 100
        }});
        assert_eq!(
            Usage::from_response(&cached),
            Some(Usage {
                input_tokens: 3500,
                output_tokens: 100
            })
        );
    }

    #[test]
    fn cost_is_priced_by_family_and_rounded() {
        let t = PriceTable::builtin();
        // 1M input + 1M output on the opus family = 1500 + 7500 = 9000 cents.
        let u = Usage {
            input_tokens: 1_000_000,
            output_tokens: 1_000_000,
        };
        assert_eq!(t.cost_cents("claude-opus-4-8", &u), 9000);
        // Haiku is far cheaper for the same tokens.
        assert_eq!(t.cost_cents("claude-haiku-4-5", &u), 80 + 400);
        // Unknown model falls back to the default price.
        assert_eq!(t.cost_cents("mystery-model", &u), 1000 + 3000);
    }

    #[test]
    fn exact_override_beats_family_match() {
        let mut t = PriceTable::builtin();
        t.set(
            "claude-opus-4-8",
            Price {
                input_per_mtok_cents: 1,
                output_per_mtok_cents: 1,
            },
        );
        let u = Usage {
            input_tokens: 1_000_000,
            output_tokens: 1_000_000,
        };
        assert_eq!(t.cost_cents("claude-opus-4-8", &u), 2, "override wins");
        // A different opus version still uses the family default.
        assert_eq!(t.cost_cents("claude-opus-5", &u), 9000);
    }

    #[test]
    fn no_budget_meters_but_never_blocks() {
        let mut m = SpendMeter::new(None, PriceTable::builtin());
        let u = Usage {
            input_tokens: 10_000_000,
            output_tokens: 10_000_000,
        };
        for _ in 0..5 {
            assert!(m.allow_request());
            assert!(matches!(m.charge("opus", &u), Charge::Ok { .. }));
        }
        assert!(!m.is_blocked());
    }

    #[test]
    fn the_kill_switch_halts_a_runaway_loop_at_the_budget() {
        // Budget $5.00 = 500 cents. Each call costs 150 cents: sonnet output is
        // 1500 c/Mtok, so 100k output tokens = 0.1 Mtok = 150 c.
        let mut m = SpendMeter::new(Some(500), PriceTable::builtin());
        let per_call = Usage {
            input_tokens: 0,
            output_tokens: 100_000,
        };
        // Calls 1..=3 spend 150/300/450 — all under 500, all allowed.
        for expected in [150u64, 300, 450] {
            assert!(m.allow_request());
            assert_eq!(
                m.charge("claude-sonnet-5", &per_call),
                Charge::Ok {
                    cost_cents: 150,
                    spent_cents: expected
                }
            );
        }
        // Call 4 takes us to 600 ≥ 500 — recorded, but the kill switch trips.
        assert!(m.allow_request(), "still allowed just before crossing");
        assert!(matches!(
            m.charge("claude-sonnet-5", &per_call),
            Charge::Ok {
                spent_cents: 600,
                ..
            }
        ));
        assert!(m.is_blocked(), "crossing the budget trips the switch");

        // Every further request is refused pre-flight — the runaway is stopped.
        assert!(!m.allow_request());
        assert_eq!(
            m.charge("claude-sonnet-5", &per_call),
            Charge::Blocked {
                spent_cents: 600,
                budget_cents: 500
            }
        );
        assert_eq!(m.spent_cents(), 600, "blocked requests add nothing");
    }
}
