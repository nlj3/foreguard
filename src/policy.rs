//! The **Cedar policy engine** — Foreguard's authorization layer.
//!
//! The classifier answers *"is this call a mutation?"* Policy answers the next
//! question: *"is this call **allowed**?"* — the business-action-level rule that an
//! identity layer ("this agent may call the Stripe API") is too coarse to express:
//! *refunds ≤ $50 run, refunds to new accounts never run, and no session may make
//! more than N tool calls.*
//!
//! We use [Cedar](https://www.cedarpolicy.com/) rather than inventing a DSL. AWS
//! built Cedar to authorize agent tool calls (Bedrock AgentCore) and donated it to
//! the CNCF, so it is becoming the standard; and its semantics — default-deny,
//! **forbid overrides permit**, order-independent, deterministic, no side effects —
//! are exactly Foreguard's fail-safe, deny-wins ethos. Speaking Cedar makes
//! Foreguard interoperable with where the market is heading while staying the open,
//! local, framework-neutral enforcement point.
//!
//! ## How a Cedar decision maps to a Foreguard action
//!
//! Cedar returns only `Allow`/`Deny`, but Foreguard needs three outcomes, so we read
//! the diagnostics to tell a *satisfied `forbid`* apart from a *default-deny*:
//!
//! | Cedar result                         | [`PolicyDecision`] | What the proxy does                     |
//! |--------------------------------------|--------------------|-----------------------------------------|
//! | `Allow` (a `permit` matched)         | `Authorized`       | pre-authorized — execute for real       |
//! | `Deny`, a `forbid` satisfied         | `Blocked`          | hard block — never runs, even with `--approve` |
//! | `Deny`, nothing matched              | `Unset`            | defer to Foreguard's existing behavior  |
//!
//! One safety override on that table: if *any* policy **errors** while evaluating
//! (e.g. a `forbid` that references an attribute this call lacks), an `Allow` is
//! downgraded to `Unset` rather than `Authorized` — a silently-broken `forbid` must
//! never fail open into auto-executing a real mutation.
//!
//! `Unset` — not Cedar's strict default-deny — is deliberate: with no policy opinion
//! we fall back to Foreguard's already-safe default (dry-run), so adding a policy
//! file can only ever make a call *more* restricted (a new `forbid`) or lift the
//! babysitting on a *known-safe* one (an explicit `permit`). It never loosens the
//! floor. Taint (Rule-of-Two) still overrides a `permit`: untrusted data driving a
//! mutation is gated no matter what policy says.

use std::path::Path;
use std::str::FromStr;

use anyhow::{Context as _, Result};
use cedar_policy::{
    Authorizer, Context, Decision, Entities, EntityId, EntityTypeName, EntityUid, PolicySet,
    Request,
};
use serde_json::{json, Map, Value};

/// What policy says should happen to one tool call. See the module table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
    /// A `forbid` matched — hard block. Never executes, even under `--approve`.
    Blocked,
    /// A `permit` matched — the call is pre-authorized to run for real.
    Authorized,
    /// No policy matched — defer to Foreguard's existing (safe) behavior.
    Unset,
}

/// The facts about a tool call that a Cedar policy can test, surfaced as the
/// request's principal/resource and its `context` record.
pub struct CallContext<'a> {
    /// The agent making the call (`context`'s principal, `Agent::"…"`).
    pub agent: &'a str,
    /// The tool being invoked (the resource, `Tool::"…"`, and `context.tool`).
    pub tool: &'a str,
    /// `context.mutating` — did the classifier judge this a mutation?
    pub mutating: bool,
    /// `context.risk` — `"high"`, `"medium"`, or `"none"` for a read.
    pub risk: Option<&'a str>,
    /// `context.tainted` — is untrusted data driving this call (Rule-of-Two)?
    pub tainted: bool,
    /// `context.session_calls` — tool calls seen this session (runaway-loop guard).
    pub session_calls: i64,
    /// `context.session_cost` — estimated spend so far, in cents (0 until the LLM
    /// proxy surface lands; wired now so policies can be written against it).
    pub session_cost: i64,
    /// The call's top-level arguments, exposed two ways: `context.args.*` (typed —
    /// integers as `Long`, so `<= 50` works) and `context.dec.*` (every number as a
    /// Cedar `decimal`, for fractional money — `.lessThanOrEqual(decimal("50.00"))`).
    pub arguments: &'a Value,
}

/// A parsed, ready-to-evaluate Cedar policy set plus its authorizer.
pub struct PolicyEngine {
    policies: PolicySet,
    authorizer: Authorizer,
}

impl PolicyEngine {
    /// Load and parse a Cedar policy file. Parse errors are surfaced here, at
    /// startup, rather than mid-session.
    pub fn from_file(path: &Path) -> Result<Self> {
        let src = std::fs::read_to_string(path)
            .with_context(|| format!("reading policy file {}", path.display()))?;
        Self::parse(&src).with_context(|| format!("in policy file {}", path.display()))
    }

    /// Parse Cedar policy source into an engine.
    pub fn parse(src: &str) -> Result<Self> {
        let policies =
            PolicySet::from_str(src).map_err(|e| anyhow::anyhow!("parsing Cedar policy: {e}"))?;
        Ok(Self {
            policies,
            authorizer: Authorizer::new(),
        })
    }

    /// How many policies were loaded (for the startup banner).
    pub fn len(&self) -> usize {
        self.policies.policies().count()
    }

    /// Evaluate one call. **Fail-safe:** any error building the request defers to
    /// `Unset` (Foreguard's safe default), never to `Authorized`.
    pub fn evaluate(&self, call: &CallContext) -> PolicyDecision {
        match self.try_evaluate(call) {
            Ok(d) => d,
            Err(e) => {
                eprintln!(
                    "⚠  foreguard: policy evaluation error ({e}); deferring to default handling."
                );
                PolicyDecision::Unset
            }
        }
    }

    fn try_evaluate(&self, call: &CallContext) -> Result<PolicyDecision> {
        let principal = uid("Agent", call.agent);
        let action = uid("Action", "invoke");
        let resource = uid("Tool", call.tool);
        let context = Context::from_json_value(self.context_json(call), None)
            .map_err(|e| anyhow::anyhow!("building policy context: {e}"))?;
        let request = Request::new(principal, action, resource, context, None)
            .map_err(|e| anyhow::anyhow!("building policy request: {e}"))?;

        let response = self
            .authorizer
            .is_authorized(&request, &self.policies, &Entities::empty());

        // A policy that *errors* at evaluation (e.g. a `forbid` that references an
        // attribute this call doesn't have) is silently skipped by Cedar and does
        // not contribute to the decision. That is a fail-*open* footgun here,
        // because a satisfied `permit` would then AUTHORIZE a real mutation — the
        // author's `forbid` having quietly not applied. So: if any policy errored,
        // never authorize. A satisfied `forbid` still blocks; everything else
        // downgrades to `Unset` and falls back to Foreguard's safe gate (dry-run /
        // approval), where the human still sees it.
        let had_errors = response.diagnostics().errors().next().is_some();
        if had_errors {
            for e in response.diagnostics().errors() {
                eprintln!(
                    "⚠  foreguard: a policy failed to evaluate ({e}); it will not authorize this \
                     call. Guard optional attributes with `has` (e.g. `context.args has x && …`)."
                );
            }
        }

        Ok(match response.decision() {
            // A `permit` was satisfied and no `forbid` overrode it — but only trust
            // it when the whole policy set evaluated cleanly.
            Decision::Allow if !had_errors => PolicyDecision::Authorized,
            Decision::Allow => PolicyDecision::Unset,
            Decision::Deny => {
                // `reason()` lists the policies that *forced* this decision. On a
                // Deny those are satisfied `forbid`s — if there are none, nothing
                // matched at all (Cedar's implicit default-deny), which for us means
                // "no opinion", not "blocked".
                if response.diagnostics().reason().next().is_some() {
                    PolicyDecision::Blocked
                } else {
                    PolicyDecision::Unset
                }
            }
        })
    }

    /// Build the Cedar `context` record from the call's facts.
    fn context_json(&self, call: &CallContext) -> Value {
        json!({
            "tool": call.tool,
            "risk": call.risk.unwrap_or("none"),
            "mutating": call.mutating,
            "tainted": call.tainted,
            "session_calls": call.session_calls,
            "session_cost": call.session_cost,
            "args": sanitize_args(call.arguments),
            "dec": decimal_args(call.arguments),
        })
    }
}

/// Build an `EntityUid` (`Type::"id"`) from a static type name and a runtime id,
/// via the typed constructor so arbitrary tool/agent names can't break the parse
/// the way string interpolation into Cedar syntax could.
fn uid(type_name: &str, id: &str) -> EntityUid {
    let ty = EntityTypeName::from_str(type_name).expect("static Cedar type name is valid");
    EntityUid::from_type_name_and_id(ty, EntityId::new(id))
}

/// Flatten a call's arguments into a Cedar-safe record for `context.args`: keep
/// strings, booleans, and integer numbers (Cedar `Long`, so `context.args.n <= 50`
/// works ergonomically); render floats and out-of-range integers as strings (Cedar
/// `Long` can't hold them); drop nulls and nested arrays/objects. Flat, typed, and
/// total so evaluation can't trip over a shape Cedar won't accept. For fractional
/// money, use the companion `context.dec.*` record instead (see [`decimal_args`]).
fn sanitize_args(args: &Value) -> Value {
    let mut out = Map::new();
    if let Some(obj) = args.as_object() {
        for (k, v) in obj {
            let cedar = match v {
                Value::String(_) | Value::Bool(_) => v.clone(),
                Value::Number(n) if n.is_i64() => v.clone(),
                Value::Number(n) => Value::String(n.to_string()),
                _ => continue,
            };
            out.insert(k.clone(), cedar);
        }
    }
    Value::Object(out)
}

/// Build the companion `context.dec` record: every numeric argument as a Cedar
/// **decimal** extension value, so a money rule can compare cents uniformly —
/// `context.dec.amount.lessThanOrEqual(decimal("50.00"))` holds for `30`, `30.0`,
/// and `49.99` alike. Integers live in `context.args` too (as `Long`), but only
/// `context.dec` gives fractional money a working numeric comparison. Numbers that
/// don't fit Cedar's decimal range are omitted, so a rule referencing one errors and
/// falls closed rather than poisoning the whole context.
fn decimal_args(args: &Value) -> Value {
    let mut out = Map::new();
    if let Some(obj) = args.as_object() {
        for (k, v) in obj {
            if let Value::Number(n) = v {
                if let Some(arg) = to_decimal_arg(n) {
                    out.insert(
                        k.clone(),
                        json!({ "__extn": { "fn": "decimal", "arg": arg } }),
                    );
                }
            }
        }
    }
    Value::Object(out)
}

/// Format a JSON number as a Cedar decimal literal string: a `.` with digits on both
/// sides and at most 4 fractional digits (`"49.9900"`), within decimal's range
/// (±922337203685477.5807). Returns `None` for non-finite or out-of-range values so
/// they're simply left out of `context.dec`.
fn to_decimal_arg(n: &serde_json::Number) -> Option<String> {
    let f = n.as_f64()?;
    // Leave headroom under the true bound so rounding to 4dp can't push us over.
    if !f.is_finite() || f.abs() > 922_337_203_685_477.0 {
        return None;
    }
    Some(format!("{f:.4}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn call<'a>(tool: &'a str, mutating: bool, args: &'a Value) -> CallContext<'a> {
        CallContext {
            agent: "default",
            tool,
            mutating,
            risk: Some(if mutating { "high" } else { "none" }),
            tainted: false,
            session_calls: 0,
            session_cost: 0,
            arguments: args,
        }
    }

    #[test]
    fn a_forbid_blocks_the_matching_tool() {
        let eng = PolicyEngine::parse(
            r#"forbid(principal, action, resource) when { context.tool == "delete_file" };"#,
        )
        .unwrap();
        assert_eq!(
            eng.evaluate(&call("delete_file", true, &json!({"path": "/etc/passwd"}))),
            PolicyDecision::Blocked
        );
        // A different tool isn't mentioned by any policy → no opinion.
        assert_eq!(
            eng.evaluate(&call("write_file", true, &json!({"path": "a"}))),
            PolicyDecision::Unset
        );
    }

    #[test]
    fn a_permit_preauthorizes_the_matching_call() {
        let eng = PolicyEngine::parse(
            r#"permit(principal, action, resource) when { context.mutating == false };"#,
        )
        .unwrap();
        assert_eq!(
            eng.evaluate(&call("read_file", false, &json!({"path": "x"}))),
            PolicyDecision::Authorized
        );
        // A mutation isn't permitted by this policy, and nothing forbids it → Unset.
        assert_eq!(
            eng.evaluate(&call("delete_file", true, &json!({}))),
            PolicyDecision::Unset
        );
    }

    #[test]
    fn forbid_wins_over_permit() {
        // Refunds up to $50 are fine — but never to a brand-new account, even under $50.
        let eng = PolicyEngine::parse(
            r#"
            permit(principal, action, resource)
              when { context.tool == "issue_refund" && context.args.amount <= 50 };
            forbid(principal, action, resource)
              when { context.tool == "issue_refund" && context.args.new_account == true };
            "#,
        )
        .unwrap();

        assert_eq!(
            eng.evaluate(&call(
                "issue_refund",
                true,
                &json!({"amount": 30, "new_account": false})
            )),
            PolicyDecision::Authorized,
            "a small refund to an established account is pre-authorized"
        );
        assert_eq!(
            eng.evaluate(&call(
                "issue_refund",
                true,
                &json!({"amount": 30, "new_account": true})
            )),
            PolicyDecision::Blocked,
            "forbid overrides the permit for a new account"
        );
        assert_eq!(
            eng.evaluate(&call(
                "issue_refund",
                true,
                &json!({"amount": 5000, "new_account": false})
            )),
            PolicyDecision::Unset,
            "a large refund is neither permitted nor forbidden → defer to approval"
        );
    }

    #[test]
    fn session_call_count_guards_a_runaway_loop() {
        // The tool-call-layer kill switch: no session may exceed 50 tool calls.
        let eng = PolicyEngine::parse(
            r#"forbid(principal, action, resource) when { context.session_calls > 50 };"#,
        )
        .unwrap();
        let args = json!({});
        let under = CallContext {
            session_calls: 50,
            ..call("anything", true, &args)
        };
        let over = CallContext {
            session_calls: 51,
            ..call("anything", true, &args)
        };
        assert_eq!(eng.evaluate(&under), PolicyDecision::Unset);
        assert_eq!(eng.evaluate(&over), PolicyDecision::Blocked);
    }

    #[test]
    fn decimal_money_rules_handle_cents() {
        // The gap this closes: fractional money in a numeric comparison. Using the
        // `context.dec` companion, one rule handles integer and fractional amounts.
        let eng = PolicyEngine::parse(
            r#"
            permit(principal, action, resource)
              when { context.tool == "issue_refund"
                     && context.dec.amount.lessThanOrEqual(decimal("50.00")) };
            "#,
        )
        .unwrap();

        // Integer amount under the limit → authorized.
        assert_eq!(
            eng.evaluate(&call("issue_refund", true, &json!({"amount": 30}))),
            PolicyDecision::Authorized
        );
        // Fractional amount under the limit — the case that used to fail — authorized.
        assert_eq!(
            eng.evaluate(&call("issue_refund", true, &json!({"amount": 49.99}))),
            PolicyDecision::Authorized
        );
        // Fractional amount just over the limit → not permitted → Unset.
        assert_eq!(
            eng.evaluate(&call("issue_refund", true, &json!({"amount": 50.01}))),
            PolicyDecision::Unset
        );
    }

    #[test]
    fn a_decimal_forbid_blocks_over_a_cents_threshold() {
        // forbid-wins with decimals: block refunds strictly over $50.00.
        let eng = PolicyEngine::parse(
            r#"forbid(principal, action, resource)
                 when { context.dec.amount.greaterThan(decimal("50.00")) };"#,
        )
        .unwrap();
        assert_eq!(
            eng.evaluate(&call("issue_refund", true, &json!({"amount": 50.01}))),
            PolicyDecision::Blocked
        );
        assert_eq!(
            eng.evaluate(&call("issue_refund", true, &json!({"amount": 50.00}))),
            PolicyDecision::Unset,
            "exactly at the limit is not over it"
        );
    }

    #[test]
    fn invalid_policy_source_is_a_parse_error() {
        assert!(PolicyEngine::parse("this is not cedar").is_err());
    }

    #[test]
    fn an_erroring_policy_never_authorizes_a_mutation() {
        // The permit matches; the forbid errors because the call has no `blocked`
        // attribute. A silently-erroring forbid must NOT fail open into
        // auto-execution — the decision downgrades to Unset (fall back to the gate),
        // never Authorized.
        let eng = PolicyEngine::parse(
            r#"
            permit(principal, action, resource) when { context.tool == "issue_refund" };
            forbid(principal, action, resource) when { context.args.blocked == true };
            "#,
        )
        .unwrap();
        let args = json!({"amount": 30}); // no `blocked` field → the forbid errors
        assert_eq!(
            eng.evaluate(&call("issue_refund", true, &args)),
            PolicyDecision::Unset,
            "an erroring policy set must never auto-authorize a real mutation"
        );

        // The `has`-guarded form evaluates cleanly, so the permit is trusted.
        let guarded = PolicyEngine::parse(
            r#"
            permit(principal, action, resource) when { context.tool == "issue_refund" };
            forbid(principal, action, resource)
              when { context.args has blocked && context.args.blocked == true };
            "#,
        )
        .unwrap();
        assert_eq!(
            guarded.evaluate(&call("issue_refund", true, &args)),
            PolicyDecision::Authorized
        );
    }

    #[test]
    fn float_and_nested_args_do_not_break_evaluation() {
        // Floats become strings and nested values are dropped; evaluation stays total
        // and a policy that references a now-absent nested field simply doesn't fire.
        let eng = PolicyEngine::parse(
            r#"forbid(principal, action, resource) when { context.args.limit > 10 };"#,
        )
        .unwrap();
        let args = json!({"limit": 49.99, "nested": {"a": 1}, "list": [1, 2]});
        // `limit` is a float → stringified → the `> 10` comparison errors for that
        // policy, which Cedar skips; no forbid is satisfied → Unset (fail-safe).
        assert_eq!(
            eng.evaluate(&call("do_thing", true, &args)),
            PolicyDecision::Unset
        );
    }
}
