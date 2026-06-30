# Business Logic Testing — Swarm Workflow

## MCP Tools
- `get_wstg_test(category="business")` — Business logic test cases
- `search_wstg("business logic")` — Find relevant test procedures
- `get_witness_payloads("business")` — Business logic test payloads

## Key Test Categories
1. Workflow bypass (multi-step process reordering)
2. Pricing manipulation (negative quantities, fractional amounts)
3. Coupon/promo code abuse (reuse, stacking, excessive discounts)
4. Currency conversion rounding exploits
5. Race conditions (TOCTOU in financial transactions)
6. Loyalty/rewards program abuse
7. KYC bypass

## Burp Workflow
```bash
# Capture multi-step workflow
burp_send_to_repeater(step1_url, headers, body)
burp_send_to_repeater(step2_url, headers, body)

# Replay steps out of order
burp_send_to_repeater(step3_url, headers, body)  # skip to step 3 directly

# Race condition testing
burp_send_to_intruder(url, positions=["coupon_code"], payloads=["WELCOME10"], concurrent=10)
```

## WSTG Test Map

| ID | What It Covers |
|----|----------------|
| WSTG-BUSL-01 | Workflow bypass — skip steps in multi-step process (checkout, registration, KYC) |
| WSTG-BUSL-02 | Pricing manipulation — negative quantities, decimal truncation, currency swap |
| WSTG-BUSL-03 | Coupon/promo abuse — reuse, stacking, excessive percentage, applying to excluded items |
| WSTG-BUSL-04 | Race condition — TOCTOU in financial transactions, coupon redemption, account creation |
| WSTG-BUSL-05 | Loyalty/rewards abuse — point inflation, unauthorized transfers, expiration bypass |
| WSTG-BUSL-06 | KYC bypass — submit fake documents, skip verification step |
| WSTG-BUSL-07 | Functionality misuse — use intended feature for unintended purpose (e.g., support tool to read other user data) |

## Attack Playbook

### Pricing Manipulation (WSTG-BUSL-02)
1. Add item to cart → intercept POST/PUT → modify `price`, `quantity`, `currency`
2. Test negative quantity: `"quantity": -1` → does it increase balance or reduce price?
3. Test decimal truncation: `"quantity": 0.01` or `"price": 0.001` → rounding behavior
4. Test currency conversion: modify `"currency": "USD"` → `"currency": "XXX"` → does it accept anything?
5. Test bundle manipulation: add bundle, remove items from bundle, check if discount still applies
6. Chain: pricing bug → purchase high-value item at ~$0 → resell

### Coupon Abuse (WSTG-BUSL-03)
1. Apply coupon → capture request → replay same coupon code
2. Test coupon stacking: apply multiple coupons via param pollution
3. Test percentage overflow: `"discount": 100` → price becomes 0? `"discount": -100` → price increases?
4. Test wildcard: try `*`, `ALL`, `PERCENT_OFF` as coupon codes
5. Chain: coupon abuse → unlimited free purchases → inventory depletion

### Race Condition (WSTG-BUSL-04)
1. Send 10+ concurrent POSTs for same action (redeem coupon, withdraw, transfer)
2. Use burp Intruder with concurrent threads = 10-20
3. Key endpoints to test: coupon redemption, account creation (same email), fund transfer, voting, like/follow
4. Check if limit is enforced AFTER processing (TOCTOU) vs BEFORE
5. Chain: race condition → redeem same coupon 10x → disproportionate benefit

### Workflow Bypass (WSTG-BUSL-01)
1. Map the full multi-step flow (e.g., payment: cart → shipping → billing → confirm → pay)
2. Skip directly to step 5 (pay) and POST with step 4 data
3. Go back to step 2 after completing step 5 → modify shipping address → confirm
4. Intercept step transitions → replay step 3 with modified step 1 data
5. Chain: workflow bypass → purchase without payment → item received

## Anti-Patterns

| Pitfall | Why It Wastes Time |
|---------|-------------------|
| **Testing business logic without understanding the flow first** | You can't find logic flaws if you don't know the intended flow |
| **Skipping race condition testing because "it's hard to reproduce"** | Use burp Intruder concurrent mode; 10 parallel requests is often enough |
| **Only testing coupon abuse with a single coupon code** | Test stacking, wildcards, expired coupons, and pasting the same code multiple times |
| **Not documenting the business impact in dollar terms** | A pricing bug that costs $1M/year is critical, same bug on a free site is low |
| **Testing race conditions on GET-only endpoints** | Write operations (POST/PUT/DELETE) are where races manifest |

## Evidence Requirements
- [ ] Complete workflow sequence screenshots
- [ ] Manipulated request/response pairs
- [ ] Business impact calculation ($$ at risk)
- [ ] WSTG BUSL test ID
- [ ] Race condition timing (concurrent request count + successful duplicates)

## Phase Gates
- Phase 3 (INFO-GATHERING): Understand application business flow
- Phase 5 (SURFACE): Identify high-value business operations
- Phase 6 (HUNT): Test each business logic violation
- Phase 8 (EXPLOIT): Demonstrate financial/operational impact
