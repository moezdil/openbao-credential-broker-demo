#!/usr/bin/env bash
#
# Runnable proof for Mode 3b on OpenBao with control groups (see README.md).
#
# Mode 3b keeps a broker in front of OpenBao that checks each live request
# before a decrypt happens. Letting that broker write per-row ACL policies and
# mint tokens over a decrypt-row-* role makes it an OpenBao admin, because the
# role checks the policy name and never the body (check 0 shows this). Here the
# broker writes nothing and mints nothing:
#   - the controller holds a static policy on transit/decrypt/user-* with a
#     control_group factor, so every decrypt it sends is held, not executed
#   - the broker can only review and approve held requests
#     (sys/control-group/request, sys/control-group/authorize)
#   - before approving, the broker verifies the subject JWT and the gateway's
#     single-use freshness proof, recomputes the row context from what it
#     verified, and compares it to OpenBao's stored copy of the request
#   - the controller unwraps, which executes the approved decrypt, then revokes
#     the wrapping token (an approved wrapping token can otherwise be unwrapped
#     again until the control group ttl expires, see check 15)
#
# Checks:
#   0      the per-row policy broker escalates to admin (the problem)
#   1-2    a controller decrypt is held, the broker approves a live request, the controller unwraps
#   3-7    nobody gets a decrypt alone: unwrap before approval, self-approval,
#          broker direct decrypt, broker policy write / token create
#   8-12   per-row scoping: wrong resource, wrong user, wrong ciphertext,
#          batch_input, replayed or expired gateway proof
#   13-16  lifetime: ttl expiry, controller revocation, wrapping token reuse,
#          ttl placement
#   17     audit joins the held request to the broker's approval
#
# Requirements: bao (2.7.0 or later), openssl, jq. Everything runs on 127.0.0.1.

set -u

PORT=8298
export BAO_ADDR="http://127.0.0.1:${PORT}"
export BAO_TOKEN=root
WORK=$(mktemp -d)
CG_TTL=15   # control group ttl in seconds; short on purpose, keep it near the proof window
PASS=0
FAIL=0

cleanup() {
  [ -n "${BAO_PID:-}" ] && kill "$BAO_PID" 2>/dev/null && wait "$BAO_PID" 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
b64url_d() { local s; s=$(tr -- '-_' '+/'); while [ $((${#s} % 4)) -ne 0 ]; do s="$s="; done; printf '%s' "$s" | openssl base64 -d -A; }
sha256() { printf '%s' "$1" | openssl dgst -sha256 -r | cut -d' ' -f1; }

# sign <key> <payload-json>  ->  RS256 JWT
sign() {
  local key=$1 header payload sig
  header=$(printf '{"alg":"RS256","typ":"JWT"}' | b64url)
  payload=$(printf '%s' "$2" | b64url)
  sig=$(printf '%s.%s' "$header" "$payload" | openssl dgst -sha256 -sign "$key" -binary | b64url)
  printf '%s.%s.%s' "$header" "$payload" "$sig"
}

# verify <pubkey> <jwt>  ->  payload json on stdout if the signature is valid
verify() {
  local pub=$1 jwt=$2 h p s
  IFS=. read -r h p s <<<"$jwt"
  printf '%s' "$s" | b64url_d >"$WORK/sig.bin"
  printf '%s.%s' "$h" "$p" | openssl dgst -sha256 -verify "$pub" -signature "$WORK/sig.bin" >/dev/null 2>&1 || return 1
  printf '%s' "$p" | b64url_d
}

# subject token from the IdP: who the user is
mkjwt() { sign "$WORK/idp.key" "$(printf '{"iss":"https://idp.local","aud":"agentgateway","sub":"%s","exp":%s}' "$1" "$2")"; }

# freshness proof from the gateway (stands in for a JWT-SVID signed proof):
# single-use jti, short exp, bound to the resource and a hash of the subject
mkproof() {
  sign "$WORK/gw.key" "$(printf '{"iss":"spiffe://demo/agentgateway","jti":"%s","exp":%s,"resource":"%s","sub_hash":"%s"}' \
    "$(openssl rand -hex 8)" "$3" "$2" "$(sha256 "$1")")"
}

fresh_proof() { mkproof "$1" "$2" $(($(date +%s) + 30)); }

# the row context, computed by the controller at write time and recomputed by
# the broker at approve time from what it verified
row_ctx() { printf '%s|%s|%s' "$1" "$2" "$3" | base64; }

# broker_approve <accessor> <subject-jwt> <proof> <row-id>
# Prints "approved" or "denied: <reason>". The broker trusts nothing the
# controller says about the request except the row id; everything else comes
# from the two signed tokens or from OpenBao's stored copy of the request.
broker_approve() {
  local acc=$1 jwt=$2 proof=$3 row=$4 now claims sub pclaims jti resource req
  now=$(date +%s)

  claims=$(verify "$WORK/idp.pub" "$jwt") || { echo "denied: subject token signature"; return; }
  [ "$(jq -r .aud <<<"$claims")" = agentgateway ] || { echo "denied: subject token audience"; return; }
  [ "$(jq -r .exp <<<"$claims")" -gt "$now" ] || { echo "denied: subject token expired"; return; }
  sub=$(jq -r .sub <<<"$claims")

  pclaims=$(verify "$WORK/gw.pub" "$proof") || { echo "denied: proof signature"; return; }
  [ "$(jq -r .exp <<<"$pclaims")" -gt "$now" ] || { echo "denied: proof expired"; return; }
  jti=$(jq -r .jti <<<"$pclaims")
  grep -qx "$jti" "$WORK/jti.seen" 2>/dev/null && { echo "denied: proof replayed"; return; }
  echo "$jti" >>"$WORK/jti.seen"
  [ "$(jq -r .sub_hash <<<"$pclaims")" = "$(sha256 "$sub")" ] || { echo "denied: proof is for another subject"; return; }
  resource=$(jq -r .resource <<<"$pclaims")

  req=$(env BAO_TOKEN="$BROKER_TOKEN" bao write -format=json sys/control-group/request accessor="$acc" 2>&1) \
    || { echo "denied: no such held request"; return; }
  [ "$(jq -r .data.request_entity.ID <<<"$req")" = "$CTRL_ENTITY" ] || { echo "denied: not held by the controller"; return; }
  [ "$(jq -r .data.request_path <<<"$req")" = "transit/decrypt/user-${sub}" ] || { echo "denied: key path is not this user's"; return; }
  [ "$(jq -r '.data.request_data | keys | join(",")' <<<"$req")" = "ciphertext,context" ] || { echo "denied: unexpected parameters"; return; }
  [ "$(jq -r .data.request_data.context <<<"$req")" = "$(row_ctx "$sub" "$resource" "$row")" ] \
    || { echo "denied: row is not for this request"; return; }

  [ "$(env BAO_TOKEN="$BROKER_TOKEN" bao write -field=approved sys/control-group/authorize accessor="$acc")" = true ] \
    && echo approved || echo "denied: authorize did not record"
}

# hold <token> <key> <ciphertext> <context>  ->  wrap_info json (or the error)
hold() { env BAO_TOKEN="$1" bao write -format=json "transit/decrypt/$2" ciphertext="$3" context="$4" 2>&1; }

# unwrap <wrapping-token>  ->  decoded plaintext, or the error
unwrap() {
  local out
  out=$(env -u BAO_TOKEN bao unwrap -format=json "$1" 2>&1) || { printf '%s' "$out"; return; }
  jq -r .data.plaintext <<<"$out" | base64 -d
}

# check <name> <expected-substring> <actual-output>
check() {
  local name=$1 want=$2 got=$3
  if printf '%s' "$got" | grep -q -- "$want"; then
    printf 'PASS  %s\n' "$name"
    PASS=$((PASS + 1))
  else
    printf 'FAIL  %s\n      wanted: %s\n      got: %s\n' "$name" "$want" "$got"
    FAIL=$((FAIL + 1))
  fi
}

echo "== starting OpenBao dev server on ${BAO_ADDR}"
# 2.7 refuses to enable audit devices through the API, so declare it in config
cat >"$WORK/server.hcl" <<EOF
audit "file" "file" {
  options {
    file_path = "$WORK/audit.log"
    log_raw   = "true"
  }
}
EOF
bao server -dev -dev-root-token-id=root -dev-listen-address="127.0.0.1:${PORT}" \
  -config="$WORK/server.hcl" >"$WORK/server.log" 2>&1 &
BAO_PID=$!
for _ in $(seq 1 20); do
  bao status >/dev/null 2>&1 && break
  sleep 0.5
done
bao status >/dev/null || { echo "server did not come up, see $WORK/server.log"; exit 1; }
bao version

echo "== setup: transit, controller and broker identities, policies"
openssl genrsa -out "$WORK/idp.key" 2048 2>/dev/null
openssl rsa -in "$WORK/idp.key" -pubout -out "$WORK/idp.pub" 2>/dev/null
openssl genrsa -out "$WORK/gw.key" 2048 2>/dev/null
openssl rsa -in "$WORK/gw.key" -pubout -out "$WORK/gw.pub" 2>/dev/null

bao secrets enable transit >/dev/null
bao write -f transit/keys/user-alice derived=true type=aes256-gcm96 >/dev/null
bao write -f transit/keys/user-bob   derived=true type=aes256-gcm96 >/dev/null

# The controller encrypts freely. Every decrypt it sends is held until one
# member of cb4a-broker approves it. On 2.7.2 the parser differs from the
# docs: controlled_capabilities is required, ttl and self_auth_allowed sit
# directly under control_group, and any other key inside identity {} is
# silently ignored (see check 16).
cat >"$WORK/controller.hcl" <<EOF
path "transit/encrypt/user-*" {
  capabilities = ["update"]
}

path "transit/decrypt/user-*" {
  capabilities       = ["update"]
  allowed_parameters = { "ciphertext" = [], "context" = [] }
  control_group = {
    ttl               = "${CG_TTL}s"
    self_auth_allowed = false
    factor "broker" {
      controlled_capabilities = ["update"]
      identity {
        group_names = ["cb4a-broker"]
        approvals   = 1
      }
    }
  }
}
EOF
bao policy write controller "$WORK/controller.hcl" >/dev/null

# The broker's entire OpenBao authority: review and approve. No transit path,
# no auth/token/create, no sys/policies.
cat >"$WORK/broker.hcl" <<'EOF'
path "sys/control-group/request"   { capabilities = ["update"] }
path "sys/control-group/authorize" { capabilities = ["update"] }
EOF
bao policy write broker "$WORK/broker.hcl" >/dev/null

# Both log in through AppRole so their tokens carry an identity entity
# (approvers are matched by group membership). In production the broker
# would use cert or JWT auth with its SVID.
bao auth enable approle >/dev/null
approle_login() {
  bao write auth/approle/role/"$1" token_policies="$2" token_ttl=30m >/dev/null
  local rid sid
  rid=$(bao read -field=role_id auth/approle/role/"$1"/role-id)
  sid=$(bao write -f -field=secret_id auth/approle/role/"$1"/secret-id)
  bao write -field=token auth/approle/login role_id="$rid" secret_id="$sid"
}
entity_of() { env BAO_TOKEN="$1" bao token lookup -format=json | jq -r .data.entity_id; }

CTRL_TOKEN=$(approle_login controller controller)
BROKER_TOKEN=$(approle_login broker broker)
CTRL_ENTITY=$(entity_of "$CTRL_TOKEN")
BROKER_ENTITY=$(entity_of "$BROKER_TOKEN")
bao write identity/group name=cb4a-broker member_entity_ids="$BROKER_ENTITY" >/dev/null

# stored rows: context = owner | resource | row id
encrypt() {
  env BAO_TOKEN="$CTRL_TOKEN" bao write -field=ciphertext "transit/encrypt/user-$1" \
    plaintext="$(printf '%s' "$3" | base64)" context="$2"
}
CTX_A_GH=$(row_ctx alice github row-123); CT_A_GH=$(encrypt alice "$CTX_A_GH" alice-github-token)
CTX_A_SL=$(row_ctx alice slack  row-789); CT_A_SL=$(encrypt alice "$CTX_A_SL" alice-slack-token)
CTX_B_GH=$(row_ctx bob   github row-456); CT_B_GH=$(encrypt bob   "$CTX_B_GH" bob-github-token)

NOW=$(date +%s)
ALICE_JWT=$(mkjwt alice $((NOW + 300)))

echo "== checks"

# 0) the problem: a broker that can write decrypt-row-* policies and mint over
# a role limited to that glob writes itself an admin policy
cat >"$WORK/broker-old.hcl" <<'EOF'
path "sys/policies/acl/decrypt-row-*" { capabilities = ["create", "update"] }
path "auth/token/create/decrypt"      { capabilities = ["update"] }
EOF
bao policy write broker-old "$WORK/broker-old.hcl" >/dev/null
bao write auth/token/roles/decrypt allowed_policies_glob="decrypt-row-*" \
  orphan=true renewable=false token_type=batch >/dev/null
OLD=$(bao token create -field=token -policy=broker-old)
env BAO_TOKEN="$OLD" bao policy write decrypt-row-4711 - >/dev/null 2>&1 <<'EOF'
path "*" { capabilities = ["create", "read", "update", "delete", "list", "sudo"] }
EOF
EVIL=$(env BAO_TOKEN="$OLD" bao write -field=token auth/token/create/decrypt policies=decrypt-row-4711 2>/dev/null)
env BAO_TOKEN="$EVIL" bao write transit/keys/user-alice/config exportable=true >/dev/null 2>&1
OUT=$(env BAO_TOKEN="$EVIL" bao read -format=json transit/export/encryption-key/user-alice 2>&1 | jq -r '.data.keys["1"] // empty' 2>/dev/null)
check "0 [old Mode 3b] per-row policy broker exports alice's key" "=" "$OUT"
bao policy delete decrypt-row-4711 >/dev/null; bao policy delete broker-old >/dev/null
bao delete auth/token/roles/decrypt >/dev/null
# exportable can't be turned back off, so start alice over on a fresh key
bao write transit/keys/user-alice/config deletion_allowed=true >/dev/null
bao delete transit/keys/user-alice >/dev/null
bao write -f transit/keys/user-alice derived=true type=aes256-gcm96 >/dev/null
CT_A_GH=$(encrypt alice "$CTX_A_GH" alice-github-token)
CT_A_SL=$(encrypt alice "$CTX_A_SL" alice-slack-token)

# 1) the controller's decrypt is held: wrap_info comes back, no plaintext
R=$(hold "$CTRL_TOKEN" user-alice "$CT_A_GH" "$CTX_A_GH")
check "1 controller decrypt is held, not executed" \
  "\"creation_path\": \"transit/decrypt/user-alice\"" "$(jq '{data, wrap_info}' <<<"$R")"
ACC=$(jq -r .wrap_info.accessor <<<"$R"); WT=$(jq -r .wrap_info.token <<<"$R")

# 3) before approval the wrapping token executes nothing (runs ahead of 2 on purpose)
OUT=$(unwrap "$WT")
check "3 unwrap before approval refused" "^s\..* wrapping token is not valid" "$(printf '%s %s' "$WT" "$OUT" | tr '\n' ' ')"

# 2) alice's live GitHub request: the broker checks both tokens and OpenBao's
# stored copy of the request, approves, the controller unwraps and revokes
PROOF=$(fresh_proof alice github)
OUT=$(broker_approve "$ACC" "$ALICE_JWT" "$PROOF" row-123)
[ "$OUT" = approved ] || echo "      broker said: $OUT"
OUT=$(unwrap "$WT")
env BAO_TOKEN="$WT" bao token revoke -self >/dev/null 2>&1
check "2 live request: broker approves, controller decrypts that row" "alice-github-token" "$OUT"

# 4) the controller approves its own held request: no policy for it
R=$(hold "$CTRL_TOKEN" user-alice "$CT_A_GH" "$CTX_A_GH")
OUT=$(env BAO_TOKEN="$CTRL_TOKEN" bao write sys/control-group/authorize accessor="$(jq -r .wrap_info.accessor <<<"$R")" 2>&1)
check "4 controller cannot approve its own request" "permission denied" "$OUT"

# 5) even with the policy and approver-group membership, self_auth_allowed=false
# refuses the approval ("token owner cannot be approver", returned as a 500)
bao policy write controller-plus - >/dev/null <<EOF
$(cat "$WORK/controller.hcl")
$(cat "$WORK/broker.hcl")
EOF
SELF_TOKEN=$(approle_login self-approver controller-plus)
bao write identity/group name=cb4a-broker member_entity_ids="$BROKER_ENTITY,$(entity_of "$SELF_TOKEN")" >/dev/null
R=$(hold "$SELF_TOKEN" user-alice "$CT_A_GH" "$CTX_A_GH")
SACC=$(jq -r .wrap_info.accessor <<<"$R"); SWT=$(jq -r .wrap_info.token <<<"$R")
OUT1=$(env BAO_TOKEN="$SELF_TOKEN" bao write -field=approved sys/control-group/authorize accessor="$SACC" 2>&1)
OUT2=$(env BAO_TOKEN="$BROKER_TOKEN" bao write -format=json sys/control-group/request accessor="$SACC" | jq -c '.data.authorizations')
OUT3=$(unwrap "$SWT")
check "5 approver-group member cannot self-approve" "token owner cannot be approver.*\[\] .*not valid" "$(printf '%s %s %s' "$OUT1" "$OUT2" "$OUT3" | tr '\n' ' ')"
bao write identity/group name=cb4a-broker member_entity_ids="$BROKER_ENTITY" >/dev/null

# 6) the broker decrypts directly: it has no transit path at all
OUT=$(env BAO_TOKEN="$BROKER_TOKEN" bao write transit/decrypt/user-alice \
  ciphertext="$CT_A_GH" context="$CTX_A_GH" 2>&1)
check "6 broker cannot decrypt alone" "permission denied" "$OUT"

# 7) the check-0 escalation, tried with the new broker: no policy write, no mint
OUT1=$(env BAO_TOKEN="$BROKER_TOKEN" bao policy write decrypt-row-4711 - 2>&1 <<<'path "*" { capabilities = ["sudo"] }')
OUT2=$(env BAO_TOKEN="$BROKER_TOKEN" bao token create -policy=default 2>&1)
check "7 broker cannot write policy or mint tokens" "permission denied.*permission denied" "$(printf '%s %s' "$OUT1" "$OUT2" | tr '\n' ' ')"

# 8) during alice's live GitHub request the controller sends her Slack row
R=$(hold "$CTRL_TOKEN" user-alice "$CT_A_SL" "$CTX_A_SL")
OUT=$(broker_approve "$(jq -r .wrap_info.accessor <<<"$R")" "$ALICE_JWT" "$(fresh_proof alice github)" row-123)
check "8 another of the user's rows during a live request refused" "denied: row is not for this request" "$OUT"

# 9) during alice's live request the controller sends bob's row on bob's key
R=$(hold "$CTRL_TOKEN" user-bob "$CT_B_GH" "$CTX_B_GH")
OUT=$(broker_approve "$(jq -r .wrap_info.accessor <<<"$R")" "$ALICE_JWT" "$(fresh_proof alice github)" row-123)
check "9 another user's row during a live request refused" "denied: key path is not this user's" "$OUT"

# 10) the right context with another row's ciphertext: the broker approves
# (the request names the right row) but transit's derived key won't open it
R=$(hold "$CTRL_TOKEN" user-alice "$CT_A_SL" "$CTX_A_GH")
OUT1=$(broker_approve "$(jq -r .wrap_info.accessor <<<"$R")" "$ALICE_JWT" "$(fresh_proof alice github)" row-123)
OUT2=$(unwrap "$(jq -r .wrap_info.token <<<"$R")")
check "10 ciphertext from another row fails the AEAD open" "^approved .*message authentication failed" "$(printf '%s %s' "$OUT1" "$OUT2" | tr '\n' ' ')"

# 11) batch_input is refused before anything is held
BATCH=$(jq -nc --arg c1 "$CT_A_GH" --arg x1 "$CTX_A_GH" --arg c2 "$CT_A_SL" --arg x2 "$CTX_A_SL" \
  '{batch_input: [{ciphertext: $c1, context: $x1}, {ciphertext: $c2, context: $x2}]}')
OUT=$(printf '%s' "$BATCH" | env BAO_TOKEN="$CTRL_TOKEN" bao write transit/decrypt/user-alice - 2>&1)
check "11 batch_input denied before it is held" "permission denied" "$OUT"

# 12) no live request: a replayed proof, and an expired one
R=$(hold "$CTRL_TOKEN" user-alice "$CT_A_GH" "$CTX_A_GH")
OUT1=$(broker_approve "$(jq -r .wrap_info.accessor <<<"$R")" "$ALICE_JWT" "$PROOF" row-123)
OUT2=$(broker_approve "$(jq -r .wrap_info.accessor <<<"$R")" "$ALICE_JWT" "$(mkproof alice github $((NOW - 5)))" row-123)
check "12 replayed or expired gateway proof refused" "proof replayed.*proof expired" "$(printf '%s %s' "$OUT1" "$OUT2")"

# 13) ttl: approve one now and leave one pending, wait out the ttl
R1=$(hold "$CTRL_TOKEN" user-alice "$CT_A_GH" "$CTX_A_GH")
R2=$(hold "$CTRL_TOKEN" user-alice "$CT_A_GH" "$CTX_A_GH")
OUT0=$(broker_approve "$(jq -r .wrap_info.accessor <<<"$R1")" "$ALICE_JWT" "$(fresh_proof alice github)" row-123)
sleep $((CG_TTL + 2))
OUT1=$(unwrap "$(jq -r .wrap_info.token <<<"$R1")")
OUT2=$(env BAO_TOKEN="$BROKER_TOKEN" bao write sys/control-group/authorize accessor="$(jq -r .wrap_info.accessor <<<"$R2")" 2>&1)
check "13 approved and pending requests both die at the ttl" "^approved .*not valid.*invalid accessor" "$(printf '%s %s %s' "$OUT0" "$OUT1" "$OUT2" | tr '\n' ' ')"

# 14) the controller's token is revoked after approval: unwrap runs the request
# as the controller at unwrap time, so it fails (a second login on the same
# AppRole role, so same entity, and revoking it leaves CTRL_TOKEN alone)
T2=$(approle_login controller controller)
R=$(hold "$T2" user-alice "$CT_A_GH" "$CTX_A_GH")
OUT1=$(broker_approve "$(jq -r .wrap_info.accessor <<<"$R")" "$ALICE_JWT" "$(fresh_proof alice github)" row-123)
bao token revoke "$T2" >/dev/null
OUT2=$(unwrap "$(jq -r .wrap_info.token <<<"$R")")
check "14 revoking the controller kills its approved requests" "^approved .*permission denied" "$(printf '%s %s' "$OUT1" "$OUT2" | tr '\n' ' ')"

# 15) an approved wrapping token is not single-use: it re-executes the approved
# request on every unwrap until the ttl. The repeat is the same row, but the
# controller should revoke the wrapping token after its first unwrap.
R=$(hold "$CTRL_TOKEN" user-alice "$CT_A_GH" "$CTX_A_GH")
WT=$(jq -r .wrap_info.token <<<"$R")
broker_approve "$(jq -r .wrap_info.accessor <<<"$R")" "$ALICE_JWT" "$(fresh_proof alice github)" row-123 >/dev/null
OUT1=$(unwrap "$WT"); OUT2=$(unwrap "$WT")
env BAO_TOKEN="$WT" bao token revoke -self >/dev/null 2>&1
OUT3=$(unwrap "$WT")
check "15 wrapping token reusable until revoked, revoke -self closes it" \
  "alice-github-token alice-github-token .*not valid" "$(printf '%s %s %s' "$OUT1" "$OUT2" "$OUT3" | tr '\n' ' ')"

# 16) ttl inside identity {} (where the docs' syntax section puts it) is
# ignored, so the control group has a zero ttl: the decrypt returns an empty
# 200, nothing held, nothing executed
sed -e "/ttl               = \"${CG_TTL}s\"/d" -e "s/approvals   = 1/approvals   = 1\n        ttl         = \"${CG_TTL}s\"/" \
  "$WORK/controller.hcl" >"$WORK/controller-misplaced.hcl"
bao policy write controller-misplaced "$WORK/controller-misplaced.hcl" >/dev/null
TM=$(bao token create -field=token -policy=controller-misplaced)
OUT=$(hold "$TM" user-alice "$CT_A_GH" "$CTX_A_GH" | jq -c '{data, wrap_info}')
check "16 ttl inside identity {} silently does nothing" '{"data":null,"wrap_info":null}' "$OUT"

# 17) audit: the controller's held request and the broker's approval share the
# wrapping accessor, under two different entities
R=$(hold "$CTRL_TOKEN" user-alice "$CT_A_GH" "$CTX_A_GH")
ACC=$(jq -r .wrap_info.accessor <<<"$R")
broker_approve "$ACC" "$ALICE_JWT" "$(fresh_proof alice github)" row-123 >/dev/null
HELD_BY=$(jq -r --arg a "$ACC" 'select(.type=="response" and .response.wrap_info.accessor==$a) | .auth.entity_id' "$WORK/audit.log")
APPROVED_BY=$(jq -r --arg a "$ACC" 'select(.type=="response" and .request.path=="sys/control-group/authorize" and .request.data.accessor==$a) | .auth.entity_id' "$WORK/audit.log")
check "17 audit joins hold and approval on the accessor" \
  "held=${CTRL_ENTITY} approved=${BROKER_ENTITY}" "held=${HELD_BY} approved=${APPROVED_BY}"

echo
echo "${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
