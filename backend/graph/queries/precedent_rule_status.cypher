// precedent_rule_status (graph `precedent`): the critic's verdict is stored on the rule.
MATCH (r:Rule {id: $id})
SET r.status = $status, r.critic = $critic, r.critic_ts = $ts
RETURN r.status AS status
