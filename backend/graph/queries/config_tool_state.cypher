// config_tool_state (stack graph): what the stack CONFIG alone says about a tool, with no taint
// tracking. Used to test a patch by itself: a gated tool needs a human, and a sink whose
// REACHES edge is scoped is unreachable because the tool's token lost that permission.
MATCH (t:Tool {id: $tool})
OPTIONAL MATCH (a:Agent)-[i:CAN_INVOKE]->(t)
OPTIONAL MATCH (t)-[r:REACHES]->(s:Sink)
WHERE coalesce(r.scoped, false)
RETURN t.id AS tool, coalesce(i.gated, false) AS gated,
       collect(DISTINCT s.id) AS scoped_sinks
