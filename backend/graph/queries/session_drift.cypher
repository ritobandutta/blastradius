// session_drift (session graph): the raw counts behind the trust-score signals.
//   total          events so far (the baseline is the first few)
//   recent         events inside the burst window
//   same_tool      earlier calls to this tool (0 after the baseline = a tool never seen before)
//   distinct_args  distinct argument hashes sent to this tool inside the enumeration window
//   same_args      earlier calls to this tool with exactly these arguments in that window
MATCH (e:Event)
RETURN count(e) AS total,
       sum(CASE WHEN e.ts >= $burst_since THEN 1 ELSE 0 END) AS recent,
       sum(CASE WHEN e.tool = $tool THEN 1 ELSE 0 END) AS same_tool,
       count(DISTINCT CASE WHEN e.tool = $tool AND e.ts >= $enum_since THEN e.args_hash END) AS distinct_args,
       sum(CASE WHEN e.tool = $tool AND e.args_hash = $args_hash AND e.ts >= $enum_since THEN 1 ELSE 0 END) AS same_args
