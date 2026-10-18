// housekeeping_stack_age (stack graph): when was this stack loaded? Stacks loaded before this
// field existed return null and are never deleted by the janitor.
MATCH (a:Agent)
RETURN a.created AS created
LIMIT 1
