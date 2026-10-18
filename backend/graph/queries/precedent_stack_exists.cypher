// precedent_stack_exists (graph `precedent`): has this stack been scanned into the memory?
MATCH (s:Stack {id: $id})
RETURN s.owner AS owner, s.scanned AS scanned
