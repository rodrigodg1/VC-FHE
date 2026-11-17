"""A continuation must advertise exactly the retained, preselected full cases."""
def select_full_catalog(prepared, full_names, available):
    cases=prepared['cases']
    if len({c['name'] for c in cases})!=len(cases):
        raise ValueError('Duplicate prepared case')
    selected=[c for c in cases if c.get('fullCase')]
    if [c['name'] for c in selected]!=full_names or len(full_names)!=27:
        raise ValueError('Changed preselected full-case grid')
    if not set(full_names)<=set(available):
        raise ValueError('A retained full-case directory is missing')
    return {**prepared,'cases':selected}
