"""Check only workflow-prefix shape. This never authorizes a release or execution."""
def inspect_frontier(planned_names, progress_events, application):
    planned=list(planned_names)
    if not planned or len(planned)!=len(set(planned)):
        raise ValueError('Missing or duplicate planned cases')
    done=[e.get('caseName') for e in progress_events
          if e.get('phase')=='full-case' and e.get('group')=='full' and e.get('state')=='done']
    if not done or len(done)>=len(planned):
        raise ValueError('This route requires a nonempty incomplete prefix')
    if done!=planned[:len(done)]:
        raise ValueError('Duplicate, reordered or non-prefix completed events')
    rows=application.get('cases')
    if not isinstance(rows,list) or [c.get('name') for c in rows]!=done:
        raise ValueError('Released rows and completed events differ. Reconcile before recovery')
    if application.get('kmsCalls')!=len(done):
        raise ValueError('KMS-call count differs from the completed prefix')
    return {'status':'prefix-shape-checked-not-authorized-to-resume',
            'completedCases':done,'remainingCases':planned[len(done):],
            'requiresChainReconciliation':True,'requiresRecipientVerification':True,
            'requiresSourceVerification':True,'analysisComplete':False}
