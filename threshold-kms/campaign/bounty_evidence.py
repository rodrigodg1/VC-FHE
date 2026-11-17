"""Reject stale/misattributed bounty-v2 settlement evidence; no chain writes."""
import json
from pathlib import Path


def test_economics(config=None):
    """Independently derive the pinned functional profile, not market prices."""
    p = Path(__file__).resolve().parents[2] / 'fhe-pod/scripts/bounty-economics.json'
    c = json.loads(p.read_text()) if config is None else config
    if c['revision'] != 'bounded-cost-v1':
        raise ValueError('unsupported bounty economics revision')
    fee = int(c['disclosureBaseWei']) + c['maxTraceLeaves'] * int(c['disclosurePerLeafWei'])
    reward = fee + int(c['challengeCostBudgetWei']) + int(c['challengerMarginWei'])
    penalty = reward + fee + int(c['operatorLossFloorWei'])
    return c, penalty, reward

def validate_bounty_evidence(cfg, app):
    from onchain_evidence import require, _keccak256
    protocol = cfg.get('nonlinearProtocol', 'canonical')
    require(protocol in {'canonical', 'bounty-v2'}, 'unknown nonlinear protocol')
    if protocol != 'bounty-v2':
        require(not any(c.get('metrics', {}).get('nonlinearProtocol') == 'bounty-v2'
                        for c in app['cases']), 'bounty results labelled as legacy')
        return
    require(cfg['half'] in {'nonlinear', 'both'}, 'bounty-v2 requires a nonlinear or combined run')
    dispute_only = cfg.get('readinessDisputesOnly') == 'bounty-v2-dispute-readiness-v1'
    require(not cfg.get('readinessDisputesOnly') or (dispute_only and cfg.get('readinessOnly')
            and cfg.get('smoke') and cfg.get('half') == 'nonlinear'
            and cfg.get('parameters') == 'Test' and not cfg.get('pocPlan')
            and not cfg.get('policyRefreshPlan')), 'invalid dispute-only evidence scope')
    require(isinstance(cfg.get('bountyEconomics'), dict), 'missing sealed economic configuration')
    economics, expected_penalty, expected_reward = test_economics(cfg['bountyEconomics'])
    receipts = app['receipts']
    by_hash = {r.get('txHash', r.get('hash')): r for r in receipts}
    require(len(by_hash) == len(receipts), 'duplicate bounty receipts')
    event = _keccak256(b'BountySettlement(bytes32,address,address,uint256,uint256,uint256)')
    withdrawal_event = _keccak256(b'StakeWithdrawn(address,address,uint256)')
    for case in app['cases']:
        m = case['metrics']
        if case['half'] == 'linear':
            require(cfg['half'] == 'both' and m.get('nonlinearProtocol') != protocol,
                    'linear case mislabelled as bounty')
            continue
        require(case['half'] == 'nonlinear' and m.get('nonlinearProtocol') == protocol
                and case['workflowManifest']['kind'] == 'canonical-bounty-nonlinear-v2',
                'bounty protocol identity mismatch')
        require(len(m['disputes']) == 1, 'one certified adversarial dispute per full case is required')
        settlement = m['disputes'][0]['settlement']
        b = settlement.get('bounty')
        require(b and b['protocol'] == protocol, 'missing measured bounty settlement')
        op, challenger, relay = (b[k].lower() for k in ['operator','challenger','relayer'])
        state = settlement.get('state')
        require(isinstance(state, list) and len(state) == 5
                and type(state[0]) is int and state[0] == 3
                and type(state[1]) is int and state[1] == 2
                and state[2] is True
                and all(isinstance(address, str) for address in state[3:])
                and [address.lower() for address in state[3:]] == [op, challenger],
                'bounty dispute did not reject the bound operator for the bound challenger')
        require(len({op,challenger,relay}) == 3, 'operator/challenger/relay identities overlap')
        require(b['game'].lower() == case['workflowManifest']['game'].lower()
                and b['availability'].lower() == case['workflowManifest']['availability'].lower(),
                'bounty measured on another deployment')
        penalty, reward, burned = (int(b[k]) for k in ['penaltyWei','rewardWei','burnedWei'])
        require(penalty == expected_penalty and reward == expected_reward and burned == penalty-reward,
                'bounty parameters or irreversible debit differ from the selected profile')
        require(isinstance(m['leaves'], int) and 0 < m['leaves'] <= economics['maxTraceLeaves']
                and m['leaves'] & (m['leaves']-1) == 0, 'trace exceeds the calibrated deployment scope')
        recorded = m.get('economics', {})
        fee_max = int(economics['disclosureBaseWei']) + economics['maxTraceLeaves'] * int(economics['disclosurePerLeafWei'])
        expected = dict(revision=economics['revision'], maxTraceLeaves=economics['maxTraceLeaves'],
                        maxDisclosureFeeWei=str(fee_max), challengeCostBudgetWei=economics['challengeCostBudgetWei'],
                        challengerMarginWei=economics['challengerMarginWei'], operatorLossFloorWei=economics['operatorLossFloorWei'],
                        bountyWei=str(reward), operatorPenaltyWei=str(penalty),
                        extraConstructorArgs=[str(penalty), str(reward), economics['maxTraceLeaves'], economics['challengeCostBudgetWei']])
        require(recorded == expected, 'missing or inconsistent recorded economics')
        require(int(b['withdrawalWei']) == reward, 'bounty was not withdrawn')
        parties = [x.lower() for x in b['parties']]
        before, after = list(map(int,b['stakesBefore'])), list(map(int,b['stakesAfter']))
        require(len(parties) == len(set(parties)) == len(before) == len(after) == 4
                and parties[0] == op and challenger in parties, 'wrong settlement participant set')
        for who, old, new in zip(parties,before,after):
            require(new-old == (-penalty if who == op else reward if who == challenger else 0),
                    'incorrect debit, bounty, or payment to another auditor')
        related = [r for r in receipts if str(r.get('to','')).lower() in
                   {b['game'].lower(), b['availability'].lower()}]
        # After creation the operator sends nothing: trace and both branches are relayed.
        require(all(r['from'].lower() != op for r in related
                    if r['label'] not in {'registerOperator','createTask'}),
                'abandonment case still depends on an operator transaction')
        labels = [r['label'] for r in related]
        required_labels = ['requestBountyTraceDisclosure','publishAuthenticatedTraceBatch',
                      'submitSealedAudit','revealSealedAudit','admitCanonicalLeaf','settleCanonicalLeaf',
                      'claimUnusedAuditBond','withdrawChallengeBounty']
        if not dispute_only:
            required_labels += ['honestSubmitSealedAudit','honestRevealSealedAudit','honestClaimAuditBond']
        for label in required_labels:
            require(label in labels, 'missing bounty workflow operation: '+label)
        if m['leaves'] > 1:
            require('relayOperatorBisection' in labels and 'relayChallengerBisection' in labels,
                    'both authenticated branches must be relayed')
        require('submitAudit' not in labels and 'openVerdict' not in labels,
                'legacy audit operations in bounty evidence')
        d=b['disclosure']
        require(d['splits'] == m['leaves']-1 and
                int(d['commitDeadline']) >= int(d['disclosureDeadline'])+cfg['windowSeconds'],
                'incomplete disclosure or shortened full-replay window')
        require(d['receipts'] and all(h in by_hash for h in d['receipts']), 'missing disclosure receipts')
        fee = int(economics['disclosureBaseWei']) + m['leaves'] * int(economics['disclosurePerLeafWei'])
        require(int(d['requestBondWei']) == fee and d['recipient'].lower() == op,
                'disclosure fee or recipient differs from the selected profile')
        request = [by_hash[h] for h in d['receipts'] if by_hash[h]['label'] == 'requestBountyTraceDisclosure']
        require(len(request) == 1 and request[0]['from'].lower() == d['requester'].lower()
                and int(request[0]['valueWei']) == fee, 'disclosure payer/value mismatch')
        fee_event = _keccak256(b'DisclosureRequestBondSettled(bytes32,address,uint256,bool)')
        credits = [l for h in d['receipts'] for l in by_hash[h].get('logs', [])
                   if l['address'].lower() == b['availability'].lower() and l['topics'][0].lower() == fee_event]
        require(len(credits) == 1 and [x.lower() for x in credits[0]['topics'][1:]] ==
                [b['taskId'].lower(), '0x'+op[2:].zfill(64)] and
                credits[0]['data'].lower() == '0x'+format(fee,'064x')+format(1,'064x'),
                'disclosure credit differs from the raw settlement event')
        for receipt in related:
            require(int(receipt['transactionFeeWei']) == int(receipt['gasUsed']) * int(receipt['effectiveGasPriceWei'])
                    and int(receipt['effectiveGasPriceWei']) >= 0, 'invalid measured gas fee')
        r=by_hash.get(b['settlementTx'])
        require(r and r['label']=='settleCanonicalLeaf' and r['status']==1, 'missing settlement receipt')
        logs=[l for l in r.get('logs',[]) if l['address'].lower()==b['game'].lower()
              and l['topics'][0].lower()==event]
        require(len(logs)==1, 'missing/duplicate raw BountySettlement event')
        log=logs[0]
        require([x.lower() for x in log['topics'][1:]] ==
                [b['taskId'].lower(), '0x'+op[2:].zfill(64), '0x'+challenger[2:].zfill(64)],
                'bounty event belongs to another task or recipient')
        require(log['data'].lower()=='0x'+''.join(format(v,'064x') for v in [penalty,reward,burned]),
                'bounty summary differs from the raw settlement event')
        w=by_hash.get(b['withdrawalTx'])
        require(w and w['label']=='withdrawChallengeBounty' and w['status']==1
                and w['from'].lower()==challenger, 'missing challenger withdrawal receipt')
        logs=[l for l in w.get('logs',[]) if l['address'].lower()==b['game'].lower()
              and l['topics'][0].lower()==withdrawal_event]
        require(len(logs)==1 and [x.lower() for x in logs[0]['topics'][1:]]==
                ['0x'+challenger[2:].zfill(64),'0x'+relay[2:].zfill(64)]
                and logs[0]['data'].lower()=='0x'+format(reward,'064x'),
                'withdrawal summary differs from raw event')


def economic_observation(case, receipts):
    """Exact wei arithmetic on validated receipts. Gas is not total economic cost."""
    from onchain_evidence import require
    m = case['metrics']
    b = m['disputes'][0]['settlement']['bounty']
    index = {r.get('hash', r.get('txHash')): r for r in receipts}
    hashes = m['disputeCosts']['receiptScopes']['dispute']['transactions']
    require(len(hashes) == len(set(hashes)) and hashes, 'missing/duplicate dispute cost receipts')
    fees_by_sender = {}
    for h in hashes:
        r = index[h]
        require(int(r['transactionFeeWei']) == int(r['gasUsed']) * int(r['effectiveGasPriceWei'])
                and int(r['effectiveGasPriceWei']) >= 0, 'gas fee mismatch')
        sender = r['from'].lower()
        fees_by_sender[sender] = fees_by_sender.get(sender, 0) + int(r['transactionFeeWei'])
    fee = int(b['disclosure']['requestBondWei'])
    reward, penalty = int(b['rewardWei']), int(b['penaltyWei'])
    gas = sum(fees_by_sender.values())
    return dict(revision=m['economics']['revision'],
                disclosureFeeWei=str(fee), rewardWei=str(reward), penaltyWei=str(penalty),
                burnedWei=b['burnedWei'], withdrawalWei=b['withdrawalWei'],
                disputeGasFeeWei=str(gas),
                rewardAfterDisclosureAndGasWei=str(reward-fee-gas),
                coalitionLossAfterDisclosureWei=str(penalty-reward-fee),
                declaredOtherCostBudgetWei=m['economics']['challengeCostBudgetWei'],
                gasExceedsDeclaredBudget=gas > int(m['economics']['challengeCostBudgetWei']),
                disclosurePayer=b['disclosure']['requester'], disclosureRecipient=b['operator'],
                bountyRecipient=b['challenger'], withdrawalRecipient=b['relayer'],
                gasFeesBySender={k:str(v) for k,v in fees_by_sender.items()},
                unpriced=['off-chain computation', 'capital lockup', 'retries', 'service compensation'],
                scope='Successful measured dispute, including relay and secondary-auditor transactions. '
                      'The reward residual is before unpriced costs, not observed profit. '
                      'Disclosure is a claimable credit, not a measured withdrawal.')
