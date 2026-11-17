import VCFHE.Quorum

namespace VCFHE.Release

/-! One fixed policy deployment. Natural-number tokens denote authenticated
identifiers/digests. `Terms` includes the context bound by computation consent;
`Request` includes the fields bound by exact release approval and signature.
The registry, context and accepted final outputs are immutable in this model.
-/
structure Terms where
  task : Nat
  slot : Nat
  records : List Nat
  recipient : Nat
  context : Nat
  deriving DecidableEq, Repr

structure Request where
  consent : Nat
  id : Nat
  key : Nat
  output : Nat
  recipient : Nat
  recipientKey : Nat
  wire : Nat
  query : Nat
  aggregate : Nat
  deriving DecidableEq, Repr

structure Config where
  terms : Nat → Terms
  owner : Nat → Nat
  limit : Nat → Nat
  initialSpent : Nat → Nat
  acceptedOutput : Nat → Option Nat
  chainFinality : Request → Prop
  recipientSigned : Request → Prop
  deliveryValid : Request → Prop

structure State where
  consentApproval : Nat → Nat → Bool
  exactApproval : Request → Nat → Bool
  reserved : List Request
  spent : Nat → Nat

def initial (c : Config) : State :=
  ⟨fun _ _ => false, fun _ _ => false, [], c.initialSpent⟩

def Authorized (c : Config) (s : State) (r : Request) : Prop :=
  r.recipient = (c.terms r.consent).recipient ∧
  c.recipientSigned r ∧
  c.chainFinality r ∧
  ∀ record ∈ (c.terms r.consent).records,
    s.consentApproval r.consent (c.owner record) = true ∧
    s.exactApproval r (c.owner record) = true

/- Output binding includes the owner/recipient verification of public
conversion on the linear path. It is separate from the on-chain guard. -/
def OutputBound (c : Config) (r : Request) : Prop :=
  c.acceptedOutput (c.terms r.consent).task = some r.output ∧ c.deliveryValid r

def Guard (c : Config) (s : State) (r : Request) : Prop :=
  Authorized c s r ∧
  (c.terms r.consent).records.Nodup ∧
  (∀ old ∈ s.reserved, old.id ≠ r.id ∧ old.key ≠ r.key ∧
    (c.terms old.consent).slot ≠ (c.terms r.consent).slot) ∧
  ∀ record ∈ (c.terms r.consent).records, s.spent record < c.limit record

def approveConsent (s : State) (consent owner : Nat) : State :=
  { s with consentApproval := fun t o =>
      if t = consent ∧ o = owner then true else s.consentApproval t o }

def approveExact (s : State) (r : Request) (owner : Nat) : State :=
  { s with exactApproval := fun r' o =>
      if r' = r ∧ o = owner then true else s.exactApproval r' o }

def reserve (c : Config) (s : State) (r : Request) : State :=
  { s with reserved := r :: s.reserved, spent := fun record =>
      if record ∈ (c.terms r.consent).records then s.spent record + 1
      else s.spent record }

/- The owner argument is the authenticated transaction sender. Approval
transitions are deliberately permissive about membership: the reservation
guard still requires every actual registered input owner. -/
inductive Step (c : Config) : State → State → Prop where
  | consent (s t o) : Step c s (approveConsent s t o)
  | exact (s r o) : Step c s (approveExact s r o)
  | reservation (s r) (guard : Guard c s r) : Step c s (reserve c s r)

inductive Reachable (c : Config) : State → Prop where
  | init : Reachable c (initial c)
  | next {s t} : Reachable c s → Step c s t → Reachable c t

def charge (c : Config) (history : List Request) (record : Nat) : Nat :=
  (history.map fun r => if record ∈ (c.terms r.consent).records then 1 else 0).sum

structure Invariant (c : Config) (s : State) : Prop where
  budgets : ∀ record, s.spent record ≤ c.limit record
  accounting : ∀ record, s.spent record = c.initialSpent record + charge c s.reserved record
  authorization : ∀ r ∈ s.reserved, Authorized c s r
  requestIds : (s.reserved.map Request.id).Nodup
  requestKeys : (s.reserved.map Request.key).Nodup
  slots : (s.reserved.map fun r => (c.terms r.consent).slot).Nodup

theorem authorization_after_consent (c : Config) (s : State) (r : Request)
    (t o : Nat) (h : Authorized c s r) : Authorized c (approveConsent s t o) r := by
  rcases h with ⟨hr, hs, hf, ha⟩
  refine ⟨hr, hs, hf, ?_⟩
  intro record hm
  obtain ⟨h1, h2⟩ := ha record hm
  constructor
  · simp only [approveConsent]
    split <;> simp_all
  · exact h2

theorem authorization_after_exact (c : Config) (s : State) (r req : Request)
    (o : Nat) (h : Authorized c s r) : Authorized c (approveExact s req o) r := by
  rcases h with ⟨hr, hs, hf, ha⟩
  refine ⟨hr, hs, hf, ?_⟩
  intro record hm
  obtain ⟨h1, h2⟩ := ha record hm
  constructor
  · exact h1
  · simp only [approveExact]
    split <;> simp_all

theorem initial_invariant (c : Config)
    (bounds : ∀ record, c.initialSpent record ≤ c.limit record) :
    Invariant c (initial c) := by
  constructor
  · exact bounds
  · intro record; simp [initial, charge]
  · simp [initial]
  · simp [initial]
  · simp [initial]
  · simp [initial]

theorem step_preserves (c : Config) (s t : State)
    (inv : Invariant c s) (transition : Step c s t) : Invariant c t := by
  cases transition with
  | consent terms owner =>
    refine ⟨inv.budgets, inv.accounting, ?_, inv.requestIds, inv.requestKeys, inv.slots⟩
    intro r hr
    exact authorization_after_consent c s r terms owner (inv.authorization r hr)
  | exact req owner =>
    refine ⟨inv.budgets, inv.accounting, ?_, inv.requestIds, inv.requestKeys, inv.slots⟩
    intro r hr
    exact authorization_after_exact c s r req owner (inv.authorization r hr)
  | reservation r guard =>
    rcases guard with ⟨auth, _, fresh, budget⟩
    constructor
    · intro record
      simp only [reserve]
      split
      · have := budget record ‹_›; omega
      · exact inv.budgets record
    · intro record
      have h := inv.accounting record
      simp only [reserve, charge, List.map_cons, List.sum_cons] at *
      split <;> simp_all <;> omega
    · intro req hr
      simp only [reserve, List.mem_cons] at hr
      rcases hr with h | h
      · subst req; exact auth
      · exact inv.authorization req h
    · simp only [reserve, List.map_cons, List.nodup_cons]
      refine ⟨?_, inv.requestIds⟩
      intro h
      obtain ⟨old, hm, he⟩ := List.mem_map.mp h
      exact (fresh old hm).1 he
    · simp only [reserve, List.map_cons, List.nodup_cons]
      refine ⟨?_, inv.requestKeys⟩
      intro h
      obtain ⟨old, hm, he⟩ := List.mem_map.mp h
      exact (fresh old hm).2.1 he
    · simp only [reserve, List.map_cons, List.nodup_cons]
      refine ⟨?_, inv.slots⟩
      intro h
      obtain ⟨old, hm, he⟩ := List.mem_map.mp h
      exact (fresh old hm).2.2 he

theorem reachable_invariant (c : Config)
    (bounds : ∀ record, c.initialSpent record ≤ c.limit record)
    (s : State) (run : Reachable c s) : Invariant c s := by
  induction run with
  | init => exact initial_invariant c bounds
  | next previous transition ih => exact step_preserves c _ _ ih transition

theorem cannot_reserve_twice (c : Config) (s : State) (r : Request)
    (used : r ∈ s.reserved) : ¬ Guard c s r := by
  intro guard
  exact (guard.2.2.1 r used).1 rfl

/- Authenticated, distinct KMS responders; each honest responder observes
the exact request reserved at the same finalized policy state. -/
theorem threshold_release_authorized (c : Config) (s : State)
    (bounds : ∀ record, c.initialSpent record ≤ c.limit record)
    (run : Reachable c s) (r : Request)
    (q f : Nat) (faulty : Fin q → Bool)
    (corruption : Quorum.faultyCount q faulty ≤ f) (threshold : f < q)
    (honestDuty : ∀ i, faulty i = false → r ∈ s.reserved) :
    Authorized c s r := by
  obtain ⟨i, hi⟩ := Quorum.honest_signer_exists q f faulty corruption threshold
  exact (reachable_invariant c bounds s run).authorization r (honestDuty i hi)

theorem threshold_release_bound (c : Config) (s : State)
    (bounds : ∀ record, c.initialSpent record ≤ c.limit record)
    (run : Reachable c s) (r : Request)
    (q f : Nat) (faulty : Fin q → Bool)
    (corruption : Quorum.faultyCount q faulty ≤ f) (threshold : f < q)
    (honestDuty : ∀ i, faulty i = false → r ∈ s.reserved)
    (outputValidation : r ∈ s.reserved → OutputBound c r) :
    Authorized c s r ∧ OutputBound c r := by
  obtain ⟨i, hi⟩ := Quorum.honest_signer_exists q f faulty corruption threshold
  exact ⟨threshold_release_authorized c s bounds run r q f faulty corruption
    threshold honestDuty, outputValidation (honestDuty i hi)⟩

end VCFHE.Release
