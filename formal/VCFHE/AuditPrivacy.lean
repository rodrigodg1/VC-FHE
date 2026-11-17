import Std

namespace VCFHE.AuditPrivacy

def PublicOnly {S P R : Type} (operation : S → P → R → P) : Prop :=
  ∀ s1 s2 p r, operation s1 p r = operation s2 p r

def run {S P R : Type} (operations : List (S → P → R → P))
    (secret : S) (public : P) (randomness : R) : P :=
  operations.foldl (fun state operation => operation secret state randomness) public

theorem public_transcript_noninterference {S P R : Type}
    (operations : List (S → P → R → P))
    (publicOnly : ∀ op ∈ operations, PublicOnly op)
    (s1 s2 : S) (public : P) (randomness : R) :
    run operations s1 public randomness = run operations s2 public randomness := by
  induction operations generalizing public with
  | nil => rfl
  | cons op ops ih =>
    simp only [run, List.foldl_cons]
    have head := publicOnly op (by simp)
    rw [head s1 s2 public randomness]
    exact ih (fun f hf => publicOnly f (by simp [hf])) _

theorem public_simulator_exists {S P R : Type} (referenceSecret : S)
    (operations : List (S → P → R → P))
    (publicOnly : ∀ op ∈ operations, PublicOnly op) :
    ∃ simulator : P → R → P, ∀ secret public randomness,
      simulator public randomness = run operations secret public randomness := by
  refine ⟨fun p r => run operations referenceSecret p r, ?_⟩
  intro secret public randomness
  exact public_transcript_noninterference operations publicOnly referenceSecret secret public randomness

end VCFHE.AuditPrivacy
