use anyhow::Result;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;

use sch::schnorr::*;
use sch::schnorr_prover::*;

use super::{C, D, F};

/// if s==0: returns x
/// if s==1: returns y
/// Warning: this method assumes all input values are ensured to be \in {0,1}
fn selector_gate(builder: &mut CircuitBuilder<F, D>, x: Target, y: Target, s: Target) -> Target {
    // z = x + s(y-x)
    let y_x = builder.sub(y, x);
    // z = x+s(y-x) <==> mul_add(s, yx, x)=s*(y-x)+x
    builder.mul_add(s, y_x, x)
}

/// ensures b \in {0,1}
fn binary_check(builder: &mut CircuitBuilder<F, D>, b: Target) {
    let zero = builder.zero();
    let one = builder.one();
    // b * (b-1) == 0
    let b_1 = builder.sub(b, one);
    let r = builder.mul(b, b_1);
    builder.connect(r, zero);
}

pub struct PODInput {
    pub pk: SchnorrPublicKey,
    pub sig: SchnorrSignature,
}

/// The logic of this gadget verifies the given signature if `selector==0`.
/// We reuse this gadget for all the the signature verifications in the node of the recursion tree.
///
/// Contains the methods to `add_targets` (ie. create the targets, the logic of the circuit), and
/// `set_targets` (ie. set the specific values to be used for the previously created targets).
pub struct PODGadgetTargets {
    pub selector_targ: Target,
    pub selector_booltarg: BoolTarget,

    pub pk_targ: SchnorrPublicKeyTarget,
    pub sig_targ: SchnorrSignatureTarget,
}

impl PODGadgetTargets {
    pub fn add_targets(
        mut builder: &mut CircuitBuilder<F, D>,
        msg_targ: &MessageTarget,
    ) -> Result<Self> {
        let selector_targ = builder.add_virtual_target();
        // ensure that selector_booltarg is \in {0,1}
        binary_check(builder, selector_targ);
        let selector_booltarg = BoolTarget::new_unsafe(selector_targ);

        // signature verification:
        let sb: SchnorrBuilder = SchnorrBuilder {};
        let pk_targ = SchnorrPublicKeyTarget::new_virtual(&mut builder);
        let sig_targ = SchnorrSignatureTarget::new_virtual(&mut builder);
        let sig_verif_targ = sb.verify_sig::<C>(&mut builder, &sig_targ, &msg_targ, &pk_targ);

        // - if selector=0
        //     verify_sig==1 && proof_enabled=0
        // - if selector=1
        //     verify_sig==NaN && proof_enabled=1   (don't check the sig)
        //
        // if selector=0: check that sig_verif==1
        // if selector=1: check that one==1
        let one = builder.one();
        let expected = selector_gate(
            builder,
            sig_verif_targ.target,
            one,
            selector_booltarg.target,
        );
        let one_2 = builder.one();
        builder.connect(expected, one_2);

        Ok(Self {
            selector_targ,
            selector_booltarg,
            pk_targ,
            sig_targ,
        })
    }
    pub fn set_targets(
        &mut self,
        pw: &mut PartialWitness<F>,
        // if `selector` set to 0 will verify the given signature, if set to 1 won't (and the
        // recursion layer will verify the respective plonky2 proof)
        selector: F,
        pod: &PODInput,
    ) -> Result<()> {
        pw.set_target(self.selector_targ, selector)?;

        // set signature related values:
        self.pk_targ.set_witness(pw, &pod.pk).unwrap();
        self.sig_targ.set_witness(pw, &pod.sig).unwrap();

        Ok(())
    }
}
