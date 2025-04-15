use crate::types::{ReadPrecompileInput, ReadPrecompileResult};
use alloy::primitives::{Address, Bytes};
use revm::{
    handler::register::EvmHandler,
    precompile::{PrecompileError, PrecompileSpecId},
    primitives::{Env, HashMap, Precompile, PrecompileOutput, PrecompileResult, StatefulPrecompile},
    ContextPrecompile, ContextPrecompiles,
};
use std::sync::Arc;

struct ReplayPrecompile(Arc<HashMap<ReadPrecompileInput, ReadPrecompileResult>>);

impl StatefulPrecompile for ReplayPrecompile {
    // This is a non-exact inversion of the PrecompileResult -> InterpreterResult -> ReadPrecompileResult function
    fn call(&self, bytes: &Bytes, gas_limit: u64, _env: &Env) -> PrecompileResult {
        match *self.0.get(&ReadPrecompileInput { input: bytes.clone(), gas_limit }).expect("missing precompile call") {
            ReadPrecompileResult::Ok { gas_used, ref bytes } => Ok(PrecompileOutput { gas_used, bytes: bytes.clone() }),
            ReadPrecompileResult::OutOfGas => Err(PrecompileError::OutOfGas.into()),
            ReadPrecompileResult::Error => Err(PrecompileError::other("precompile failed").into()),
            ReadPrecompileResult::UnexpectedError => panic!("unexpected precompile error"),
        }
    }
}

pub(crate) fn set_replay_precompiles<EXT, DB>(
    handler: &mut EvmHandler<EXT, DB>,
    results: Arc<HashMap<Address, Arc<HashMap<ReadPrecompileInput, ReadPrecompileResult>>>>,
) where
    DB: revm::Database,
{
    let spec_id = handler.cfg.spec_id;

    handler.pre_execution.load_precompiles = Arc::new(move || {
        let results = Arc::clone(&results);
        let mut res = ContextPrecompiles::new(PrecompileSpecId::from_spec_id(spec_id));
        res.extend(results.iter().map(|(&address, calls)| {
            (address, ContextPrecompile::Ordinary(Precompile::Stateful(Arc::new(ReplayPrecompile(Arc::clone(calls))))))
        }));
        res
    });
}
