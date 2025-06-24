/*
type Hash256 = [u8; 32];

enum Error {
    Oops
}

trait TreeHash {
    fn get_field(&self, index: usize) -> Result<&dyn TreeHash, Error>;

    fn merkle_proof(&self, generalized_index: usize) -> Result<Vec<Hash256>, Error>;
}
*/
use std::marker::PhantomData;

// A path is a sequence of field accesses like `self.foo.bar`.
//
// We can resolve these at compile time, because we're sickos.
struct Path<First, Rest>(PhantomData<(First, Rest)>);

// The field trait is implemented for all struct fields.
//
// It provides conversion from a named field type to a numeric field index.
trait Field {
    const NUM_FIELDS: usize;
    const INDEX: usize;
}

// If T implements Resolve<Field> it means T has a field named Field of type Output.
trait Resolve<Field> {
    type Output;

    fn gindex(parent_index: usize) -> usize;
}

// This impl defines how paths are resolved and converted to gindices.
impl<T, First, Rest> Resolve<Path<First, Rest>> for T
where
    Self: Resolve<First>,
    First: Field,
    <Self as Resolve<First>>::Output: Resolve<Rest>,
{
    type Output = <<Self as Resolve<First>>::Output as Resolve<Rest>>::Output;

    fn gindex(parent_index: usize) -> usize {
        // From `get_generalized_index`:
        // https://github.com/ethereum/consensus-specs/blob/dev/ssz/merkle-proofs.md#ssz-object-to-index
        let new_parent_index = <Self as Resolve<First>>::gindex(parent_index);
        <Self as Resolve<First>>::Output::gindex(new_parent_index)
    }
}

// Some example structs.
struct Nested3 {
    x3: Nested2,
    y3: Nested1,
}

struct Nested2 {
    x2: Nested1,
    y2: Nested1,
}

struct Nested1 {
    x1: u64,
    y1: Vec<u64>,
}

// Fields of Nested3 (these would be generated).
struct FieldX3;
struct FieldY3;

impl Field for FieldX3 {
    const NUM_FIELDS: usize = 2;
    const INDEX: usize = 0;
}

impl Field for FieldY3 {
    const NUM_FIELDS: usize = 2;
    const INDEX: usize = 1;
}

// Fields of Nested2 (generated).
struct FieldX2;
struct FieldY2;

impl Field for FieldX2 {
    const NUM_FIELDS: usize = 2;
    const INDEX: usize = 0;
}

impl Field for FieldY2 {
    const NUM_FIELDS: usize = 2;
    const INDEX: usize = 1;
}

// Fields of Nested1 (generated).
struct FieldX1;
struct FieldY1;

impl Field for FieldX1 {
    const NUM_FIELDS: usize = 2;
    const INDEX: usize = 0;
}

impl Field for FieldY1 {
    const NUM_FIELDS: usize = 2;
    const INDEX: usize = 1;
}

// Implementations of Resolve (generated).
impl Resolve<FieldX3> for Nested3 {
    type Output = Nested2;

    fn gindex(parent_index: usize) -> usize {
        parent_index * <FieldX3 as Field>::NUM_FIELDS.next_power_of_two()
            + <FieldX3 as Field>::INDEX
    }
}

impl Resolve<FieldY3> for Nested3 {
    type Output = Nested1;

    fn gindex(parent_index: usize) -> usize {
        parent_index * <FieldY3 as Field>::NUM_FIELDS.next_power_of_two()
            + <FieldY3 as Field>::INDEX
    }
}

impl Resolve<FieldX2> for Nested2 {
    type Output = Nested1;

    fn gindex(parent_index: usize) -> usize {
        parent_index * <FieldX2 as Field>::NUM_FIELDS.next_power_of_two()
            + <FieldX2 as Field>::INDEX
    }
}

impl Resolve<FieldY2> for Nested2 {
    type Output = Nested1;

    fn gindex(parent_index: usize) -> usize {
        parent_index * <FieldY2 as Field>::NUM_FIELDS.next_power_of_two()
            + <FieldY2 as Field>::INDEX
    }
}

impl Resolve<FieldX1> for Nested1 {
    type Output = u64;

    fn gindex(parent_index: usize) -> usize {
        parent_index * <FieldX1 as Field>::NUM_FIELDS.next_power_of_two()
            + <FieldX1 as Field>::INDEX
    }
}

impl Resolve<FieldY1> for Nested1 {
    type Output = Vec<u64>;

    fn gindex(parent_index: usize) -> usize {
        parent_index * <FieldY1 as Field>::NUM_FIELDS.next_power_of_two()
            + <FieldY1 as Field>::INDEX
    }
}

// x3.x2.x1
type FieldX3X2X1 = Path<FieldX3, Path<FieldX2, FieldX1>>;

// x3.x2.x1
type FieldX3X2Y1 = Path<FieldX3, Path<FieldX2, FieldY1>>;

// This evaluates to u64 at compile-time.
type TypeOfFieldX3X2X1 = <Nested3 as Resolve<FieldX3X2X1>>::Output;

#[test]
fn gindex_basics() {
    // This works but just shows compile-time field resolution.
    let x: TypeOfFieldX3X2X1 = 0u64;

    // Gindex computation.
    assert_eq!(<Nested3 as Resolve<FieldX3X2X1>>::gindex(1), 8);
    assert_eq!(<Nested3 as Resolve<FieldX3X2Y1>>::gindex(1), 9);
}

/*
impl TreeHash for u64 {
    fn get_field(&self, _: usize) -> Result<&dyn TreeHash, Error> {
        Err(Error::Oops)
    }

    fn merkle_proof(&self)
}
*/
