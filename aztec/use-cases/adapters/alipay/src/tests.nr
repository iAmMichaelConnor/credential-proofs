// Plain unit tests of the adapter's pure helpers; the signed-response tests
// are TXE tests in payment-settlement/alipay/src/test.nr.
use crate::payee;

#[test]
fn payee_depends_on_the_key() {
    let mut other = [0; 18];
    other[0] = 1;
    assert(payee([0; 18]) != payee(other));
}
