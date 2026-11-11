// Plain unit tests of the adapter's pure helpers; the signed-response tests
// are TXE tests in payment-settlement/wechatpay/src/test.nr.
use crate::payee;

#[test]
fn payee_separates_appid_and_mchid() {
    let x: BoundedVec<u8, 128> = BoundedVec::from_array("wx1".as_bytes());
    let y: BoundedVec<u8, 128> = BoundedVec::from_array("190".as_bytes());
    assert(payee(x, y) != payee(y, x));
}
