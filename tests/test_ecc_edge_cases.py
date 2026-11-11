from ecc_library import ECCPoint, G, curve


def assert_is_infinity(point):
    assert point.is_infinity is True


def test_point_at_infinity_is_additive_identity():
    infinity = ECCPoint(is_infinity=True)

    assert curve.add(infinity, G) == G
    assert curve.add(G, infinity) == G


def test_add_point_and_its_inverse_returns_infinity():
    inverse_g = ECCPoint(G.x, (-G.y) % curve.p)

    assert_is_infinity(curve.add(G, inverse_g))


def test_multiply_by_zero_returns_infinity():
    assert_is_infinity(curve.multiply(G, 0))


def test_double_point_at_infinity_returns_infinity():
    infinity = ECCPoint(is_infinity=True)

    assert_is_infinity(curve.double_point(infinity))


def test_double_point_with_y_zero_returns_infinity():
    # double_point explicitly handles points with y == 0.
    point = ECCPoint(1, 0)

    assert_is_infinity(curve.double_point(point))


def test_multiplication_by_two_matches_point_doubling():
    assert curve.multiply(G, 2) == curve.double_point(G)