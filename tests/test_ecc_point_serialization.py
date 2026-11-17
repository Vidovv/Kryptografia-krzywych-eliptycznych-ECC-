import pytest

from ecc_library import ECCPoint, G


def assert_same_point(actual, expected):
    assert actual.is_infinity == expected.is_infinity
    assert actual.x == expected.x
    assert actual.y == expected.y


def test_uncompressed_point_round_trip():
    restored = ECCPoint.from_bytes(G.to_bytes())

    assert_same_point(restored, G)


def test_compressed_point_round_trip():
    restored = ECCPoint.from_bytes(G.to_bytes(compressed=True))

    assert_same_point(restored, G)


def test_point_at_infinity_round_trip():
    infinity = ECCPoint(is_infinity=True)

    restored = ECCPoint.from_bytes(infinity.to_bytes())

    assert restored.is_infinity is True


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"\x05" + b"\x00" * 32,
        b"\x04" + b"\x00" * 10,
        b"\x02" + b"\x00" * 10,
    ],
)
def test_from_bytes_rejects_empty_unknown_prefix_or_wrong_length(data):
    with pytest.raises(ValueError):
        ECCPoint.from_bytes(data)