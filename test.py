import unittest

from tests.single_exponent_test import TestSignleExponent
from tests.pedersen_commitment_test import TestPedersenCommitment
from tests.single_exponent_equality_test import TestSignleExponentEquality
from tests.single_pedersen_inner_product_test import TestSinglePedersenInnerProduct
from tests.boolean_test import TestBoolean
from tests.polynomial_commitment_test import TestPolinomialCommitment

if __name__ == '__main__':
    unittest.main()